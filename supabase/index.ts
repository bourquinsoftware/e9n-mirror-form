// ============================================================================
// submit-response  (Supabase Edge Function, Deno)
//
// Browser -> this function -> Cloudflare Turnstile siteverify -> database.
// The page never talks to the database directly.
//
// Secrets to set (never put these in the page or the repo):
//   supabase secrets set TURNSTILE_SECRET=...            # from the Cloudflare dashboard
//   supabase secrets set TURNSTILE_HOSTNAMES=mirror.example.com
//        comma-separated hostnames the widget may run on (add localhost ONLY on a dev project)
//   supabase secrets set ALLOWED_ORIGINS=https://mirror.example.com
//        comma-separated origins allowed to call this function (CORS)
// Optional:
//   TURNSTILE_ACTION   defaults to "submit_mirror" (must match turnstileAction in the page)
//
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided automatically.
//
// Deploy (Turnstile is the gate, so JWT verification is off; no key is needed in the page):
//   supabase functions deploy submit-response --no-verify-jwt
// ============================================================================
import { createClient } from "jsr:@supabase/supabase-js@2";

const TURNSTILE_SECRET = Deno.env.get("TURNSTILE_SECRET") ?? "";
const EXPECTED_ACTION = Deno.env.get("TURNSTILE_ACTION") ?? "submit_mirror";
const csv = (v: string | undefined) =>
  (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const ALLOWED_HOSTNAMES = new Set(csv(Deno.env.get("TURNSTILE_HOSTNAMES")));
const ALLOWED_ORIGINS = new Set(csv(Deno.env.get("ALLOWED_ORIGINS")));

const MAX_BODY_BYTES = 300_000;
const KEY_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false } },
);

function corsHeaders(origin: string | null): Record<string, string> {
  const h: Record<string, string> = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, authorization, apikey, x-client-info",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
  if (origin && ALLOWED_ORIGINS.has(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}

function json(body: unknown, status: number, origin: string | null) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

// deno-lint-ignore no-explicit-any
type Json = any;

function isObj(v: unknown): v is Record<string, Json> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const numOrNull = (v: unknown) => (v === null || v === undefined ? true : typeof v === "number" && Number.isFinite(v));

// Returns an error string, or null when the payload is acceptable.
function validate(b: Json): string | null {
  if (!isObj(b)) return "body";
  const { respondent, quiz, response, answers, scores } = b;
  if (!isObj(respondent) || typeof respondent.name !== "string" || respondent.name.length > 200) return "respondent.name";
  if (typeof respondent.email !== "string" || respondent.email.length > 320 || !EMAIL_RE.test(respondent.email.trim())) return "respondent.email";
  if (!isObj(quiz) || !KEY_RE.test(String(quiz.slug)) || typeof quiz.version !== "string" || quiz.version.length < 1 || quiz.version.length > 64) return "quiz";
  if (quiz.definition !== undefined && !isObj(quiz.definition)) return "quiz.definition";
  if (!isObj(response)) return "response";
  if (!/^[0-9a-f-]{36}$/i.test(String(response.clientResponseId))) return "response.clientResponseId";
  for (const f of ["source", "primaryArchetype", "supportingArchetype", "schemaVersion", "createdAt"]) {
    if (response[f] !== undefined && response[f] !== null && (typeof response[f] !== "string" || response[f].length > 100)) return `response.${f}`;
  }
  if (response.createdAt && Number.isNaN(Date.parse(response.createdAt))) return "response.createdAt";
  if (response.result !== undefined && !isObj(response.result)) return "response.result";
  if (!Array.isArray(answers) || answers.length > 500) return "answers";
  const seen = new Set<string>();
  for (const a of answers) {
    if (!isObj(a) || !KEY_RE.test(String(a.key)) || !KEY_RE.test(String(a.section))) return "answers[].key";
    if (seen.has(a.key)) return "answers[] duplicate";
    seen.add(a.key);
    if (!numOrNull(a.value_num) || !numOrNull(a.scored_num)) return "answers[] value";
  }
  if (!Array.isArray(scores) || scores.length > 200) return "scores";
  const seenS = new Set<string>();
  for (const s of scores) {
    if (!isObj(s) || !KEY_RE.test(String(s.key)) || !KEY_RE.test(String(s.kind))) return "scores[].key";
    const id = `${s.kind}:${s.key}`;
    if (seenS.has(id)) return "scores[] duplicate";
    seenS.add(id);
    if (!numOrNull(s.score) || (s.band != null && typeof s.band !== "string")) return "scores[] value";
  }
  return null;
}

// Canonical Turnstile check: success, expected action, approved hostname.
async function verifyTurnstile(token: unknown, ip: string | null): Promise<boolean> {
  if (typeof token !== "string" || token.length === 0 || token.length > 2048) return false;
  try {
    const body = new URLSearchParams({ secret: TURNSTILE_SECRET, response: token });
    if (ip) body.set("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    if (!r.ok) return false;
    const result = await r.json();
    if (!result.success) return false;
    if (result.action !== EXPECTED_ACTION) return false;
    if (!ALLOWED_HOSTNAMES.has(result.hostname)) return false;
    return true;
  } catch (e) {
    console.error("siteverify failed", e);
    return false;
  }
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405, origin);

  // Origin allow-list (browsers always send Origin on cross-site POSTs)
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return json({ error: "forbidden" }, 403, origin);

  if (!TURNSTILE_SECRET || ALLOWED_HOSTNAMES.size === 0) {
    console.error("Missing TURNSTILE_SECRET or TURNSTILE_HOSTNAMES");
    return json({ error: "server_misconfigured" }, 500, origin);
  }

  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return json({ error: "too_large" }, 413, origin);

  let body: Json;
  try { body = JSON.parse(raw); } catch { return json({ error: "bad_json" }, 400, origin); }

  const ip = req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? null;

  // 1) Bot check first, so junk never reaches validation or the database
  if (!(await verifyTurnstile(body?.turnstileToken, ip))) return json({ error: "turnstile_failed" }, 403, origin);

  // 2) Shape check
  const problem = validate(body);
  if (problem) return json({ error: "invalid_payload", field: problem }, 400, origin);

  // 3) Single atomic write (see submit_mirror_response in 001_schema.sql)
  const { turnstileToken: _t, ...payload } = body;
  const { data, error } = await supabase.rpc("submit_mirror_response", { p: payload });
  if (error) {
    console.error("db error", error);
    return json({ error: "db_error" }, 500, origin);
  }
  return json({ ok: true, id: data }, 200, origin);
});
