-- ============================================================================
-- THE MIRROR: admin views (step 2)
--
-- security_invoker = true means these views run with the CALLER's permissions,
-- so the admin-only RLS policies from 001 still apply. A signed-in non-admin
-- (or anon) gets zero rows, even though the view exists.
--
-- Two views cover CSV export:
--   admin_responses : one row per response  (wide: person, archetypes, scores)
--   admin_answers   : one row per answer     (long: every question + its text)
-- Two small optional views feed analytics charts.
-- Test-mode responses are included but flagged (is_test); filter them out in
-- the admin UI or add "where not r.is_test".
-- ============================================================================

create or replace view public.admin_responses
with (security_invoker = true) as
select
  r.id                    as response_id,
  r.created_at            as submitted_at,
  p.name,
  p.email,
  q.quiz_slug,
  q.version               as quiz_version,
  r.source,
  r.is_test,
  r.primary_archetype,
  r.supporting_archetype,
  -- Every dimension, whatever the quiz currently has (flexible):
  (select jsonb_object_agg(s.score_key, s.score)
     from public.response_scores s where s.response_id = r.id and s.kind = 'dimension') as dimension_scores,
  (select jsonb_object_agg(s.score_key, s.score)
     from public.response_scores s where s.response_id = r.id and s.kind = 'archetype') as archetype_scores,
  -- Convenience columns for the CURRENT 8 dimensions (CSV-friendly). If you add a
  -- dimension, add a line here with "create or replace view"; nothing else changes.
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'viewOfGod')      as view_of_god,
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'viewOfWorld')    as view_of_world,
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'sacredSecular') as sacred_secular,
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'spirit')         as spirit,
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'viewOfCulture')  as view_of_culture,
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'viewOfSelf')     as view_of_self,
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'future')         as future,
  max(s.score) filter (where s.kind = 'dimension' and s.score_key = 'wholeness')     as wholeness,
  r.result                as result_json
from public.responses r
join public.respondents  p on p.id = r.respondent_id
join public.quiz_versions q on q.id = r.quiz_version_id
left join public.response_scores s on s.response_id = r.id
group by r.id, p.name, p.email, q.quiz_slug, q.version;

create or replace view public.admin_answers
with (security_invoker = true) as
select
  r.id                    as response_id,
  r.created_at            as submitted_at,
  p.email,
  q.version               as quiz_version,
  a.section,
  a.question_key,
  -- Question wording as it was when this response was taken (from the snapshot)
  (select e ->> 'text'
     from jsonb_array_elements(q.definition -> 'questions') e
    where e ->> 'id' = a.question_key
    limit 1)              as question_text,
  a.value_num,
  a.scored_num,
  a.value_json,
  r.is_test
from public.response_answers a
join public.responses     r on r.id = a.response_id
join public.respondents   p on p.id = r.respondent_id
join public.quiz_versions q on q.id = r.quiz_version_id;

-- ---- Optional: analytics --------------------------------------------------
create or replace view public.admin_dimension_summary
with (security_invoker = true) as
select q.version as quiz_version, s.score_key as dimension,
       count(*) as n, round(avg(s.score), 2) as avg_score,
       min(s.score) as min_score, max(s.score) as max_score
from public.response_scores s
join public.responses r on r.id = s.response_id and not r.is_test
join public.quiz_versions q on q.id = r.quiz_version_id
where s.kind = 'dimension'
group by q.version, s.score_key;

create or replace view public.admin_archetype_summary
with (security_invoker = true) as
select q.version as quiz_version, r.primary_archetype, count(*) as n,
       round(100.0 * count(*) / sum(count(*)) over (partition by q.version), 1) as pct
from public.responses r
join public.quiz_versions q on q.id = r.quiz_version_id
where not r.is_test
group by q.version, r.primary_archetype;

revoke all on public.admin_responses, public.admin_answers,
              public.admin_dimension_summary, public.admin_archetype_summary from anon;
grant select on public.admin_responses, public.admin_answers,
                public.admin_dimension_summary, public.admin_archetype_summary to authenticated;
