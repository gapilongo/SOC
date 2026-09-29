-- Export the analyst-labelled alerts of one tenant as an lg-sotf eval dataset (JSONL).
--
--   psql "$OWNER_DSN" -v tenant=acme -v days=90 -v out="$HOME/lg-sotf-eval/acme-feedback.jsonl" \
--        -f docs/tools/export_feedback.sql
--
-- `out` is required (a path without spaces); write it OUTSIDE any git work
-- tree. The file contains customer telemetry (secrets are redacted at
-- ingestion; names, addresses and hosts are not): restrict access and delete
-- it when done. See docs/evaluation.md.
--
-- One item per alert. An alert can collect several decisions (a needs_more_info
-- decision re-escalates it and the next decision is recorded as another
-- analyst_feedback row); the item's label is the alert's latest decision other
-- than needs_more_info, or needs_more_info (inconclusive) when that is all
-- there is. Exporting every row would replay the same raw event twice: the
-- second copy is rejected as a duplicate at ingestion and the final decision
-- would be lost.
\if :{?out}
\else
  \echo 'usage: psql "$OWNER_DSN" -v tenant=<id> -v days=<n> -v out=<path outside the repository> -f export_feedback.sql'
  \quit
\endif
SET app.tenant_id = :'tenant';
\pset format unaligned
\pset tuples_only on
\o :out
-- export-query-begin
WITH final AS (
    SELECT DISTINCT ON (f.alert_id) f.*
    FROM analyst_feedback f
    WHERE f.tenant_id = :'tenant'
      AND f.created_at >= now() - make_interval(days => :days)
    ORDER BY f.alert_id, (f.decision = 'needs_more_info'), f.created_at DESC, f.id DESC
)
SELECT json_build_object(
    'id', 'fb-' || f.id,
    'source_type', CASE
        WHEN s.type IS NULL THEN 'canonical'
        WHEN s.type IN ('webhook', 'file') AND coalesce(s.config->>'format', '') IN
             ('splunk', 'crowdstrike', 'sentinel', 'wazuh', 'guardduty', 'qradar') THEN s.config->>'format'
        WHEN s.type IN ('webhook', 'file') AND (s.config->>'format' = 'generic' OR s.config ? 'field_map') THEN 'webhook'
        WHEN s.type IN ('webhook', 'file') THEN 'canonical'
        ELSE s.type
    END,
    'source_config', CASE
        WHEN s.type IN ('webhook', 'file') AND (s.config->>'format' = 'generic' OR s.config ? 'field_map')
        THEN s.config - 'format' END,
    'alert', a.raw,
    'expected', json_build_object('disposition', CASE f.decision
        WHEN 'true_positive' THEN 'malicious'
        WHEN 'needs_more_info' THEN 'inconclusive'
        ELSE 'benign' END),
    'labels', json_build_array(json_build_object(
        'annotator', 'analyst-' || left(md5(coalesce(f.user_id::text, 'unknown')), 10),
        'disposition', CASE f.decision
            WHEN 'true_positive' THEN 'malicious'
            WHEN 'needs_more_info' THEN 'inconclusive'
            ELSE 'benign' END)),
    'split', 'feedback',
    'tags', json_build_array('analyst-feedback', 'severity:' || a.severity, 'decision:' || f.decision)
)
FROM final f
JOIN alerts a ON a.tenant_id = f.tenant_id AND a.id = f.alert_id
LEFT JOIN sources s ON s.tenant_id = a.tenant_id AND s.id = a.source_id
WHERE NOT (a.raw ? '_lgsotf_truncated')
ORDER BY f.created_at, f.id;
-- export-query-end
\o
