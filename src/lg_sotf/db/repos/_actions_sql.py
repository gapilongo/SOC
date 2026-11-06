"""SQL of the ActionsRepo sweeps (executed counts, orphaned executions).

Kept apart only so ``actions.py`` stays within its module size budget; the
statements are used by :class:`lg_sotf.db.repos.actions.ActionsRepo` alone.
"""

EXECUTED_COUNTS_SQL = """
    SELECT action_type, count(*)::int AS n FROM response_actions
    WHERE tenant_id = $1 AND status = ANY($3::text[])
      -- The window is measured on the database clock that stamps executed_at, unless given.
      AND executed_at >= COALESCE($2::timestamptz, now() - interval '1 hour')
    GROUP BY action_type
"""
# Workflow actions left 'executing' whose run will never come back to them ($3: grace period in seconds,
# so a call still in flight is left alone).
ORPHANED_EXECUTING_SQL = """
    SELECT a.tenant_id, a.id, a.connector FROM response_actions a
    JOIN workflow_runs r ON r.tenant_id = a.tenant_id AND r.alert_id = a.alert_id
    WHERE a.status = 'executing' AND a.execution_owner = 'workflow' AND r.status IN ('dead_lettered', 'completed')
      AND ($1::text IS NULL OR a.tenant_id = $1)
      AND (a.executed_at IS NULL OR a.executed_at < now() - make_interval(secs => $3))
    ORDER BY a.executed_at NULLS FIRST
    LIMIT $2
"""
