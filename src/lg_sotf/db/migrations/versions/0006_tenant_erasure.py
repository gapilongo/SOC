"""Tenant erasure function for the runtime role (GDPR Art. 17 requests for a whole tenant).

The API/worker runtime role cannot delete alerts, events, escalations,
feedback, actions or tokens (retention is the schema owner's job) and cannot
bypass RLS. ``lgsotf_erase_tenant_batch`` lets it delete one bounded batch
of one *suspended* tenant's rows at a time, and nothing else:

* it refuses unless the tenant exists and its status is ``suspended``;
* each call deletes at most ``p_limit`` rows from the first table that still
  has rows of the tenant, and returns that table and the count; callers loop
  until it returns no table, so a large tenant is erased in many short
  transactions instead of one huge one;
* tables are visited children first, so a batch never cascades: the order
  is computed from the foreign keys in ``pg_constraint`` (a table is visited
  only once no remaining table references it), over every table with a
  ``tenant_id`` column. Ties keep a fixed order: tables this function does
  not know by name (added by a later migration) alphabetically, then the
  known tables. The LangGraph checkpoint tables (thread ids
  ``{tenant}:{alert}``) come last;
* ``audit_log`` is never touched: it is append-only by design and its
  trigger would refuse anyway. The ``tenants`` row stays too (the audit rows
  reference it); once nothing else is left its settings, which may hold
  encrypted secrets, are replaced by ``{"erased_at": ...}``.

The platform-admin check is the caller's (API or CLI).

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-30
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ERASE_FUNCTION = r"""
CREATE FUNCTION lgsotf_erase_tenant_batch(p_id TEXT, p_limit INTEGER)
RETURNS TABLE (table_name TEXT, deleted BIGINT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
    tenant_status TEXT;
    known TEXT[] := ARRAY[
        'indicator_sightings', 'llm_usage_daily', 'suppression_rules', 'response_actions',
        'analyst_feedback', 'escalations', 'workflow_runs', 'alert_events', 'alerts',
        'sources', 'api_keys', 'refresh_tokens', 'users'
    ];
    checkpoint_tables TEXT[] := ARRAY['checkpoint_writes', 'checkpoint_blobs', 'checkpoints'];
    candidates TEXT[];
    remaining TEXT[];
    leaves TEXT[];
    ordered TEXT[] := ARRAY[]::text[];
    t TEXT;
    n BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'batch size must be between 1 and 100000' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('app.bypass_rls', 'on', true);
    SELECT tn.status INTO tenant_status FROM public.tenants tn WHERE tn.id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF tenant_status <> 'suspended' THEN
        RAISE EXCEPTION 'tenant must be suspended before it is erased'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;

    SELECT array_agg(c.relname::text ORDER BY c.relname) INTO candidates
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
    WHERE ns.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
      AND c.relname::text <> ALL (known) AND c.relname::text NOT IN ('tenants', 'audit_log');
    candidates := COALESCE(candidates, ARRAY[]::text[]) || known;

    -- Children first: repeatedly take the tables that no other remaining table references. Deleting a
    -- batch of parent rows first would cascade to an unbounded number of child rows in one statement.
    remaining := candidates;
    WHILE cardinality(remaining) > 0 LOOP
        SELECT array_agg(rel ORDER BY array_position(candidates, rel)) INTO leaves
        FROM unnest(remaining) AS rel
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_constraint con
            JOIN pg_class child ON child.oid = con.conrelid
            JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
            JOIN pg_class parent ON parent.oid = con.confrelid
            JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
            WHERE con.contype = 'f' AND child_ns.nspname = 'public' AND parent_ns.nspname = 'public'
              AND parent.relname::text = rel AND child.relname::text <> rel
              AND child.relname::text = ANY (remaining)
        );
        IF leaves IS NULL THEN
            leaves := remaining;  -- a reference cycle: what is left keeps the fixed order
        END IF;
        ordered := ordered || leaves;
        remaining := ARRAY(SELECT rel FROM unnest(remaining) AS rel WHERE rel <> ALL (leaves));
    END LOOP;

    FOREACH t IN ARRAY ordered LOOP
        EXECUTE format(
            'DELETE FROM public.%I WHERE (tableoid, ctid) IN '
            '(SELECT tableoid, ctid FROM public.%I WHERE tenant_id = $1 LIMIT $2)', t, t
        ) USING p_id, p_limit;
        GET DIAGNOSTICS n = ROW_COUNT;
        IF n > 0 THEN
            table_name := t;
            deleted := n;
            PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
            RETURN NEXT;
            RETURN;
        END IF;
    END LOOP;

    FOREACH t IN ARRAY checkpoint_tables LOOP
        IF to_regclass(format('public.%I', t)) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format(
            'DELETE FROM public.%I WHERE ctid = ANY(ARRAY('
            'SELECT ctid FROM public.%I WHERE split_part(thread_id, '':'', 1) = $1 LIMIT $2))', t, t
        ) USING p_id, p_limit;
        GET DIAGNOSTICS n = ROW_COUNT;
        IF n > 0 THEN
            table_name := t;
            deleted := n;
            PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
            RETURN NEXT;
            RETURN;
        END IF;
    END LOOP;

    UPDATE public.tenants tn
    SET settings = jsonb_build_object('erased_at', COALESCE(tn.settings -> 'erased_at', to_jsonb(clock_timestamp())))
    WHERE tn.id = p_id AND tn.settings IS DISTINCT FROM
        jsonb_build_object('erased_at', tn.settings -> 'erased_at');
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
    RETURN;
END
$$;

REVOKE ALL ON FUNCTION lgsotf_erase_tenant_batch(TEXT, INTEGER) FROM PUBLIC;
"""


def upgrade() -> None:
    op.execute(ERASE_FUNCTION)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS lgsotf_erase_tenant_batch(TEXT, INTEGER)")
