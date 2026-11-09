"""Disable suppression suggestions that match a fingerprint alone (#343).

Before verdict keys, a rule suggested from an analyst's false positive (or a
bulk proposal from benign escalations) matched the alert fingerprint: the
detection and its hosts, users, IPs, hashes and domains, not what ran. Once
an admin enabled one, it closed a malicious service or command next to the
benign one on the same host (corpus_v1: a ransomware ``PSEXESVC`` service
after an Edge update service; a web shell's ``ps`` after monitoring's).

Every enabled rule with a ``fingerprint`` predicate that came from a false
positive (``source_feedback_id``) or has exactly a suggestion's shape
(``fingerprint``, ``source_id``, ``severity``) is disabled, and each one is
audited in its tenant's chain as ``suppression.revoked`` by the system actor
``migration-0016`` with the reason ``fingerprint_suggestion``. The gate also
ignores such rules (``lg_sotf.domain.suppression.fingerprint_suggestion``),
so one enabled again by hand still never applies; an admin replaces it with
a rule on ``verdict_key``. Rules an admin wrote with other predicates are
left alone. Downgrade does not re-enable anything.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-09
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db import locks

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The audit append of lg_sotf.db.repos.audit.AuditRepo.append, per disabled rule, under the same
# chain lock.
DISABLE = f"""
DO $$
DECLARE
    r RECORD;
    prev TEXT;
    entry_id BIGINT;
    entry_ts TIMESTAMPTZ;
    details JSONB;
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);  -- every tenant's rules and chain
    FOR r IN
        UPDATE suppression_rules SET enabled = false
        WHERE enabled AND match ? 'fingerprint'
          AND (source_feedback_id IS NOT NULL
               OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(match) AS k)
                  = ARRAY['fingerprint', 'severity', 'source_id'])
        RETURNING tenant_id, id
    LOOP
        PERFORM pg_advisory_xact_lock({locks.AUDIT_CHAIN}, hashtext(r.tenant_id));
        SELECT hash INTO prev FROM audit_log WHERE tenant_id = r.tenant_id ORDER BY id DESC LIMIT 1;
        entry_id := nextval(pg_get_serial_sequence('audit_log', 'id'));
        entry_ts := clock_timestamp();
        details := jsonb_build_object('reason', 'fingerprint_suggestion', 'issue', 343);
        INSERT INTO audit_log (tenant_id, id, ts, actor_type, actor_id, action, resource_type, resource_id,
                               details, prev_hash, hash)
        VALUES (r.tenant_id, entry_id, entry_ts, 'system', 'migration-0016', 'suppression.revoked',
                'suppression_rule', r.id, details, prev,
                audit_entry_hash(r.tenant_id, entry_id, entry_ts, 'system', 'migration-0016',
                                 'suppression.revoked', 'suppression_rule', r.id, details, prev));
    END LOOP;
END
$$;
"""  # noqa: S608 - the only interpolation is the lock class constant


def upgrade() -> None:
    op.execute(DISABLE)


def downgrade() -> None:
    # Re-enabling rules that closed attacks is never automatic.
    pass
