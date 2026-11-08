"""Shadow agreement: ``shadow_verdicts``, production's verdict and a candidate's on the same alert.

``lg-sotf shadow-run`` replays recent alerts through a candidate model
profile in shadow mode (AI-E1.5b). Each alert replayed is one row of a
report (``report_id``, ``shr_`` + 32 hex): the candidate's label, both
routes (``close``, ``plan_response``, ``escalate``; ``NULL`` when that
side has none), dispositions, confidences, planned actions
(``action_type:target``), LLM tokens and cost and model-and-tool latency,
and the error type of a candidate run that failed.

A separate table rather than more ``shadow_effects`` rows: an effect is one
diverted call of a run (many per run, written by the sink), a verdict is one
row per alert per report with typed, checked columns the report aggregates.

Rows go with their alert (``ON DELETE CASCADE``), so they follow the
tenant's ``alerts_days`` retention and tenant erasure. Tenant-scoped with
forced RLS; the runtime role may read and insert, never update or delete.
Not part of the evidence pack.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-08
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SIDE = """
    {p}_route TEXT CHECK ({p}_route IN ('escalate', 'plan_response', 'close')),
    {p}_disposition TEXT CHECK ({p}_disposition IN ('malicious', 'benign', 'inconclusive')),
    {p}_confidence REAL CHECK ({p}_confidence BETWEEN 0 AND 100),
    {p}_actions TEXT[] NOT NULL DEFAULT '{{}}' CHECK (cardinality({p}_actions) <= 20),
    {p}_tokens BIGINT NOT NULL DEFAULT 0 CHECK ({p}_tokens >= 0),
    {p}_cost_usd NUMERIC(14, 6) NOT NULL DEFAULT 0 CHECK ({p}_cost_usd >= 0),
    {p}_latency_ms BIGINT NOT NULL DEFAULT 0 CHECK ({p}_latency_ms >= 0),"""

SCHEMA = f"""
CREATE TABLE shadow_verdicts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    report_id TEXT NOT NULL CHECK (report_id ~ '^shr_[0-9a-f]{{32}}$'),
    run_id TEXT CHECK (run_id LIKE 'shadow/%' AND length(run_id) <= 200),
    candidate TEXT NOT NULL CHECK (length(candidate) BETWEEN 1 AND 128),
    {_SIDE.format(p="prod")}
    {_SIDE.format(p="cand")}
    cand_error TEXT CHECK (length(cand_error) <= 128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT shadow_verdicts_report_alert_key UNIQUE (tenant_id, report_id, alert_id),
    CONSTRAINT shadow_verdicts_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX shadow_verdicts_alert_idx ON shadow_verdicts (tenant_id, alert_id);
"""

RLS = (
    "ALTER TABLE shadow_verdicts ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE shadow_verdicts FORCE ROW LEVEL SECURITY",
    f"CREATE POLICY tenant_isolation ON shadow_verdicts USING ({TENANT_POLICY_PREDICATE}) "
    f"WITH CHECK ({TENANT_POLICY_PREDICATE})",
)


def upgrade() -> None:
    op.execute(SCHEMA)
    for statement in RLS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS shadow_verdicts")
