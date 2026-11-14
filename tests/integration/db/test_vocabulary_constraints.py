"""The database CHECK constraints list exactly the vocabulary's values (roadmap F2.5, ADR-0004).

Migrations are frozen and never import :mod:`lg_sotf.models.vocabulary`, so
nothing else ties a new vocabulary value to a migration that admits it. This
test reads every value-list ``CHECK`` of the migrated schema with
``pg_get_constraintdef`` (``col = ANY (ARRAY[...])``, ``col = '...'`` and
``col <@ ARRAY[...]``) and compares it, as a set, with the declaration the
code validates against.
"""

from __future__ import annotations

import re
from typing import Dict, FrozenSet, Iterable, Tuple

import psycopg
import pytest

from lg_sotf.db.repos.alert_events import EVENT_ACTOR_TYPES
from lg_sotf.db.repos.audit import AUDIT_ACTOR_TYPES
from lg_sotf.db.repos.integrations import INTEGRATION_KINDS, TICKETING_KINDS
from lg_sotf.db.repos.outbox import OUTBOX_OPERATIONS, OUTBOX_STATUSES
from lg_sotf.db.repos.sources import SOURCE_HEALTH
from lg_sotf.db.repos.tenants import TENANT_STATUSES
from lg_sotf.db.urls import to_libpq_url
from lg_sotf.domain.pov import POV_BACKTEST_STATUSES
from lg_sotf.models import vocabulary as v
from lg_sotf.models.trace import STEP_KINDS, STEP_OUTCOMES
from lg_sotf.security.shadow import EFFECT_OUTCOMES

pytestmark = pytest.mark.asyncio

# (table, column) -> the values its CHECK must admit.
EXPECTED: Dict[Tuple[str, str], Iterable[str]] = {
    ("alerts", "severity"): v.SEVERITIES,
    ("alerts", "status"): v.ALERT_STATUSES,
    ("alerts", "disposition"): v.DISPOSITIONS,
    ("response_actions", "risk_level"): v.RISK_LEVELS,
    ("response_actions", "status"): v.ACTION_STATUSES,
    ("response_actions", "execution_owner"): v.EXECUTION_OWNERS,
    ("response_actions", "verification"): v.VERIFICATION_STATES,
    ("escalations", "level"): v.ESCALATION_LEVELS,
    ("escalations", "status"): v.ESCALATION_STATUSES,
    ("escalations", "decision"): v.DECISIONS,
    ("analyst_feedback", "decision"): v.DECISIONS,
    ("workflow_runs", "status"): v.RUN_STATUSES,
    ("sources", "type"): v.SOURCE_TYPES,
    ("sources", "health"): SOURCE_HEALTH,
    ("users", "role"): v.ROLES,
    ("tenant_grants", "role"): v.ROLES,
    ("api_keys", "scopes"): v.SCOPES,
    ("integrations", "kind"): INTEGRATION_KINDS,
    ("integrations", "min_severity"): v.SEVERITIES,
    ("notification_outbox", "status"): OUTBOX_STATUSES,
    ("notification_outbox", "operation"): OUTBOX_OPERATIONS,
    ("external_tickets", "system"): TICKETING_KINDS,
    ("tenants", "status"): TENANT_STATUSES,
    ("alert_events", "actor_type"): EVENT_ACTOR_TYPES,
    ("audit_log", "actor_type"): AUDIT_ACTOR_TYPES,
    ("investigation_steps", "kind"): STEP_KINDS,
    ("investigation_steps", "outcome"): STEP_OUTCOMES,
    ("blind_audit_runs", "trigger"): v.AUDIT_TRIGGERS,
    ("blind_audit_runs", "seed_source"): v.SEED_SOURCES,
    ("blind_audit_items", "ai_class"): v.DISPOSITIONS,
    ("blind_audit_items", "label"): v.AUDIT_LABELS,
    ("shadow_effects", "outcome"): EFFECT_OUTCOMES,
    ("pov_runs", "backtest_status"): POV_BACKTEST_STATUSES,
    ("shadow_verdicts", "prod_route"): v.ROUTES,
    ("shadow_verdicts", "cand_route"): v.ROUTES,
    ("shadow_verdicts", "prod_disposition"): v.DISPOSITIONS,
    ("shadow_verdicts", "cand_disposition"): v.DISPOSITIONS,
    # Suppression rules only ever close alerts as benign.
    ("suppression_rules", "disposition"): ("benign",),
}

# Local CHECKs only: partitions inherit their parent's (conislocal = false).
CHECKS_SQL = """
    SELECT c.conrelid::regclass::text, pg_get_constraintdef(c.oid)
    FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
    WHERE c.contype = 'c' AND c.conislocal AND n.nspname = 'public'
"""
# The value-list forms PostgreSQL prints for IN (...), = '...' and <@ ARRAY[...].
_LIST_RE = re.compile(r"\(?(\w+)\)? (?:= ANY|<@) \(?ARRAY\[([^\]]*)\]")
# A single admitted value only when it is the whole check (not a condition inside a larger one).
_ONE_RE = re.compile(r"^CHECK \(\((\w+) = ('(?:[^']|'')*'::text)\)\)$")
_VALUE_RE = re.compile(r"'((?:[^']|'')*)'::text")


def _value_lists(url: str) -> Dict[Tuple[str, str], FrozenSet[str]]:
    with psycopg.connect(to_libpq_url(url)) as conn:
        rows = conn.execute(CHECKS_SQL).fetchall()
    found: Dict[Tuple[str, str], FrozenSet[str]] = {}
    for table, definition in rows:
        for column, listed in [*_LIST_RE.findall(definition), *_ONE_RE.findall(definition)]:
            key = (table, column)
            assert key not in found, f"two value-list checks on {key}: {definition}"
            found[key] = frozenset(m.replace("''", "'") for m in _VALUE_RE.findall(listed))
    return found


async def test_value_list_checks_match_the_vocabulary(migrated_database_url: str) -> None:
    found = _value_lists(migrated_database_url)
    assert set(found) == set(EXPECTED), "map every value-list CHECK to the declaration the code validates against"
    mismatched = {key: (sorted(found[key]), sorted(values)) for key, values in EXPECTED.items() if found[key] != set(values)}
    assert mismatched == {}, "(database, code): a vocabulary changed without a migration, or the reverse"
