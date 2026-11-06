"""The domain vocabulary (roadmap F2): every other declaration of a vocabulary holds the same values.

``lg_sotf.models.vocabulary`` declares each cross-package value set once. The
names other modules keep (repository re-exports, API and MCP ``Literal``
aliases, the settings models, which sit below ``models`` and cannot import it)
must hold exactly its values: compared as sets, because only the canonical
declaration fixes the order, except ``ROLE_RANK``, which is an order. The
database ``CHECK`` constraints are compared in
``tests/integration/db/test_vocabulary_constraints.py``.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Any, Iterator, List, Literal, Tuple, Union, get_args, get_origin

import pytest

from lg_sotf.models import vocabulary as v

SRC = Path(v.__file__).resolve().parents[1]

# (vocabulary values, "module:attribute") for every name that redeclares or re-exports a vocabulary.
SITES: List[Tuple[Any, str]] = [
    # roles and scopes
    (v.Role, "lg_sotf.api.schemas:Role"),
    (v.ROLES, "lg_sotf.api.auth.principal:ROLES"),
    (v.ROLES, "lg_sotf.services.review:ROLES"),
    (v.ROLES, "lg_sotf.db.repos.users:ROLES"),
    (v.REVIEWER_ROLES, "lg_sotf.services.review:REVIEWER_ROLES"),
    (v.ROLES, "lg_sotf.settings:AuthSettings.oidc_role_map"),
    (v.ROLES, "lg_sotf.settings:AuthSettings.oidc_default_role"),
    (v.Scope, "lg_sotf.api.schemas:Scope"),
    (v.SCOPES, "lg_sotf.api.auth.principal:SCOPES"),
    (v.SCOPES, "lg_sotf.db.repos.api_keys:API_KEY_SCOPES"),
    # severity
    (v.Severity, "lg_sotf.models.alert:Severity"),
    (v.SEVERITIES, "lg_sotf.models.alert:SEVERITIES"),
    (v.SEVERITIES, "lg_sotf.db.repos.alerts:SEVERITIES"),
    (v.SEVERITIES, "lg_sotf.queue.streams:SEVERITIES"),
    (v.SEVERITIES, "lg_sotf.integrations.events:SEVERITIES"),
    (v.Severity, "lg_sotf.api.routers.alerts:Severity"),
    (v.Severity, "lg_sotf.api.routers.integrations:Severity"),
    (v.Severity, "lg_sotf.mcp.tools:Severity"),
    (v.SEVERITIES, "lg_sotf.mcp.tools:SEVERITIES"),
    (v.HIGH_SEVERITIES, "lg_sotf.core.routing:HIGH_SEVERITIES"),
    (v.HIGH_SEVERITIES, "lg_sotf.eval.metrics:HIGH_SEVERITIES"),
    (v.HIGH_SEVERITIES, "lg_sotf.queue.streams:HIGH_PRIORITY_SEVERITIES"),
    # alert status, disposition, route
    (v.ALERT_STATUSES, "lg_sotf.db.repos.alerts:ALERT_STATUSES"),
    (v.AlertStatus, "lg_sotf.api.routers.alerts:AlertStatus"),
    (v.AlertStatus, "lg_sotf.mcp.tools:AlertStatus"),
    (v.ALERT_STATUSES, "lg_sotf.mcp.tools:ALERT_STATUSES"),
    (v.DISPOSITIONS, "lg_sotf.db.repos.alerts:DISPOSITIONS"),
    (v.Disposition, "lg_sotf.api.routers.alerts:Disposition"),
    (v.Disposition, "lg_sotf.eval.dataset:Disposition"),
    (v.DISPOSITIONS, "lg_sotf.eval.dataset:DISPOSITIONS"),
    (v.Disposition, "lg_sotf.mcp.tools:Disposition"),
    (v.DISPOSITIONS, "lg_sotf.mcp.tools:DISPOSITIONS"),
    (v.DISPOSITIONS, "lg_sotf.mcp.runs:DISPOSITIONS"),
    (v.Disposition, "lg_sotf.mcp.tester:DispositionLabel"),
    (v.Disposition, "lg_sotf.services.reporting:AiClass"),
    (v.DISPOSITIONS, "lg_sotf.services.reporting:AI_CLASSES"),
    (v.Route, "lg_sotf.core.routing:DecideRoute"),
    (v.ROUTES, "lg_sotf.mcp.runs:ROUTES"),
    (v.Route, "lg_sotf.mcp.tester:RouteLabel"),
    (v.Route, "lg_sotf.eval.dataset:Route"),
    (v.ROUTES, "lg_sotf.eval.dataset:ROUTES"),
    # escalations
    (v.DECISIONS, "lg_sotf.db.repos.escalations:DECISIONS"),
    (v.Decision, "lg_sotf.api.schemas:Decision"),
    (v.BENIGN_DECISIONS, "lg_sotf.core.routing:BENIGN_DECISIONS"),
    (v.BENIGN_DECISIONS, "lg_sotf.core.verdict_cache:BENIGN_DECISIONS"),
    (v.BENIGN_DECISIONS, "lg_sotf.services.reporting:BENIGN_DECISIONS"),
    (v.BENIGN_DECISIONS, "lg_sotf.compliance.evidence:BENIGN_DECISIONS"),
    (v.ESCALATION_STATUSES, "lg_sotf.db.repos.escalations:ESCALATION_STATUSES"),
    (v.EscalationStatus, "lg_sotf.api.routers.review:EscalationStatus"),
    (v.EscalationStatus, "lg_sotf.mcp.tools:EscalationStatus"),
    (v.ESCALATION_STATUSES, "lg_sotf.mcp.tools:ESCALATION_STATUSES"),
    (v.ESCALATION_LEVELS, "lg_sotf.db.repos.escalations:ESCALATION_LEVELS"),
    (v.ESCALATION_LEVELS, "lg_sotf.integrations.events:LEVELS"),
    (v.EscalationLevel, "lg_sotf.api.routers.review:Level"),
    (v.EscalationLevel, "lg_sotf.services.escalation:Level"),
    (v.EscalationLevel, "lg_sotf.mcp.tools:Level"),
    (v.ESCALATION_LEVELS, "lg_sotf.mcp.tools:LEVELS"),
    # response actions
    (v.ACTION_STATUSES, "lg_sotf.db.repos.actions:ACTION_STATUSES"),
    (v.TERMINAL_ACTION_STATUSES, "lg_sotf.db.repos.actions:TERMINAL_ACTION_STATUSES"),
    (v.ActionStatus, "lg_sotf.api.routers.review:ActionStatus"),
    (v.ACTION_STATUSES, "lg_sotf.mcp.tester:ACTION_STATUSES"),
    (v.ActionStatus, "lg_sotf.mcp.tester:ActionStatus"),
    (v.COMPLETED_ACTION_STATUSES, "lg_sotf.core.routing:COMPLETED_ACTION_STATUSES"),
    (v.RISK_LEVELS, "lg_sotf.db.repos.actions:RISK_LEVELS"),
    (v.RISK_LEVELS, "lg_sotf.services.response:RISK_LEVELS"),
    (v.RiskLevel, "lg_sotf.api.routers.review:Risk"),
    (v.RISK_LEVELS, "lg_sotf.mcp.tester:RISKS"),
    (v.RiskLevel, "lg_sotf.mcp.tester:Risk"),
    (v.AutonomyMode, "lg_sotf.services.response:Autonomy"),
    (v.AUTONOMY_MODES, "lg_sotf.services.response:AUTONOMY_MODES"),
    (v.AutonomyMode, "lg_sotf.settings:Autonomy"),
    (v.VERIFICATION_STATES, "lg_sotf.db.repos.actions:VERIFICATION_STATES"),
    (v.VerificationState, "lg_sotf.db.repos.actions:VerificationStateName"),
    (v.FINAL_VERIFICATION_STATES, "lg_sotf.db.repos.actions:FINAL_VERIFICATION_STATES"),
    (v.VerificationState, "lg_sotf.services.connectors.base:VerificationState"),
    (v.VerificationState, "lg_sotf.api.routers.review:Verification"),
    (v.VERIFICATION_STATES, "lg_sotf.mcp.tester:VERIFICATIONS"),
    (v.VerificationState, "lg_sotf.mcp.tester:VerificationState"),
    (v.EXECUTION_OWNERS, "lg_sotf.db.repos.actions:EXECUTION_OWNERS"),
    (v.WORKFLOW_OWNER, "lg_sotf.services.response:WORKFLOW_OWNER"),
    (v.WORKFLOW_OWNER, "lg_sotf.services.review:WORKFLOW_OWNER"),
    (v.SCHEDULER_OWNER, "lg_sotf.services.response:SCHEDULER_OWNER"),
    (v.REQUESTED_BY, "lg_sotf.services.response:REQUESTED_BY"),
    (v.POLICY_APPROVER, "lg_sotf.services.response:POLICY_APPROVER"),
    (v.POLICY_APPROVER, "lg_sotf.compliance.evidence:POLICY_APPROVER"),
    (v.POLICY_APPROVER, "lg_sotf.db.repos.reports:POLICY_APPROVER"),
    # workflow runs
    (v.RUN_STATUSES, "lg_sotf.db.repos.runs:RUN_STATUSES"),
    (v.TERMINAL_RUN_STATUSES, "lg_sotf.db.repos.runs:TERMINAL_RUN_STATUSES"),
    (v.TERMINAL_RUN_STATUSES, "lg_sotf.services.review:ENDED_RUN_STATUSES"),
    (v.WAITING_RUN_STATUSES, "lg_sotf.db.repos.runs:WAITING_RUN_STATUSES"),
    # sources
    (v.SOURCE_TYPES, "lg_sotf.db.repos.sources:SOURCE_TYPES"),
    (v.SourceType, "lg_sotf.api.schemas:SourceType"),
    (v.PUSH_SOURCE_TYPES, "lg_sotf.db.repos.sources:PUSH_SOURCE_TYPES"),
    (v.PUSH_SOURCE_TYPES, "lg_sotf.ingestion.sources:PUSH_ONLY_TYPES"),
]

# Ranks: the same value for every key (an order, so not a set comparison).
RANKS: List[Tuple[Any, str]] = [
    (v.ROLE_RANK, "lg_sotf.api.auth.principal:ROLE_RANK"),
    (v.SEVERITY_RANK, "lg_sotf.core.verdict_cache:SEVERITY_RANK"),
    (v.SEVERITY_RANK, "lg_sotf.services.escalation:SEVERITY_RANK"),
    (v.SEVERITY_RANK, "lg_sotf.integrations.events:SEVERITY_RANK"),
]


def _resolve(site: str) -> Any:
    module_name, _, path = site.partition(":")
    owner: Any = importlib.import_module(module_name)
    name, _, field = path.partition(".")
    value = getattr(owner, name)
    if field:  # a pydantic model field: its annotation
        value = value.model_fields[field].annotation
    return value


def _literal_values(annotation: Any) -> Iterator[Any]:
    """The values of every ``Literal`` inside an annotation (through ``Optional``, ``Dict`` and the like)."""
    if get_origin(annotation) is Literal:
        yield from get_args(annotation)
        return
    for arg in get_args(annotation):
        if arg is not type(None):
            yield from _literal_values(arg)


def _values(value: Any) -> frozenset[Any]:
    if isinstance(value, str):
        return frozenset({value})
    if get_origin(value) in (Literal, Union) or get_args(value):
        return frozenset(_literal_values(value))
    return frozenset(value)


@pytest.mark.parametrize(("expected", "site"), SITES, ids=[site for _, site in SITES])
def test_every_declaration_holds_the_vocabulary(expected: Any, site: str) -> None:
    assert _values(_resolve(site)) == _values(expected), site


@pytest.mark.parametrize(("expected", "site"), RANKS, ids=[site for _, site in RANKS])
def test_ranks_order_the_vocabulary(expected: Any, site: str) -> None:
    assert dict(_resolve(site)) == dict(expected), site


def test_each_tuple_is_its_literal() -> None:
    pairs = [
        (v.Role, v.ROLES), (v.Scope, v.SCOPES), (v.Severity, v.SEVERITIES), (v.AlertStatus, v.ALERT_STATUSES),
        (v.Disposition, v.DISPOSITIONS), (v.Route, v.ROUTES), (v.Decision, v.DECISIONS),
        (v.EscalationStatus, v.ESCALATION_STATUSES), (v.EscalationLevel, v.ESCALATION_LEVELS),
        (v.ActionStatus, v.ACTION_STATUSES), (v.RiskLevel, v.RISK_LEVELS), (v.AutonomyMode, v.AUTONOMY_MODES),
        (v.VerificationState, v.VERIFICATION_STATES), (v.ExecutionOwner, v.EXECUTION_OWNERS),
        (v.RunStatus, v.RUN_STATUSES), (v.SourceType, v.SOURCE_TYPES),
    ]
    for literal, values in pairs:
        assert get_args(literal) == values
        assert len(set(values)) == len(values)


def test_subsets_are_subsets() -> None:
    assert v.REVIEWER_ROLES < set(v.ROLES)
    assert v.HIGH_SEVERITIES < set(v.SEVERITIES)
    assert v.BENIGN_DECISIONS < set(v.DECISIONS)
    assert set(v.TERMINAL_ACTION_STATUSES) < set(v.ACTION_STATUSES)
    assert v.COMPLETED_ACTION_STATUSES <= set(v.TERMINAL_ACTION_STATUSES)
    assert set(v.FINAL_VERIFICATION_STATES) == set(v.VERIFICATION_STATES) - {"pending"}
    assert set(v.TERMINAL_RUN_STATUSES) < set(v.RUN_STATUSES)
    assert set(v.WAITING_RUN_STATUSES) < set(v.RUN_STATUSES)
    assert set(v.WAITING_RUN_STATUSES) < set(v.ALERT_STATUSES)
    assert set(v.PUSH_SOURCE_TYPES) < set(v.SOURCE_TYPES)
    assert set(v.RISK_LEVELS) < set(v.SEVERITIES)
    assert (v.WORKFLOW_OWNER, v.SCHEDULER_OWNER) == v.EXECUTION_OWNERS


def test_terminal_action_statuses_are_the_state_machine_sinks() -> None:
    from lg_sotf.db.repos.actions import ACTION_TRANSITIONS

    assert set(ACTION_TRANSITIONS) == set(v.ACTION_STATUSES)
    assert {s for s, targets in ACTION_TRANSITIONS.items() if not targets} == set(v.TERMINAL_ACTION_STATUSES)


def test_ranks_follow_the_canonical_order() -> None:
    assert list(v.ROLE_RANK) == ["viewer", "analyst", "admin"]
    assert [v.ROLE_RANK[r] for r in v.ROLES] == [0, 1, 2]
    assert [v.SEVERITY_RANK[s] for s in v.SEVERITIES] == [0, 1, 2, 3, 4]


def test_the_vocabulary_imports_only_the_standard_library() -> None:
    tree = ast.parse((SRC / "models" / "vocabulary.py").read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= {"__future__", "typing"}
