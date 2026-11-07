"""Vocabulary enums in OpenAPI, tolerant reader (roadmap T2, ADR-0009).

Every response field drawn from a vocabulary advertises its values as an
``enum`` in the published schema, in the vocabulary's canonical order. At
runtime the field stays a plain string: a response model accepts and returns a
value the schema does not list (a newer release during a rolling deploy).
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Sequence, Tuple, get_args
from uuid import uuid4

import pytest

from lg_sotf.api import schemas
from lg_sotf.compliance import nis2
from lg_sotf.db.repos.alert_events import EVENT_ACTOR_TYPES
from lg_sotf.db.repos.audit import AUDIT_ACTOR_TYPES
from lg_sotf.db.repos.integrations import INTEGRATION_KINDS, TICKETING_KINDS
from lg_sotf.db.repos.outbox import OUTBOX_OPERATIONS, OUTBOX_STATUSES
from lg_sotf.db.repos.sources import SOURCE_HEALTH
from lg_sotf.db.repos.tenants import TENANT_STATUSES
from lg_sotf.domain.actions import ACTION_CATALOG, TargetKind
from lg_sotf.integrations.events import EVENT_TYPES as INTEGRATION_EVENT_TYPES
from lg_sotf.models import vocabulary as v

ACTION_TYPES = tuple(ACTION_CATALOG)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "export_openapi.py"

# (component schema, field, the values its enum lists)
ENUM_FIELDS: List[Tuple[str, str, Sequence[str]]] = [
    # identity: auth, users, API keys
    ("UserOut", "role", v.ROLES),
    ("MeOut", "role", v.ROLES),
    ("MeOut", "scopes", v.SCOPES),
    ("ApiKeyOut", "scopes", v.SCOPES),
    ("ApiKeyCreatedOut", "scopes", v.SCOPES),
    # alerts
    ("AlertOut", "severity", v.SEVERITIES),
    ("AlertOut", "status", v.ALERT_STATUSES),
    ("AlertOut", "disposition", v.DISPOSITIONS),
    ("AlertDetailOut", "severity", v.SEVERITIES),
    ("AlertDetailOut", "status", v.ALERT_STATUSES),
    ("AlertDetailOut", "disposition", v.DISPOSITIONS),
    ("AlertEventOut", "actor_type", EVENT_ACTOR_TYPES),
    ("ReprocessOut", "status", v.ALERT_STATUSES),
    # escalations: review queue, triage and response preview
    ("EscalationOut", "level", v.ESCALATION_LEVELS),
    ("EscalationOut", "status", v.ESCALATION_STATUSES),
    ("EscalationOut", "decision", v.DECISIONS),
    ("EscalationOut", "alert_severity", v.SEVERITIES),
    ("PreviewActionOut", "risk", v.RISK_LEVELS),
    ("PreviewActionOut", "autonomy", v.AUTONOMY_MODES),
    # response actions
    ("ActionOut", "risk_level", v.RISK_LEVELS),
    ("ActionOut", "status", v.ACTION_STATUSES),
    ("ActionOut", "execution_owner", v.EXECUTION_OWNERS),
    ("ActionOut", "verification", v.VERIFICATION_STATES),
    ("RollbackEligibilityOut", "risk", v.RISK_LEVELS),
    ("ActionOut", "action_type", ACTION_TYPES),
    ("RollbackEligibilityOut", "action_type", ACTION_TYPES),
    ("PreviewActionOut", "action_type", ACTION_TYPES),
    ("BlastRadiusOut", "target_kind", get_args(TargetKind)),
    # sources
    ("SourceOut", "type", v.SOURCE_TYPES),
    ("SourceOut", "health", SOURCE_HEALTH),
    # suppressions
    ("SuppressionOut", "disposition", v.DISPOSITIONS),
    # integrations, deliveries and tickets
    ("IntegrationOut", "kind", INTEGRATION_KINDS),
    ("IntegrationOut", "events", INTEGRATION_EVENT_TYPES),
    ("IntegrationOut", "min_severity", v.SEVERITIES),
    ("DeliveryOut", "operation", OUTBOX_OPERATIONS),
    ("DeliveryOut", "status", OUTBOX_STATUSES),
    ("TicketOut", "system", TICKETING_KINDS),
    # tenant settings
    ("TenantSettingsOut", "status", TENANT_STATUSES),
    # platform administration
    ("TenantCreatedOut", "status", TENANT_STATUSES),
    ("TenantSummaryOut", "status", TENANT_STATUSES),
    ("TenantUsageOut", "tenant_status", TENANT_STATUSES),
    ("PlatformEscalationOut", "tenant_status", TENANT_STATUSES),
    ("PlatformEscalationOut", "alert_severity", v.SEVERITIES),
    ("PlatformEscalationOut", "level", v.ESCALATION_LEVELS),
    ("PlatformEscalationOut", "status", v.ESCALATION_STATUSES),
    # compliance: NIS2 reports and tenant erasure
    ("IncidentReportOut", "stage", nis2.STAGES),
    ("ErasureStatusOut", "status", TENANT_STATUSES),
    # audit log
    ("AuditEntryOut", "actor_type", AUDIT_ACTOR_TYPES),
    # reports
    ("Detection", "median_severity", v.SEVERITIES),
    ("Detection", "max_severity", v.SEVERITIES),
    ("Detection", "max_confirmed_benign_severity", v.SEVERITIES),
]


def _exporter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("export_openapi", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def document() -> Dict[str, Any]:
    built: Dict[str, Any] = _exporter().build_openapi()
    return built


@pytest.fixture(scope="module")
def components(document: Dict[str, Any]) -> Dict[str, Any]:
    schemas_: Dict[str, Any] = document["components"]["schemas"]
    return schemas_


@pytest.fixture(scope="module")
def paths(document: Dict[str, Any]) -> Dict[str, Any]:
    paths_: Dict[str, Any] = document["paths"]
    return paths_


def _enum(prop: Dict[str, Any]) -> List[str]:
    """The enum of a string field, of the items of a list field, or of the non-null branch of an optional one."""
    if "anyOf" in prop:
        branches = [b for b in prop["anyOf"] if b.get("type") != "null"]
        assert len(branches) == 1, prop
        return _enum(branches[0])
    if prop.get("type") == "array":
        return _enum(prop["items"])
    assert prop.get("type") == "string", prop
    enum: List[str] = prop["enum"]
    return enum


@pytest.mark.parametrize(("schema", "field", "values"), ENUM_FIELDS, ids=[f"{s}.{f}" for s, f, _ in ENUM_FIELDS])
def test_response_field_advertises_its_vocabulary(
    components: Dict[str, Any], schema: str, field: str, values: Sequence[str]
) -> None:
    assert _enum(components[schema]["properties"][field]) == list(values)


DOCUMENTED_RESPONSES = [
    ("/readyz", "get", "200", "ReadinessOut"),
    ("/readyz", "get", "503", "ReadinessOut"),
    ("/api/v1/alerts/{alert_id}/evidence", "get", "200", "EvidencePackOut"),
    ("/api/v1/tenant/response/routes", "get", "200", "ResponseRoutesOut"),
    ("/api/v1/integrations/microsoft/catalog", "get", "200", "MicrosoftCatalogOut"),
]


@pytest.mark.parametrize(("path", "method", "status", "model"), DOCUMENTED_RESPONSES)
def test_plain_json_responses_are_documented(
    paths: Dict[str, Any], path: str, method: str, status: str, model: str
) -> None:
    """Routes that build their JSON themselves publish its schema (``responses={...: {"model": X}}``)."""
    content = paths[path][method]["responses"][status]["content"]
    assert content["application/json"]["schema"] == {"$ref": f"#/components/schemas/{model}"}


def test_no_json_response_is_untyped(paths: Dict[str, Any]) -> None:
    """Every 2xx JSON body has a schema with a shape (not ``{}`` and not a bare ``Dict[str, Any]``)."""
    untyped = []
    for path, operations in paths.items():
        for method, operation in operations.items():
            for status, response in operation.get("responses", {}).items():
                schema = response.get("content", {}).get("application/json", {}).get("schema")
                if status.startswith("2") and schema is not None:
                    shaped = any(key in schema for key in ("$ref", "properties", "anyOf", "items"))
                    if not shaped and schema.get("additionalProperties") in (None, True):
                        untyped.append(f"{method.upper()} {path} {status}")
    assert untyped == []


def test_tenant_export_is_a_zip_only(paths: Dict[str, Any]) -> None:
    content = paths["/api/v1/platform/tenants/{tenant_id}/export"]["post"]["responses"]["200"]["content"]
    assert content == {"application/zip": {"schema": {"type": "string", "format": "binary"}}}


def test_vocabulary_schema_keeps_the_canonical_order() -> None:
    assert schemas.vocabulary_schema(v.SEVERITIES) == {"type": "string", "enum": list(v.SEVERITIES)}


def test_response_models_tolerate_unknown_values() -> None:
    """A value from a newer release is accepted and returned unchanged (no 500 during a rolling deploy)."""
    me = schemas.MeOut(
        kind="user", tenant_id="t1", home_tenant_id="t1", auth_method="password", role="auditor", scopes=["export"]
    )
    assert me.model_dump(mode="json")["role"] == "auditor"
    assert me.model_dump(mode="json")["scopes"] == ["export"]


def test_action_verification_is_a_tolerant_reader_too() -> None:
    """``verification`` was a strict ``Literal`` before T2: an unknown state now serializes instead of a 500."""
    now = datetime.now(UTC)
    action = schemas.ActionOut(
        id=uuid4(),
        tenant_id="t1",
        alert_id="a1",
        action_type="isolate_host",
        target="host-1",
        risk_level="severe",
        status="paused",
        created_at=now,
        updated_at=now,
        verification="superseded",
    )
    dumped = action.model_dump(mode="json")
    assert (dumped["risk_level"], dumped["status"], dumped["verification"]) == ("severe", "paused", "superseded")


def test_request_models_stay_strict() -> None:
    """Requests validate against the vocabulary itself: an unknown role is refused."""
    with pytest.raises(ValueError, match="role"):
        schemas.UserUpdateIn(role="auditor")  # type: ignore[arg-type]
