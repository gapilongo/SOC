"""Schemas of the JSON responses that routers build as plain dicts (roadmap T2, ADR-0009).

These endpoints return a ``dict`` or a ``Response`` they built themselves (a
sealed evidence bundle, a catalog, a probe result). Each one documents its
body with ``responses={200: {"model": X}}``, never ``response_model``: FastAPI
then publishes the schema but serializes the payload exactly as before. The
models are never instantiated, so their ``Literal`` fields only advertise
values; nothing validates against them at runtime.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from lg_sotf.api.schemas import ActionTypeStr, RiskLevelStr
from lg_sotf.integrations.microsoft.capability import Package
from lg_sotf.integrations.microsoft.clouds import Api, Cloud
from lg_sotf.services.connectors.routing import RouteSource

# ------------------------------------------------------------------ health


class ReadinessOut(BaseModel):
    """``GET /readyz``: 200 when every dependency answers, else 503 with the same body."""

    status: Literal["ok", "unavailable"]
    checks: Dict[str, Literal["ok", "busy", "error"]] = Field(
        description="Per dependency (database, redis): busy means every pooled connection is serving requests."
    )


# ---------------------------------------------------------------- evidence


class EvidenceIntegrityOut(BaseModel):
    canonicalization: str
    bundle_sha256: str = Field(description="SHA-256 of the canonical bundle without this block (X-Evidence-Bundle-SHA256).")
    signature: Optional[Dict[str, str]] = Field(default=None, description="alg, key_id and value when a key is set.")


class EvidencePackOut(BaseModel):
    """``GET /alerts/{alert_id}/evidence``: the sealed case bundle (docs/compliance.md)."""

    format: str = Field(description="lg-sotf.evidence-pack")
    version: int
    generated_at: datetime
    generated_by: Dict[str, Any]
    lg_sotf_version: str
    tenant_id: str
    alert: Dict[str, Any] = Field(description="The alert record, raw payload redacted (raw_redacted, raw_redactions).")
    timeline: List[Dict[str, Any]]
    agents: Dict[str, Any] = Field(description="Per workflow step: whether it ran, its model, verdict and reasoning.")
    investigation: Dict[str, Any] = Field(
        description="The investigation trace: every LLM and tool step (prompt and model or tool, tokens, latency, "
        "input and output SHA-256, redacted result digest) and totals."
    )
    enrichment: Dict[str, Any]
    correlation: Dict[str, Any]
    escalations: List[Dict[str, Any]]
    feedback: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    human_oversight: Dict[str, Any]
    audit: Dict[str, Any] = Field(description="The audit entries of the case and the chain verification.")
    limits: Dict[str, bool] = Field(description="Which lists were truncated.")
    integrity: EvidenceIntegrityOut


# ------------------------------------------------------- response routing


class RouteOut(BaseModel):
    connector: str = Field(description="microsoft, ticketing, webhook or dry_run.")
    source: RouteSource
    capability: Optional[str] = None
    live: Optional[bool] = None
    problem: Optional[str] = None


class ResponseRoutesOut(BaseModel):
    """``GET /tenant/response/routes``: which connector executes each catalog action type, and why."""

    dry_run_forced: bool
    routes: Dict[str, RouteOut] = Field(description="Keyed by action type.")


# ------------------------------------------------------- Microsoft catalog


class MicrosoftActionSupportOut(BaseModel):
    reversible: bool
    rollback_window_s: Optional[int] = None
    note: str
    inverse: Optional[ActionTypeStr] = None
    risk: Optional[RiskLevelStr] = None
    restorative: bool
    irreversible_note: str


class MicrosoftPermissionOut(BaseModel):
    api: Api
    role: str
    purpose: str
    required: bool
    when: str
    directory_role: Optional[str] = None
    exchange_rbac: Optional[str] = None


class MicrosoftCapabilityOut(BaseModel):
    key: str
    package: Package
    api: Api
    title: str
    description: str
    actions: Dict[str, MicrosoftActionSupportOut] = Field(description="Keyed by action type.")
    permissions: List[MicrosoftPermissionOut]
    options_schema: Dict[str, Any] = Field(description="JSON schema of the capability's options.")
    options_defaults: Dict[str, Any]
    clouds: List[Cloud]
    licence: str
    live_confirmation: str
    excludes: List[str]


class MicrosoftCloudOut(BaseModel):
    name: Cloud
    login_host: str
    graph_host: str
    defender_supported: bool


class MicrosoftCatalogOut(BaseModel):
    """``GET /integrations/microsoft/catalog``: the capabilities, the clouds and the Defender geos."""

    capabilities: List[MicrosoftCapabilityOut]
    clouds: List[MicrosoftCloudOut]
    defender_geos: List[str]


__all__ = [
    "EvidencePackOut",
    "MicrosoftCatalogOut",
    "ReadinessOut",
    "ResponseRoutesOut",
]
