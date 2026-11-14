# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/onboarding/connectors`` (admin): guided setup of an alert source.

``POST /onboarding/connectors/wazuh/check`` runs the Wazuh setup checks
(:mod:`lg_sotf.ingestion.guided.wazuh`) and answers with one result per
check: ``passed``, ``failed`` with the exact fix, or ``skipped``.

* ``pull``: the config and credentials of a Wazuh indexer source that is not
  saved yet. The connector the poller uses sends one read-only search
  through the install's destination policy. The credentials are used for
  this request only: they are not stored, logged, audited or returned.
* ``push``: the id of the webhook source the Wazuh manager posts to and,
  optionally, the API key it sends. The key is compared with the tenant's
  keys and never stored or returned.

Like creating a source, this is refused under a grant. A tenant gets
``SETUP_CHECK_PER_MINUTE`` runs a minute (``429`` beyond): each run may send a
request to a host the caller names and compare a pasted key. Each run is
audited as ``source.setup_checked`` with the ids of the failed checks.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, SecretStr, model_validator

from lg_sotf.api.auth.deps import ADMIN_NOT_UNDER_GRANT, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import get_ctx
from lg_sotf.api.ratelimit import rate_limited
from lg_sotf.api.schemas import SOURCE_ID_PATTERN, In
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.ingestion.guided import SetupCheck, all_passed
from lg_sotf.ingestion.guided.wazuh import check_wazuh_push

router = APIRouter(prefix="/onboarding/connectors", tags=["onboarding"])

DEFAULT_PUSH_SOURCE_ID = "wazuh-push"
SETUP_CHECK_BUCKET = "source_setup_check"
SETUP_CHECK_PER_MINUTE = 20


class SetupCheckOut(BaseModel):
    id: str = Field(description="Stable id of the check, e.g. reachable, tls, credentials, index_permission.")
    title: str
    status: Literal["passed", "failed", "skipped"]
    message: str = Field(description="What was found; never holds a credential.")
    fix: Optional[str] = Field(default=None, description="What to change, on a failed check.")


class GuidedCheckOut(BaseModel):
    ok: bool = Field(description="No check failed and at least one passed.")
    checks: List[SetupCheckOut]


class WazuhPullIn(In):
    config: Dict[str, Any] = Field(
        description="The source config to check: base_url, and optionally index, time_field, ca_cert_pem."
    )
    secret: Dict[str, Any] = Field(
        description="username and password of the indexer user; used for this check only, never stored or returned."
    )


class WazuhPushIn(In):
    source_id: str = Field(default=DEFAULT_PUSH_SOURCE_ID, pattern=SOURCE_ID_PATTERN)
    api_key: Optional[SecretStr] = Field(
        default=None, max_length=300, description="The API key the Wazuh manager sends; checked, never stored."
    )


class WazuhCheckIn(In):
    pull: Optional[WazuhPullIn] = None
    push: Optional[WazuhPushIn] = None

    @model_validator(mode="after")
    def _something_to_check(self) -> WazuhCheckIn:
        if self.pull is None and self.push is None:
            raise ValueError("send pull, push or both")
        return self


@router.post("/wazuh/check", response_model=GuidedCheckOut, summary="Guided Wazuh setup: run the connection checks")
async def check_wazuh(
    body: WazuhCheckIn, request: Request, principal: Principal = Depends(require(ADMIN_NOT_UNDER_GRANT))
) -> GuidedCheckOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    decision = await ctx.limiter.hit(SETUP_CHECK_BUCKET, tenant_id, SETUP_CHECK_PER_MINUTE, tenant_id=tenant_id)
    if not decision.allowed:
        raise rate_limited(decision)
    checks: List[SetupCheck] = []
    if body.pull is not None:
        checks += await ctx.ingestion.check_wazuh_setup(tenant_id, body.pull.config, body.pull.secret)
    if body.push is not None:
        key = body.push.api_key.get_secret_value() if body.push.api_key is not None else None
        checks += await check_wazuh_push(ctx.repos, tenant_id, body.push.source_id, key)
    ok = all_passed(checks)
    # A connectivity check, not a change: recorded on its own, without the URL or any credential.
    await AuditLogger(ctx.repos).record_event(
        tenant_id,
        "source.setup_checked",
        "source",
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={
            "kind": "wazuh",
            "modes": [mode for mode, section in (("pull", body.pull), ("push", body.push)) if section is not None],
            "ok": ok,
            "failed": [c.id for c in checks if c.status == "failed"],
        },
    )
    return GuidedCheckOut(
        ok=ok,
        checks=[SetupCheckOut(id=c.id, title=c.title, status=c.status, message=c.message, fix=c.fix) for c in checks],
    )
