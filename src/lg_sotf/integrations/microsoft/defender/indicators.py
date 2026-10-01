"""``defender.indicators`` and ``defender.file_indicators``: Defender for Endpoint custom indicators.

Network indicators (``block_ip``/``block_domain``/``block_url``, undone by
``unblock_*``) use ``action: "Block"``; file indicators (``quarantine_file``,
undone by ``unblock_file``) use ``action: "BlockAndRemediate"``. The legacy
``Alert``/``AlertAndBlock`` values and ``Warn`` are never sent.

Block (and quarantine by file indicator)
    1. Validate the target for its indicator type: ``IpAddress`` (a single
       *public* address; Defender takes external single IPs only, no CIDR),
       ``DomainName``, ``Url``, or ``FileSha256``/``FileSha1``/``FileMd5`` by
       hash length (SHA-512 is ``unsupported_target``).
    2. ``GET /api/indicators?$filter=indicatorValue eq '<v>' and indicatorType eq '<T>'``
       (active indicators only): an ``Allowed`` or ``Warn`` indicator wins over a
       block (Allow > Warn > Block), so the action fails with
       ``conflicting_indicator``; a block whose description carries our marker
       is adopted (a re-run); a block by someone else means the value is
       already blocked (``already``, and a rollback will not delete it).
    3. Checkpoint, then ``POST /api/indicators`` with the exact
       (case-sensitive) body keys, always with an ``expirationTime``.
       ``POST /api/indicators`` is an upsert on an undocumented key: when it
       answers with the id of an indicator that existed before, that
       indicator was updated in place and is not ours to delete.
    4. Verify inline by repeating the lookup: present, blocking and not
       expired -> ``verified`` (enforcement itself takes up to 48 h for network
       indicators, typically 15-30 min for files); missing -> ``failed`` with
       ``not_verified`` (retryable: a retry adopts the indicator by its marker).

Unblock
    Only an indicator LG-SOTF created (``original.external_ref.created``) is
    deleted: ``DELETE /api/indicators/{id}`` (204; 404 counts as done), then
    the lookup must no longer show it. An indicator someone else changed in
    the meantime (the description lost our marker) is left alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Literal, Mapping, Optional, Tuple

from pydantic import Field, field_validator

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import CapabilityOptions, HandlerContext, ProbeCheck, action_marker
from lg_sotf.integrations.microsoft.defender._common import (
    Hints,
    Refused,
    failure,
    iso_z,
    ms_id,
    now,
    parse_time,
    probe_get,
    settle,
    text,
    values,
)
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult, VerifyPlan

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

INDICATORS_PATH = "/api/indicators"
PERMISSION = "Ti.ReadWrite.All"
BLOCK_ACTIONS = frozenset({"Block", "BlockAndRemediate", "AlertAndBlock"})
# Allow > Warn > Block: an existing Allowed or Warn indicator makes a block of the same value ineffective.
CONFLICTING_ACTIONS = frozenset({"Allowed", "Warn"})
MAX_GROUP_NAME_CHARS = 256
TITLE_TARGET_CHARS = 60


class DefenderIndicatorOptions(CapabilityOptions):
    """Options of ``defender.indicators`` and ``defender.file_indicators``.

    ``expiration_days``: every indicator expires (the tenant holds at most
    15,000); the rollback window ends with it. ``severity`` and
    ``generate_alert`` are the indicator's alerting. ``rbac_group_names``
    limits the indicator to these device groups (empty: every device).
    """

    expiration_days: int = Field(
        default=30, ge=1, le=365, title="Expiry (days)",
        description="Days until the indicator expires (1-365); a rollback is possible until then.",
    )
    severity: Literal["Informational", "Low", "Medium", "High"] = Field(
        default="High", title="Alert severity", description="Severity of the alerts the indicator raises.",
    )
    generate_alert: bool = Field(
        default=True, title="Generate an alert", description="Raise a Defender alert when the indicator matches.",
    )
    rbac_group_names: List[str] = Field(
        default_factory=list, max_length=50, title="Device groups",
        description="Limit the indicator to these Defender device groups, one per line (empty: every device).",
    )

    @field_validator("rbac_group_names")
    @classmethod
    def _groups(cls, groups: List[str]) -> List[str]:
        cleaned: List[str] = []
        for group in groups:
            name = group.strip()
            if not name or len(name) > MAX_GROUP_NAME_CHARS or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
                raise ValueError(f"device group names must be 1-{MAX_GROUP_NAME_CHARS} printable characters")
            if name not in cleaned:
                cleaned.append(name)
        return cleaned


@dataclass(frozen=True)
class Indicator:
    """The indicator fields the capabilities use (``description`` is only matched, never shown)."""

    id: str
    value: str
    type: str
    action: str
    description: str
    expiration: Optional[datetime]

    def expired(self, at: datetime) -> bool:
        return self.expiration is not None and self.expiration <= at

    def out(self, marker: str = "") -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "expiration_time": self.expiration.isoformat() if self.expiration is not None else None,
            "ours": bool(marker) and marker in self.description,
        }


def parse_indicator(item: Any) -> Optional[Indicator]:
    """An :class:`Indicator` from a Defender entity (``None`` without a usable id)."""
    if not isinstance(item, Mapping):
        return None
    try:
        indicator_id = ms_id(item.get("id"), "indicator id")
    except MicrosoftApiError:
        return None
    return Indicator(
        id=indicator_id,
        value=text(item.get("indicatorValue"), 2_048),
        type=text(item.get("indicatorType"), 32),
        action=text(item.get("action"), 32),
        description=text(item.get("description"), 1_000),
        expiration=parse_time(item.get("expirationTime")),
    )


Validator = Callable[[str], str]
NETWORK_TYPES: Mapping[str, Tuple[str, Validator]] = {
    "block_ip": ("IpAddress", odata.public_ip),
    "block_domain": ("DomainName", odata.domain),
    "block_url": ("Url", odata.http_url),
}
NETWORK_INVERSES: Mapping[str, str] = {"unblock_ip": "block_ip", "unblock_domain": "block_domain",
                                       "unblock_url": "block_url"}


class IndicatorHandler:
    """Handler of ``defender.indicators`` (network); :class:`FileIndicatorHandler` covers files."""

    block_action = "Block"
    enforcement = "configured; takes effect in up to 48 h"
    unblock_note = ""
    hints = Hints(
        permission="grant the WindowsDefenderATP application permission Ti.ReadWrite.All with admin consent "
                   "(a token for the wrong audience also answers 403)",
        feature="turn on 'Custom network indicators' in Settings > Endpoints > General > Advanced features",
    )

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx
        options = ctx.options
        self.options = options if isinstance(options, DefenderIndicatorOptions) else DefenderIndicatorOptions()

    # -------------------------------------------------------------- targets

    def forward_type(self, action_type: str) -> Optional[str]:
        """The blocking type of ``action_type`` (itself for a block, the original's type for an unblock)."""
        if action_type in NETWORK_TYPES:
            return action_type
        return NETWORK_INVERSES.get(action_type)

    def indicator_of(self, action_type: str, target: str) -> Tuple[str, str]:
        """``(indicatorType, value)`` of a target, validated for its kind."""
        forward = self.forward_type(action_type)
        if forward is None:
            raise Refused("capability_not_implemented", f"{action_type} is not an indicator action")
        indicator_type, validate = NETWORK_TYPES[forward]
        return indicator_type, validate(target)

    # --------------------------------------------------------------- lookup

    async def lookup(self, value: str, indicator_type: str) -> List[Indicator]:
        """The active indicators for this value and type (GET; a 404 answer counts as none)."""
        filter_text = f"{odata.odata_eq('indicatorValue', value)} and {odata.odata_eq('indicatorType', indicator_type)}"
        response = await self.ctx.api("defender").request(
            "GET", INDICATORS_PATH, params={"$filter": filter_text}, not_found_ok=True, deadline=self.ctx.deadline
        )
        found = [parse_indicator(item) for item in values(response, "the indicator list")]
        return [i for i in found if i is not None]

    # -------------------------------------------------------------- rehearse

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        would: Dict[str, Any]
        if self._is_unblock(action):
            indicator_type, value = self._rollback_target(action)
            would = {"method": "DELETE", "path_template": "/api/indicators/{id}", "body_keys": []}
            summary = f"would delete the {indicator_type} indicator of {value[:80]}"
        else:
            indicator_type, value = self.indicator_of(action.action_type, action.target)
            would = {"method": "POST", "path_template": INDICATORS_PATH, "body_keys": self._body_keys()}
            summary = f"would {self.block_action} {indicator_type} {value[:80]}"
        found = await self.lookup(value, indicator_type)
        return {
            "would_execute": would,
            "indicator": {"type": indicator_type, "value": value[:200],
                          "existing": [i.out(self.ctx.marker) for i in found[:10]]},
            "summary": summary,
        }

    def _body_keys(self) -> List[str]:
        keys = ["indicatorValue", "indicatorType", "action", "title", "description", "expirationTime", "severity",
                "generateAlert"]
        return keys + (["rbacGroupNames"] if self.options.rbac_group_names else [])

    # --------------------------------------------------------------- execute

    def _is_unblock(self, action: ResponseAction) -> bool:
        return action.action_type.startswith("unblock_")

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        work = self._unblock(action) if self._is_unblock(action) else self._block(action)
        return await settle(work, self.hints)

    async def _block(self, action: ResponseAction) -> ConnectorResult:
        ctx = self.ctx
        indicator_type, value = self.indicator_of(action.action_type, action.target)
        found = await self.lookup(value, indicator_type)
        conflict = next((i for i in found if i.action in CONFLICTING_ACTIONS), None)
        if conflict is not None:
            raise Refused(
                "conflicting_indicator",
                f"an existing {conflict.action} indicator ({conflict.id}) for {value[:80]} takes precedence over "
                "a block",
                hint="review the existing indicator in Microsoft Defender (Settings > Endpoints > Indicators)",
                indicator_id=conflict.id, existing_action=conflict.action,
            )
        base_ref: Dict[str, Any] = {"indicator_value": value, "indicator_type": indicator_type}
        mine = next((i for i in found if i.action in BLOCK_ACTIONS and ctx.marker in i.description), None)
        if mine is None:
            other = next((i for i in found if i.action in BLOCK_ACTIONS), None)
            if other is not None:
                return ConnectorResult(
                    "succeeded",
                    {"summary": f"{indicator_type} {value[:80]} is already blocked by indicator {other.id}; "
                                "nothing changed",
                     "changed": False, "already": True, "indicator": other.out()},
                    external_ref={**base_ref, "indicator_id": other.id, "created": False, "reversible": False},
                    verify=VerifyPlan("verified", detail={"enforcement": self.enforcement, "indicator_id": other.id,
                                                          "action": other.action}),
                )
            await ctx.checkpoint({**base_ref, "requested": True})
            posted = await self._post(action, indicator_type, value)
            await ctx.checkpoint({"indicator_id": posted.id})
            existed = posted.id in {i.id for i in found}
            indicator, created = posted, not existed
        else:
            indicator, created = mine, True
        ref: Dict[str, Any] = {**base_ref, "indicator_id": indicator.id, "created": created, "reversible": created}
        if created and indicator.expiration is not None:
            ref["rollback_until"] = iso_z(indicator.expiration)
        check = next((i for i in await self.lookup(value, indicator_type) if i.id == indicator.id), None)
        if check is None or check.action not in BLOCK_ACTIONS or check.expired(now()):
            return failure(
                "not_verified", f"indicator {indicator.id} for {value[:80]} is not listed as an active block",
                retryable=True, external_ref=ref, indicator_id=indicator.id,
            )
        verb = "adopted the indicator already created for this action" if mine is not None else (
            "created" if created else "updated an existing indicator in place")
        detail: Dict[str, Any] = {
            "summary": f"{verb}: {check.action} {indicator_type} {value[:80]} until "
                       f"{iso_z(check.expiration) if check.expiration else 'no expiry'}",
            "changed": True,
            "adopted": mine is not None,
            "indicator": check.out(),
        }
        if not created:
            detail["note"] = "the indicator existed before; a rollback will not delete it"
        return ConnectorResult(
            "succeeded", detail, external_ref=ref,
            verify=VerifyPlan("verified", detail={"enforcement": self.enforcement, "indicator_id": check.id,
                                                  "action": check.action}),
        )

    async def _post(self, action: ResponseAction, indicator_type: str, value: str) -> Indicator:
        ctx = self.ctx
        expiration = now() + timedelta(days=self.options.expiration_days)
        body: Dict[str, Any] = {
            "indicatorValue": value,
            "indicatorType": indicator_type,
            "action": self.block_action,
            "title": f"LG-SOTF {action.action_type} {value[:TITLE_TARGET_CHARS]}",
            "description": f"{ctx.marker}; alert {action.alert_id}"[:1_000],
            "expirationTime": iso_z(expiration),
            "severity": self.options.severity,
            "generateAlert": self.options.generate_alert,
        }
        if self.options.rbac_group_names:
            body["rbacGroupNames"] = list(self.options.rbac_group_names)
        response = await ctx.api("defender").request("POST", INDICATORS_PATH, json=body, ok=(200, 201),
                                                     deadline=ctx.deadline)
        posted = parse_indicator(response.body)
        if posted is None:
            # Submitted, but no id came back: a re-run finds the indicator by its marker.
            raise MicrosoftApiError("server", "Defender accepted the indicator without returning its id",
                                    code="invalid_response", status=response.status,
                                    request_id=response.request_id, retryable=True, ambiguous=True)
        if posted.expiration is None:
            posted = Indicator(posted.id, posted.value, posted.type, posted.action, posted.description, expiration)
        return posted

    # ---------------------------------------------------------------- unblock

    def _rollback_target(self, action: ResponseAction) -> Tuple[str, str]:
        original = self.ctx.original
        ref = original.external_ref if original is not None and isinstance(original.external_ref, dict) else {}
        indicator_type, value = ref.get("indicator_type"), ref.get("indicator_value")
        if isinstance(indicator_type, str) and isinstance(value, str) and indicator_type and value:
            return indicator_type, value
        return self.indicator_of(action.action_type, action.target)

    async def _unblock(self, action: ResponseAction) -> ConnectorResult:
        ctx = self.ctx
        original = ctx.original
        ref = original.external_ref if original is not None and isinstance(original.external_ref, dict) else {}
        if original is None or ref.get("created") is not True or not ref.get("indicator_id"):
            raise Refused("rollback_not_needed",
                          "LG-SOTF did not create this indicator (the value was already blocked); nothing to delete")
        indicator_id = ms_id(ref["indicator_id"], "indicator id")
        indicator_type, value = self._rollback_target(action)
        base_ref: Dict[str, Any] = {"indicator_id": indicator_id, "indicator_value": value,
                                    "indicator_type": indicator_type}
        note = {"note": self.unblock_note} if self.unblock_note else {}
        current = next((i for i in await self.lookup(value, indicator_type) if i.id == indicator_id), None)
        if current is None:
            return ConnectorResult(
                "succeeded",
                {"summary": f"indicator {indicator_id} for {value[:80]} no longer exists; nothing changed",
                 "changed": False, "already": True, **note},
                external_ref={**base_ref, "deleted": False},
                verify=VerifyPlan("verified", detail={"indicator_id": indicator_id, "absent": True}),
            )
        if action_marker(original.id) not in current.description:
            raise Refused(
                "conflicting_indicator",
                f"indicator {indicator_id} was changed by someone else after LG-SOTF created it; not deleted",
                hint="review the indicator in Microsoft Defender (Settings > Endpoints > Indicators)",
                indicator_id=indicator_id,
            )
        await ctx.checkpoint({**base_ref, "requested": True})
        await ctx.api("defender").request(
            "DELETE", f"{INDICATORS_PATH}/{odata.segment(indicator_id)}", ok=(200, 204), not_found_ok=True,
            deadline=ctx.deadline,
        )
        still = next((i for i in await self.lookup(value, indicator_type) if i.id == indicator_id), None)
        if still is not None:
            return failure("not_verified", f"indicator {indicator_id} is still listed after the delete",
                           retryable=True, external_ref={**base_ref, "deleted": True}, indicator_id=indicator_id)
        return ConnectorResult(
            "succeeded",
            {"summary": f"deleted indicator {indicator_id} ({indicator_type} {value[:80]})", "changed": True,
             **note},
            external_ref={**base_ref, "deleted": True},
            verify=VerifyPlan("verified", detail={"indicator_id": indicator_id, "absent": True}),
        )

    # ------------------------------------------------------------------ verify

    async def verify(self, action: ResponseAction) -> VerificationResult:
        ref = action.external_ref if isinstance(action.external_ref, dict) else {}
        indicator_id, indicator_type, value = ref.get("indicator_id"), ref.get("indicator_type"), ref.get(
            "indicator_value")
        if not (indicator_id and isinstance(indicator_type, str) and isinstance(value, str)):
            return VerificationResult("inconclusive", {"reason": "no_indicator"})
        current = next((i for i in await self.lookup(value, indicator_type) if i.id == str(indicator_id)), None)
        if self._is_unblock(action):
            if current is None:
                return VerificationResult("verified", {"indicator_id": str(indicator_id), "absent": True})
            return VerificationResult("failed", {"indicator_id": str(indicator_id), "reason": "indicator_present"})
        if current is None:
            return VerificationResult("failed", {"indicator_id": str(indicator_id), "reason": "indicator_missing"})
        if current.expired(now()):
            return VerificationResult("failed", {"indicator_id": current.id, "reason": "indicator_expired"})
        if current.action not in BLOCK_ACTIONS:
            return VerificationResult("failed", {"indicator_id": current.id, "reason": "indicator_not_blocking",
                                                 "action": current.action})
        return VerificationResult("verified", {"enforcement": self.enforcement, "indicator_id": current.id,
                                               "action": current.action})

    # ------------------------------------------------------------------- probe

    async def probe(self) -> List[ProbeCheck]:
        return [await probe_get(self.ctx, "list indicators", INDICATORS_PATH, params={"$top": "1"},
                                permission=PERMISSION)]


class FileIndicatorHandler(IndicatorHandler):
    """Handler of ``defender.file_indicators``: ``quarantine_file`` as a ``BlockAndRemediate`` file indicator."""

    block_action = "BlockAndRemediate"
    enforcement = "configured; file blocks typically apply in 15-30 min"
    unblock_note = "files already quarantined stay quarantined"
    hints = Hints(
        permission=IndicatorHandler.hints.permission,
        feature="turn on 'Allow or block file' in Settings > Endpoints > General > Advanced features",
    )

    def forward_type(self, action_type: str) -> Optional[str]:
        return "quarantine_file" if action_type in ("quarantine_file", "unblock_file") else None

    def indicator_of(self, action_type: str, target: str) -> Tuple[str, str]:
        if self.forward_type(action_type) is None:
            raise Refused("capability_not_implemented", f"{action_type} is not a file indicator action")
        return odata.file_hash(target)

    def _is_unblock(self, action: ResponseAction) -> bool:
        return action.action_type == "unblock_file"


__all__ = [
    "DefenderIndicatorOptions",
    "FileIndicatorHandler",
    "Indicator",
    "IndicatorHandler",
    "parse_indicator",
]
