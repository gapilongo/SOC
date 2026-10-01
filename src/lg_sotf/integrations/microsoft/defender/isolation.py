"""``defender.isolation``: isolate a device (``isolate_host``) and release it on rollback (``release_host``).

isolate_host
    1. Resolve the machine (:func:`~.machines.resolve_machine`).
    2. Read before writing: an ``Isolate`` action of ours that is pending or
       succeeded is adopted (a re-run after a crash never isolates twice); a
       pending ``Isolate`` requested by someone else is adopted as
       ``already``; a device whose latest succeeded ``Isolate`` is newer
       than its latest succeeded ``Unisolate`` (and younger than the 7-day
       automatic lift) is already isolated: ``succeeded`` with
       ``already: true``, ``changed: false`` and nothing to roll back.
    3. Checkpoint ``{machine_id, requested}``, then
       ``POST /api/machines/{id}/isolate {"Comment": "<marker>: <alert title>", "IsolationType": ...}``
       (``IsolationType`` always sent: no default is documented). A 400
       because an isolation is in progress adopts the pending action.
    4. Checkpoint the machine action id. ``succeeded`` (reversible until the
       isolation has certainly been lifted: 7 days plus 3 days of offline
       retries), verified by polling the machine action for up to 76 hours.

release_host (a rollback; ``ctx.original`` is the isolation)
    * the original changed nothing (``already``) or its machine action ended
      without isolating: ``failed`` with ``rollback_not_needed``;
    * the isolation is still pending: ``POST /api/machineactions/{id}/cancel``,
      verified when the isolation action reads ``Cancelled``;
    * otherwise adopt a pending ``Unisolate`` of ours (or someone else's, as
      ``already``), treat a newer succeeded ``Unisolate`` or the 7-day lift
      as already released, else ``POST /api/machines/{id}/unisolate``
      (a 400 "already in progress" or "pending machine action" adopts the
      pending release), verified through the machine action.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional

from pydantic import Field

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import CapabilityOptions, HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.defender._common import (
    Hints,
    Refused,
    alert_title,
    comment,
    iso_z,
    ms_id,
    now,
    probe_get,
    settle,
)
from lg_sotf.integrations.microsoft.defender.machine_actions import (
    ACTIONS_PATH,
    MachineAction,
    get_action,
    latest,
    list_actions,
    ours,
    parse_action,
    post_action,
    verification_from,
)
from lg_sotf.integrations.microsoft.defender.machines import Machine, resolve_machine
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult, VerifyPlan

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

ISOLATE = "Isolate"
UNISOLATE = "Unisolate"
AUTO_LIFT = timedelta(days=7)
OFFLINE_RETRY = timedelta(days=3)
VERIFY_FIRST_S = 60.0
VERIFY_MAX_S = 273_600.0  # 76 h: three days of retries for an offline device, plus margin
PERMISSION = "Machine.Isolate"
READ_PERMISSION = "Machine.ReadWrite.All"
HINTS = Hints(
    permission=(
        "grant the WindowsDefenderATP application permissions Machine.Isolate and Machine.ReadWrite.All with "
        "admin consent (a token for the wrong audience also answers 403)"
    ),
)


class DefenderIsolationOptions(CapabilityOptions):
    """Options of ``defender.isolation``.

    ``isolation_type``: ``Full`` cuts the device off the network except for
    the Defender service; ``Selective`` is the documented choice on web-proxy
    (PAC/WPAD) networks, where a fully isolated device may not recover.
    """

    isolation_type: Literal["Full", "Selective"] = Field(
        default="Full",
        title="Isolation type",
        description="Full: the device can only reach the Defender service. Selective: the limited isolation "
                    "Microsoft recommends on web-proxy (PAC/WPAD) networks, where a fully isolated device might "
                    "not recover.",
    )


def _verify_plan(action: MachineAction, **detail: Any) -> VerifyPlan:
    if action.succeeded:
        return VerifyPlan("verified", detail={**action.out(), **detail})
    return VerifyPlan("pending", first_check_s=VERIFY_FIRST_S, max_duration_s=VERIFY_MAX_S,
                      detail={**action.out(), **detail})


def _lifted(action: MachineAction) -> bool:
    """Whether a succeeded isolation has certainly been lifted by Defender's 7-day automatic release."""
    return action.when is not None and action.when + AUTO_LIFT < now()


class IsolationHandler:
    """Handler of ``defender.isolation`` (see the module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx
        options = ctx.options
        self.options = options if isinstance(options, DefenderIsolationOptions) else DefenderIsolationOptions()

    # ----------------------------------------------------------------- rehearse

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        if action.action_type == "release_host":
            ref = self._original_ref()
            return {
                "would_execute": {"method": "POST", "path_template": "/api/machines/{id}/unisolate",
                                  "body_keys": ["Comment"]},
                "machine": {"id": ref.get("machine_id")},
                "summary": f"would release {action.target} from isolation",
            }
        would = {"method": "POST", "path_template": "/api/machines/{id}/isolate",
                 "body_keys": ["Comment", "IsolationType"]}
        try:
            machine = await resolve_machine(self.ctx, action.target)
        except Refused as refused:
            return {"would_execute": would, "machine": None, "problem": refused.error, "summary": refused.summary}
        return {
            "would_execute": would,
            "machine": machine.out(),
            "isolation_type": self.options.isolation_type,
            "summary": f"would isolate {machine.computer_dns_name} ({self.options.isolation_type})",
        }

    # ------------------------------------------------------------------ execute

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        if action.action_type == "release_host":
            return await settle(self._release(action), HINTS)
        return await settle(self._isolate(action), HINTS)

    async def _isolate(self, action: ResponseAction) -> ConnectorResult:
        ctx = self.ctx
        machine = await resolve_machine(ctx, action.target)
        isolations = await list_actions(ctx, machine.id, ISOLATE)
        mine = [a for a in ours(isolations, ctx.marker) if a.pending or a.succeeded]
        if mine:
            return self._isolated(machine, mine[-1], adopted=True)
        foreign = latest(isolations, lambda a: a.pending)
        if foreign is not None:
            return self._already(machine, foreign, "an isolation requested by someone else is in progress")
        last_isolate = latest(isolations, lambda a: a.succeeded)
        if last_isolate is not None and not _lifted(last_isolate):
            releases = await list_actions(ctx, machine.id, UNISOLATE)
            last_release = latest(releases, lambda a: a.succeeded)
            if last_release is None or _before(last_release, last_isolate):
                return self._already(machine, last_isolate, "the device is already isolated")
        await ctx.checkpoint({"machine_id": machine.id, "requested": True})
        title = await alert_title(ctx)
        requested, own = await post_action(
            ctx, machine.id, "isolate",
            {"Comment": comment(ctx, title), "IsolationType": self.options.isolation_type}, ISOLATE,
        )
        await ctx.checkpoint({"machine_action_id": requested.id})
        if not own:
            return self._already(machine, requested, "an isolation requested by someone else is in progress")
        return self._isolated(machine, requested, adopted=False)

    def _isolated(self, machine: Machine, requested: MachineAction, *, adopted: bool) -> ConnectorResult:
        verb = "adopted the isolation already requested for this action" if adopted else "isolation requested"
        until = (requested.created or now()) + AUTO_LIFT + OFFLINE_RETRY
        return ConnectorResult(
            "succeeded",
            {
                "summary": f"{verb} on {machine.computer_dns_name} ({self.options.isolation_type}, "
                           f"{requested.status or 'Pending'})",
                "changed": True,
                "adopted": adopted,
                "machine": machine.out(),
                **requested.out(),
            },
            external_ref={
                "machine_id": machine.id,
                "computer_dns_name": machine.computer_dns_name,
                "machine_action_id": requested.id,
                "isolation_type": self.options.isolation_type,
                "requested": True,
                "reversible": True,
                "rollback_until": iso_z(until),
            },
            verify=_verify_plan(requested),
        )

    @staticmethod
    def _already(machine: Machine, existing: MachineAction, why: str) -> ConnectorResult:
        return ConnectorResult(
            "succeeded",
            {
                "summary": f"{machine.computer_dns_name}: {why}; nothing changed",
                "changed": False,
                "already": True,
                "machine": machine.out(),
                **existing.out(),
            },
            external_ref={
                "machine_id": machine.id,
                "computer_dns_name": machine.computer_dns_name,
                "machine_action_id": existing.id,
                "already": True,
                "reversible": False,
            },
            verify=_verify_plan(existing, requested_by="another requestor"),
        )

    # ------------------------------------------------------------------ release

    def _original_ref(self) -> Dict[str, Any]:
        original = self.ctx.original
        ref = original.external_ref if original is not None else None
        return dict(ref) if isinstance(ref, dict) else {}

    async def _release(self, action: ResponseAction) -> ConnectorResult:
        ctx = self.ctx
        original = ctx.original
        ref = self._original_ref()
        result = original.result if original is not None and isinstance(original.result, dict) else {}
        if ref.get("already") is True or result.get("already") is True:
            raise Refused("rollback_not_needed", "the isolation changed nothing (the device was already isolated)")
        if ref.get("machine_id"):
            machine_id = ms_id(ref["machine_id"], "machine id")
            name = str(ref.get("computer_dns_name") or action.target)[:253]
        else:
            machine = await resolve_machine(ctx, action.target)
            machine_id, name = machine.id, machine.computer_dns_name
        isolation = await self._original_isolation(ref)
        if isolation is not None:
            if isolation.pending or (isolation.status == "Cancelled" and ctx.marker in isolation.cancellation_comment):
                return await self._cancel(machine_id, name, isolation)
            if isolation.final_failed:
                raise Refused("rollback_not_needed",
                              f"the isolation of {name} never took effect (machine action {isolation.status})")
            if isolation.succeeded and _lifted(isolation):
                return self._released_already(machine_id, name, None, "Defender lifted the isolation automatically "
                                              "after 7 days")
        return await self._unisolate(machine_id, name, isolation)

    async def _original_isolation(self, ref: Dict[str, Any]) -> Optional[MachineAction]:
        action_id = ref.get("machine_action_id")
        if not action_id:
            return None
        try:
            return await get_action(self.ctx, ms_id(action_id, "machine action id"))
        except MicrosoftApiError as exc:
            if exc.kind == "not_found":
                return None  # past Defender's retention: release by unisolating
            raise

    async def _cancel(self, machine_id: str, name: str, isolation: MachineAction) -> ConnectorResult:
        ctx = self.ctx
        cancelled = isolation
        if not (isolation.status == "Cancelled" and ctx.marker in isolation.cancellation_comment):
            await ctx.checkpoint({"machine_id": machine_id, "mode": "cancel", "machine_action_id": isolation.id,
                                  "requested": True})
            try:
                response = await ctx.api("defender").request(
                    "POST", f"{ACTIONS_PATH}/{odata.segment(isolation.id)}/cancel",
                    json={"Comment": comment(ctx, "rollback")}, ok=(200,), deadline=ctx.deadline,
                )
            except MicrosoftApiError as exc:
                if exc.kind not in ("bad_request", "not_found", "conflict"):
                    raise
                # The isolation may have reached a final state meanwhile: decide on what it is now.
                current = await get_action(ctx, isolation.id)
                if current.pending:
                    raise
                if current.succeeded:
                    return await self._unisolate(machine_id, name, current)
                raise Refused("rollback_not_needed",
                              f"the isolation of {name} never took effect (machine action {current.status})") from None
            cancelled = parse_action(response.body) or isolation
        return ConnectorResult(
            "succeeded",
            {"summary": f"cancelled the pending isolation of {name}", "changed": True, "mode": "cancel",
             **cancelled.out()},
            external_ref={"machine_id": machine_id, "computer_dns_name": name, "mode": "cancel",
                          "machine_action_id": isolation.id, "requested": True},
            verify=(
                VerifyPlan("verified", detail=cancelled.out()) if cancelled.status == "Cancelled"
                else VerifyPlan("pending", first_check_s=VERIFY_FIRST_S, max_duration_s=VERIFY_MAX_S,
                                detail=cancelled.out())
            ),
        )

    async def _unisolate(self, machine_id: str, name: str, isolation: Optional[MachineAction]) -> ConnectorResult:
        ctx = self.ctx
        releases = await list_actions(ctx, machine_id, UNISOLATE)
        mine = [a for a in ours(releases, ctx.marker) if a.pending or a.succeeded]
        if mine:
            return self._released(machine_id, name, mine[-1], adopted=True)
        if isolation is not None and isolation.succeeded:
            newer = latest(releases, lambda a: a.succeeded and not _before(a, isolation))
            if newer is not None:
                return self._released_already(machine_id, name, newer, "the device was already released")
        foreign = latest(releases, lambda a: a.pending)
        if foreign is not None:
            return self._released_already(machine_id, name, foreign, "a release requested by someone else is "
                                          "in progress")
        await ctx.checkpoint({"machine_id": machine_id, "mode": "unisolate", "requested": True})
        requested, own = await post_action(
            ctx, machine_id, "unisolate", {"Comment": comment(ctx, "rollback")}, UNISOLATE
        )
        await ctx.checkpoint({"machine_action_id": requested.id})
        if not own:
            return self._released_already(machine_id, name, requested, "a release requested by someone else is "
                                          "in progress")
        return self._released(machine_id, name, requested, adopted=False)

    @staticmethod
    def _released(machine_id: str, name: str, requested: MachineAction, *, adopted: bool) -> ConnectorResult:
        verb = "adopted the release already requested for this rollback" if adopted else "release requested"
        return ConnectorResult(
            "succeeded",
            {"summary": f"{verb} for {name} ({requested.status or 'Pending'})", "changed": True, "mode": "unisolate",
             "adopted": adopted, **requested.out()},
            external_ref={"machine_id": machine_id, "computer_dns_name": name, "mode": "unisolate",
                          "machine_action_id": requested.id, "requested": True},
            verify=_verify_plan(requested),
        )

    @staticmethod
    def _released_already(
        machine_id: str, name: str, existing: Optional[MachineAction], why: str
    ) -> ConnectorResult:
        detail: Dict[str, Any] = {"summary": f"{name}: {why}; nothing changed", "changed": False, "already": True,
                                  "mode": "unisolate"}
        ref: Dict[str, Any] = {"machine_id": machine_id, "computer_dns_name": name, "mode": "unisolate",
                               "already": True}
        if existing is None:
            return ConnectorResult("succeeded", detail, external_ref=ref)
        ref["machine_action_id"] = existing.id
        return ConnectorResult("succeeded", {**detail, **existing.out()}, external_ref=ref,
                               verify=_verify_plan(existing, requested_by="another requestor"))

    # ------------------------------------------------------------------- verify

    async def verify(self, action: ResponseAction) -> VerificationResult:
        ref = action.external_ref if isinstance(action.external_ref, dict) else {}
        action_id = ref.get("machine_action_id")
        if not action_id:
            return VerificationResult("inconclusive", {"reason": "no_machine_action"})
        current = await get_action(self.ctx, ms_id(action_id, "machine action id"))
        if action.action_type == "release_host" and ref.get("mode") == "cancel":
            return cancel_verification(current)
        return verification_from(current)

    # -------------------------------------------------------------------- probe

    async def probe(self) -> List[ProbeCheck]:
        return [
            await probe_get(self.ctx, "list machines", "/api/machines", params={"$top": "1"},
                            permission=READ_PERMISSION, not_found_ok=True),
            await probe_get(self.ctx, "list machine actions", ACTIONS_PATH, params={"$top": "1"},
                            permission=READ_PERMISSION),
        ]


def _before(first: MachineAction, second: MachineAction) -> bool:
    """Whether ``first`` completed before ``second`` (unknown times count as earlier)."""
    if first.when is None:
        return True
    if second.when is None:
        return False
    return first.when < second.when


def cancel_verification(isolation: MachineAction) -> VerificationResult:
    """A cancelled isolation proves the release; an isolation that completed anyway contradicts it."""
    detail = isolation.out()
    if isolation.pending:
        return VerificationResult("pending", detail)
    if isolation.succeeded:
        return VerificationResult("failed", {**detail, "reason": "isolation_completed_before_cancel"})
    return VerificationResult("verified", detail)


__all__ = ["DefenderIsolationOptions", "IsolationHandler", "cancel_verification"]
