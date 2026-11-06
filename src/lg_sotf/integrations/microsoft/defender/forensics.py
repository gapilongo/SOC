"""``defender.forensics``: collect an investigation package on a device (``collect_forensics``).

1. Resolve the machine (:func:`~.machines.resolve_machine`).
2. Adopt a pending (or succeeded) ``CollectInvestigationPackage`` of ours: a
   re-run never collects twice.
3. Checkpoint, then ``POST /api/machines/{id}/collectInvestigationPackage {"Comment": "<marker>"}``
   (201). Defender answers 400 when a collection is already running: the
   running collection is adopted (someone else's counts as ``already``).
4. Verified by polling the machine action for up to 24 hours.

The package stays in Defender: LG-SOTF never calls ``getPackageUri`` and
never stores a download link. Collecting evidence cannot be undone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from lg_sotf.domain.connectors import ConnectorResult, VerificationResult, VerifyPlan
from lg_sotf.integrations.microsoft.capability import HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.defender._common import Hints, Refused, comment, ms_id, probe_get, settle
from lg_sotf.integrations.microsoft.defender.machine_actions import (
    ACTIONS_PATH,
    MachineAction,
    get_action,
    list_actions,
    ours,
    post_action,
    verification_from,
)
from lg_sotf.integrations.microsoft.defender.machines import Machine, resolve_machine

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

COLLECT = "CollectInvestigationPackage"
VERIFY_FIRST_S = 60.0
VERIFY_MAX_S = 86_400.0
HINTS = Hints(
    permission="grant the WindowsDefenderATP application permissions Machine.CollectForensics and "
               "Machine.ReadWrite.All with admin consent (a token for the wrong audience also answers 403)",
)


class ForensicsHandler:
    """Handler of ``defender.forensics`` (see the module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        would = {"method": "POST", "path_template": "/api/machines/{id}/collectInvestigationPackage",
                 "body_keys": ["Comment"]}
        try:
            machine = await resolve_machine(self.ctx, action.target)
        except Refused as refused:
            return {"would_execute": would, "machine": None, "problem": refused.error, "summary": refused.summary}
        return {"would_execute": would, "machine": machine.out(),
                "summary": f"would collect an investigation package on {machine.computer_dns_name}"}

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        return await settle(self._collect(action), HINTS)

    async def _collect(self, action: ResponseAction) -> ConnectorResult:
        ctx = self.ctx
        machine = await resolve_machine(ctx, action.target)
        mine = [a for a in ours(await list_actions(ctx, machine.id, COLLECT), ctx.marker) if a.pending or a.succeeded]
        if mine:
            return self._result(machine, mine[-1], own=True, adopted=True)
        await ctx.checkpoint({"machine_id": machine.id, "requested": True})
        requested, own = await post_action(ctx, machine.id, "collectInvestigationPackage", {"Comment": comment(ctx)},
                                           COLLECT)
        await ctx.checkpoint({"machine_action_id": requested.id})
        return self._result(machine, requested, own=own, adopted=False)

    @staticmethod
    def _result(machine: Machine, requested: MachineAction, *, own: bool, adopted: bool) -> ConnectorResult:
        if own:
            verb = "adopted the collection already requested for this action" if adopted else "collection requested"
            summary = f"investigation package {verb} on {machine.computer_dns_name} ({requested.status or 'Pending'})"
        else:
            summary = f"{machine.computer_dns_name}: a collection requested by someone else is running; adopted it"
        detail: Dict[str, Any] = {"summary": summary, "changed": own, "adopted": adopted, "machine": machine.out(),
                                  **requested.out()}
        if not own:
            detail["already"] = True
        plan = (
            VerifyPlan("verified", detail=requested.out()) if requested.succeeded
            else VerifyPlan("pending", first_check_s=VERIFY_FIRST_S, max_duration_s=VERIFY_MAX_S,
                            detail=requested.out())
        )
        return ConnectorResult(
            "succeeded", detail,
            external_ref={"machine_id": machine.id, "computer_dns_name": machine.computer_dns_name,
                          "machine_action_id": requested.id, "requested": True, "reversible": False},
            verify=plan,
        )

    async def verify(self, action: ResponseAction) -> VerificationResult:
        ref = action.external_ref if isinstance(action.external_ref, dict) else {}
        action_id = ref.get("machine_action_id")
        if not action_id:
            return VerificationResult("inconclusive", {"reason": "no_machine_action"})
        return verification_from(await get_action(self.ctx, ms_id(action_id, "machine action id")))

    async def probe(self) -> List[ProbeCheck]:
        return [await probe_get(self.ctx, "list machine actions", ACTIONS_PATH, params={"$top": "1"},
                                permission="Machine.ReadWrite.All")]


__all__ = ["ForensicsHandler"]
