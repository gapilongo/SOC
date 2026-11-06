"""``defender.stop_quarantine``: stop the processes of a file and quarantine it on the alert's devices (SHA-1).

``POST /api/machines/{id}/StopAndQuarantineFile`` takes a ``Sha1`` only, so a
SHA-256 or MD5 hash is ``unsupported_target`` (``defender.file_indicators``
blocks and remediates those tenant-wide; the two capabilities exclude each
other because both execute ``quarantine_file``). It cannot be undone through
the API.

The devices are the alert's host scope (``params.scope.hosts``), resolved
one by one with :func:`~.machines.resolve_machine`; no host is
``invalid_target`` and more than ``max_machines`` is ``too_many_targets``.
Each device is one step in ``external_ref.steps`` (``host``, ``machine_id``,
``status``, ``machine_action_id``, ``error``), checkpointed before its POST,
so a re-run resumes: a requested step is kept, and a pending or succeeded
``StopAndQuarantineFile`` of ours on the machine is adopted instead of
requested again.

Outcome, as for the mail purge: every device requested -> ``succeeded``
(verified when every machine action succeeds, ``failed`` when any ends
``Failed``/``TimeOut``/``Cancelled``); some devices failed -> ``failed``
with ``partial`` (a retry resumes the failed devices); all failed ->
``failed`` with the first device's error.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Mapping

from pydantic import Field

from lg_sotf.domain.connectors import ConnectorResult, VerificationResult, VerifyPlan
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import CapabilityOptions, HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.defender._common import (
    Hints,
    Refused,
    failure,
    ms_id,
    probe_get,
    refusal_for,
    settle,
)
from lg_sotf.integrations.microsoft.defender.machine_actions import (
    ACTIONS_PATH,
    FINAL_FAILED,
    get_action,
    list_actions,
    ours,
    parse_action,
)
from lg_sotf.integrations.microsoft.defender.machines import resolve_machine
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

STOP_AND_QUARANTINE = "StopAndQuarantineFile"
VERIFY_FIRST_S = 60.0
VERIFY_MAX_S = 273_600.0  # an offline device is retried for three days
REQUESTED = "requested"
FAILED = "failed"
SHA1_HINT = "enable defender.file_indicators for SHA-256/MD5"
# Per-device outcomes: the others (throttling, 403, server and network errors) stop the whole call.
STEP_ERROR_KINDS = frozenset({"bad_request", "not_found", "conflict"})
HINTS = Hints(
    permission="grant the WindowsDefenderATP application permissions Machine.StopAndQuarantine and "
               "Machine.ReadWrite.All with admin consent (a token for the wrong audience also answers 403)",
)


class DefenderStopQuarantineOptions(CapabilityOptions):
    """Options of ``defender.stop_quarantine``: at most ``max_machines`` devices per action."""

    max_machines: int = Field(
        default=10, ge=1, le=50, title="Maximum devices",
        description="At most this many devices per action (1-50); an alert naming more fails with too_many_targets.",
    )


def _target_error(exc: Exception) -> str:
    if isinstance(exc, Refused):
        return exc.error
    if isinstance(exc, odata.InvalidTarget):
        return exc.code
    return "invalid_target"


def scope_hosts(action: ResponseAction) -> List[str]:
    """The distinct host names of the action's scope (``params.scope.hosts``), in order."""
    params = action.params if isinstance(action.params, Mapping) else {}
    scope = params.get("scope")
    hosts = scope.get("hosts") if isinstance(scope, Mapping) else None
    if not isinstance(hosts, list):
        return []
    out: List[str] = []
    for host in hosts:
        if isinstance(host, str) and host.strip() and host.strip() not in out:
            out.append(host.strip())
    return out


class StopQuarantineHandler:
    """Handler of ``defender.stop_quarantine`` (see the module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx
        options = ctx.options
        self.options = options if isinstance(options, DefenderStopQuarantineOptions) else DefenderStopQuarantineOptions()

    @staticmethod
    def sha1(target: str) -> str:
        try:
            kind, value = odata.file_hash(target)
        except odata.InvalidTarget as exc:
            raise Refused(exc.code, str(exc), hint=SHA1_HINT if exc.code == "unsupported_target" else "") from None
        if kind != "FileSha1":
            raise Refused("unsupported_target", f"stop and quarantine takes SHA-1 hashes only, not {kind}",
                          hint=SHA1_HINT)
        return value

    def hosts(self, action: ResponseAction) -> List[str]:
        hosts = scope_hosts(action)
        if not hosts:
            raise Refused("invalid_target", "no hosts in scope",
                          hint="the alert names no device to stop and quarantine the file on")
        if len(hosts) > self.options.max_machines:
            raise Refused("too_many_targets",
                          f"{len(hosts)} hosts in scope, more than max_machines ({self.options.max_machines})",
                          hint="raise max_machines, or enable defender.file_indicators instead")
        return hosts

    # ---------------------------------------------------------------- rehearse

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        would = {"method": "POST", "path_template": "/api/machines/{id}/StopAndQuarantineFile",
                 "body_keys": ["Comment", "Sha1"]}
        try:
            sha1 = self.sha1(action.target)
            hosts = self.hosts(action)
        except Refused as refused:
            return {"would_execute": would, "machines": [], "problem": refused.error, "summary": refused.summary}
        machines: List[Dict[str, Any]] = []
        unresolved: List[Dict[str, Any]] = []
        for host in hosts:
            try:
                machine = await resolve_machine(self.ctx, host)
            except (Refused, odata.InvalidTarget) as exc:
                unresolved.append({"host": host[:253], "error": _target_error(exc)})
                continue
            machines.append(machine.out())
        return {
            "would_execute": would,
            "sha1": sha1,
            "machines": machines,
            "unresolved": unresolved,
            "summary": f"would stop and quarantine {sha1} on {len(machines)} of {len(hosts)} devices",
        }

    # ----------------------------------------------------------------- execute

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        return await settle(self._run(action), HINTS)

    async def _run(self, action: ResponseAction) -> ConnectorResult:
        ctx = self.ctx
        sha1 = self.sha1(action.target)
        hosts = self.hosts(action)
        ref = action.external_ref if isinstance(action.external_ref, dict) else {}
        previous = {str(s.get("host")): dict(s) for s in ref.get("steps") or [] if isinstance(s, Mapping)}
        steps: List[Dict[str, Any]] = [previous.get(host) or {"host": host} for host in hosts]
        seen: Dict[str, str] = {}
        for step in steps:
            if step.get("status") == REQUESTED and step.get("machine_action_id"):
                seen[str(step.get("machine_id"))] = str(step["host"])
                continue
            step.pop("error", None)
            try:
                machine = await resolve_machine(ctx, str(step["host"]))
            except (Refused, odata.InvalidTarget) as exc:
                step.update(status=FAILED, error=_target_error(exc))
                continue
            if machine.id in seen:
                step.update(machine_id=machine.id, status="same_device", error=None)
                continue
            seen[machine.id] = str(step["host"])
            step["machine_id"] = machine.id
            existing = [a for a in ours(await list_actions(ctx, machine.id, STOP_AND_QUARANTINE), ctx.marker)
                        if a.pending or a.succeeded]
            if existing:
                step.update(status=REQUESTED, machine_action_id=existing[-1].id)
                continue
            step["status"] = "requesting"
            await ctx.checkpoint({"sha1": sha1, "steps": steps})
            try:
                response = await ctx.api("defender").request(
                    "POST", f"/api/machines/{odata.segment(ms_id(machine.id, 'machine id'))}/{STOP_AND_QUARANTINE}",
                    json={"Comment": ctx.marker, "Sha1": sha1}, ok=(200, 201), deadline=ctx.deadline,
                )
            except MicrosoftApiError as exc:
                if exc.kind not in STEP_ERROR_KINDS or exc.ambiguous:
                    raise
                refusal = refusal_for(exc, HINTS)
                step.update(status=FAILED, error=refusal.error if refusal is not None else exc.ledger_error)
                await ctx.checkpoint({"steps": steps})
                continue
            requested = parse_action(response.body)
            if requested is None:
                raise MicrosoftApiError("server", "Defender accepted stop and quarantine without a machine action id",
                                        code="invalid_response", status=response.status,
                                        request_id=response.request_id, retryable=True, ambiguous=True)
            step.update(status=REQUESTED, machine_action_id=requested.id)
            await ctx.checkpoint({"steps": steps})
        return self._outcome(sha1, steps)

    @staticmethod
    def _outcome(sha1: str, steps: List[Dict[str, Any]]) -> ConnectorResult:
        requested = [s for s in steps if s.get("status") == REQUESTED]
        failed = [s for s in steps if s.get("status") == FAILED]
        ref: Dict[str, Any] = {"sha1": sha1, "steps": steps, "reversible": False}
        if requested and not failed:
            return ConnectorResult(
                "succeeded",
                {"summary": f"stop and quarantine of {sha1} requested on {len(requested)} device(s)",
                 "changed": True, "machines": len(requested)},
                external_ref=ref,
                verify=VerifyPlan("pending", first_check_s=VERIFY_FIRST_S, max_duration_s=VERIFY_MAX_S,
                                  detail={"machines": len(requested)}),
            )
        if requested:
            ref["partial"] = True
            return failure(
                "partial", f"stop and quarantine requested on {len(requested)} of {len(steps)} devices; "
                           f"{len(failed)} failed", external_ref=ref, changed=True, machines=len(requested),
                failed_machines=len(failed),
            )
        first = str(failed[0].get("error") or "not_found") if failed else "not_found"
        return failure(first, f"stop and quarantine failed on every device ({first})", external_ref=ref)

    # ------------------------------------------------------------------ verify

    async def verify(self, action: ResponseAction) -> VerificationResult:
        ref = action.external_ref if isinstance(action.external_ref, dict) else {}
        steps = [s for s in ref.get("steps") or [] if isinstance(s, Mapping) and s.get("status") == REQUESTED
                 and s.get("machine_action_id")]
        if not steps:
            return VerificationResult("inconclusive", {"reason": "no_machine_action"})
        machines: List[Dict[str, Any]] = []
        for step in steps:
            current = await get_action(self.ctx, ms_id(step["machine_action_id"], "machine action id"))
            machines.append({"machine_id": step.get("machine_id"), "status": current.status})
        failed = [m for m in machines if m["status"] in FINAL_FAILED]
        if failed:
            return VerificationResult("failed", {"reason": "machine_action_failed", "machines": machines})
        if all(m["status"] == "Succeeded" for m in machines):
            return VerificationResult("verified", {"machines": machines})
        return VerificationResult("pending", {"machines": machines})

    # ------------------------------------------------------------------- probe

    async def probe(self) -> List[ProbeCheck]:
        return [await probe_get(self.ctx, "list machine actions", ACTIONS_PATH, params={"$top": "1"},
                                permission="Machine.ReadWrite.All")]


__all__ = ["DefenderStopQuarantineOptions", "StopQuarantineHandler", "scope_hosts"]
