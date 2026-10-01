"""Finding the Defender for Endpoint machine an action targets (``resolve_machine``).

The target is an untrusted host name from the alert. It is validated and
lower-cased with :func:`~lg_sotf.integrations.microsoft.odata.hostname`
(an IP address is ``unsupported_target``), then looked up:

1. ``GET /api/machines?$filter=computerDnsName eq '<host>'``; Defender
   answers 404 when it has no recent machines, which counts as empty.
2. Nothing found: ``GET /api/machines?$filter=startswith(computerDnsName,'<first label>')``,
   keeping the machines whose first DNS label equals the target's first
   label (case-insensitively). ``computerDnsName`` is a fully qualified name
   on some machines and a bare name on others; when both the target and a
   machine carry a domain, the domains must match too (``ws-042.corp`` is
   not ``ws-042.lab``).
3. Exactly one candidate: that machine. Several: the single one whose
   ``healthStatus`` is ``Active``. Otherwise the action fails with
   ``ambiguous_target`` (never a guess), or ``not_found`` when there is none.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import HandlerContext
from lg_sotf.integrations.microsoft.defender._common import Refused, ms_id, parse_time, text, values
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

MACHINES_PATH = "/api/machines"
FALLBACK_TOP = "100"
ACTIVE = "Active"


@dataclass(frozen=True)
class Machine:
    """The Defender machine fields the capabilities use."""

    id: str
    computer_dns_name: str
    health_status: str
    last_seen: Optional[datetime]
    os_platform: str

    def out(self) -> Dict[str, Any]:
        """The machine as stored in results and rehearsals."""
        return {"id": self.id, "computer_dns_name": self.computer_dns_name, "health_status": self.health_status}


def machine_from(item: Mapping[str, Any]) -> Optional[Machine]:
    """A :class:`Machine` from a Defender machine entity (``None`` without a usable id or name)."""
    name = text(item.get("computerDnsName"), 253).lower()
    try:
        machine_id = ms_id(item.get("id"), "machine id")
    except MicrosoftApiError:  # an entity without a usable id is skipped, never trusted
        return None
    if not name:
        return None
    return Machine(
        id=machine_id,
        computer_dns_name=name,
        health_status=text(item.get("healthStatus"), 64),
        last_seen=parse_time(item.get("lastSeen")),
        os_platform=text(item.get("osPlatform"), 64),
    )


async def _machines(ctx: HandlerContext, params: Mapping[str, str]) -> List[Machine]:
    response = await ctx.api("defender").request(
        "GET", MACHINES_PATH, params=params, not_found_ok=True, deadline=ctx.deadline
    )
    found: Dict[str, Machine] = {}
    for item in values(response, "the machine list"):
        machine = machine_from(item)
        if machine is not None:
            found.setdefault(machine.id, machine)
    return list(found.values())


def _split(name: str) -> tuple[str, str]:
    label, _, rest = name.partition(".")
    return label, rest


def same_host(target: str, candidate: str) -> bool:
    """Whether a machine named ``candidate`` can be the host ``target`` (first labels equal, domains compatible)."""
    label, domain = _split(target.lower())
    other_label, other_domain = _split(candidate.lower())
    if label != other_label:
        return False
    return not domain or not other_domain or domain == other_domain


def pick(name: str, candidates: List[Machine]) -> Machine:
    """The single machine for ``name`` among ``candidates`` (see the module docstring)."""
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise Refused("not_found", f"no Defender machine is named {name}",
                      hint="check the host name and that the device is onboarded to Defender for Endpoint")
    active = [m for m in candidates if m.health_status == ACTIVE]
    if len(active) == 1:
        return active[0]
    raise Refused(
        "ambiguous_target", f"{len(candidates)} Defender machines match {name}; none was chosen",
        hint="use the machine's fully qualified name, or offboard the stale duplicates",
        count=len(candidates),
    )


async def resolve_machine(ctx: HandlerContext, host: str) -> Machine:
    """The Defender machine of the untrusted host name ``host`` (GETs only); raises :class:`Refused`."""
    name = odata.hostname(host)
    exact = [m for m in await _machines(ctx, {"$filter": odata.odata_eq("computerDnsName", name)})
             if m.computer_dns_name == name]
    if exact:
        return pick(name, exact)
    label, _ = _split(name)
    prefix = await _machines(
        ctx, {"$filter": f"startswith(computerDnsName,{odata.odata_string(label)})", "$top": FALLBACK_TOP}
    )
    return pick(name, [m for m in prefix if same_host(name, m.computer_dns_name)])


__all__ = ["Machine", "machine_from", "pick", "resolve_machine", "same_host"]
