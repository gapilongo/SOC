"""What one investigation may spend, and the tenant's say in it (ADR 0014 section 2.3).

Four budgets, each checked before a tool call starts:

* ``steps``: tool calls, the ones a resumed run finds on its ledger included;
* ``wall_s``: seconds since the investigation started (a call still running when they are spent is cut
  and recorded as failed);
* ``tokens``: tokens of the model calls the executor makes itself (none while the plan is fixed);
* ``usd``: the price the tool registry declares for each call, plus the executor's own model calls.

The install sets the defaults and the most a tenant may ask for
(``settings.investigation.budget`` and ``.tenant_max``). A tenant overrides a budget in
``tenants.settings.investigation.budget``; :func:`tenant_limits` cuts every override to the install's
maximum, and a value that is not a positive number is ignored, so a tenant can lower its spend freely and
raise it only as far as the install allows. The wall-clock budget is also never more than the share of
the analysis node's time it is given.

A spent budget stops the investigation (``budget_<kind>``): it never fails the alert's run.

Standard library and pydantic only: no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, ValidationError

__all__ = [
    "BUDGET_KINDS",
    "SETTING",
    "Budget",
    "BudgetLimits",
    "TenantInvestigationSettings",
    "tenant_limits",
    "validate_investigation_settings",
]

SETTING = "investigation"
BUDGET_KINDS = ("steps", "wall_s", "tokens", "usd")


class _TenantBudget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    steps: Optional[StrictInt] = Field(default=None, ge=1, le=32)
    wall_s: Optional[StrictInt | StrictFloat] = Field(default=None, gt=0, le=300)
    tokens: Optional[StrictInt] = Field(default=None, ge=0, le=1_000_000)
    usd: Optional[StrictInt | StrictFloat] = Field(default=None, ge=0, le=10)


class TenantInvestigationSettings(BaseModel):
    """Schema of ``tenants.settings["investigation"]``: the tenant's budget overrides."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    budget: _TenantBudget = _TenantBudget()


def validate_investigation_settings(value: Any) -> Dict[str, Any]:
    """Normalised settings for the tenant settings API; raises ``ValueError`` listing the problems."""
    if not isinstance(value, Mapping):
        raise ValueError(f"{SETTING}: must be an object")
    try:
        return TenantInvestigationSettings.model_validate(dict(value)).model_dump(exclude_none=True)
    except ValidationError as exc:
        problems = [f"{SETTING}.{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"[:200] for e in exc.errors()[:5]]
        raise ValueError("; ".join(problems)) from exc


@dataclass(frozen=True)
class BudgetLimits:
    steps: int
    wall_s: float
    tokens: int
    usd: float

    def as_dict(self) -> Dict[str, float]:
        return {"steps": self.steps, "wall_s": self.wall_s, "tokens": self.tokens, "usd": self.usd}


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value < 0:
        return None
    try:
        return float(value)
    except OverflowError:  # an integer too large for a float asks for more than any maximum: it is cut to it
        return float("inf")


def tenant_limits(
    default: BudgetLimits, maximum: BudgetLimits, tenant_settings: Optional[Mapping[str, Any]], *,
    wall_cap_s: Optional[float] = None,
) -> BudgetLimits:
    """The limits of one tenant's investigations: its overrides where it set them, never above ``maximum``."""
    section = tenant_settings.get(SETTING) if isinstance(tenant_settings, Mapping) else None
    asked = section.get("budget") if isinstance(section, Mapping) else None
    asked = asked if isinstance(asked, Mapping) else {}
    chosen: Dict[str, float] = {}
    for kind in BUDGET_KINDS:
        own = _number(asked.get(kind))
        value = getattr(default, kind) if own is None else own
        chosen[kind] = min(value, getattr(maximum, kind))
    wall = chosen["wall_s"] if wall_cap_s is None else min(chosen["wall_s"], wall_cap_s)
    return BudgetLimits(steps=max(1, int(chosen["steps"])), wall_s=max(wall, 0.001), tokens=int(chosen["tokens"]),
                        usd=chosen["usd"])


@dataclass
class Budget:
    """The spend of one investigation against its limits. ``clock`` is monotonic seconds."""

    limits: BudgetLimits
    clock: Callable[[], float]
    steps: int = 0
    tokens: int = 0
    usd: float = 0.0
    started: float = field(init=False)

    def __post_init__(self) -> None:
        self.started = self.clock()

    @property
    def elapsed_s(self) -> float:
        return max(0.0, self.clock() - self.started)

    @property
    def remaining_s(self) -> float:
        return max(0.0, self.limits.wall_s - self.elapsed_s)

    def spent(self, *, next_usd: float = 0.0) -> Optional[str]:
        """Why another call may not start (``budget_steps``, ``budget_wall``, ``budget_tokens``,
        ``budget_usd``), or ``None`` when it may. ``next_usd`` is what that call would cost."""
        if self.steps >= self.limits.steps:
            return "budget_steps"
        if self.elapsed_s >= self.limits.wall_s:
            return "budget_wall"
        if self.tokens > self.limits.tokens:
            return "budget_tokens"
        if self.usd + next_usd > self.limits.usd + 1e-9:
            return "budget_usd"
        return None

    def charge(self, *, steps: int = 0, tokens: int = 0, usd: float = 0.0) -> None:
        self.steps += steps
        self.tokens += tokens
        self.usd += usd

    def used(self) -> Dict[str, Dict[str, float]]:
        """``{kind: {used, limit}}`` for the record: wall time in seconds, money in US dollars."""
        spent = {"steps": self.steps, "wall_s": round(self.elapsed_s, 3), "tokens": self.tokens, "usd": round(self.usd, 6)}
        return {kind: {"used": spent[kind], "limit": getattr(self.limits, kind)} for kind in BUDGET_KINDS}
