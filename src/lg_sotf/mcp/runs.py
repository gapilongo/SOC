"""Tester runs of the stdio MCP server (design Phase 0.5): run handles, per-alert outcomes and agreement.

A run is one ``ingest_test_alerts`` call. Its handle (``run_<32 hex>``),
the items, their expected labels and the outcomes observed so far live in
this server process's memory only: they are lost when ``lg-sotf mcp``
exits, and at most :data:`MAX_RUNS` are kept (the oldest is forgotten
first). Nothing here is sent to or stored by the LG-SOTF API.

Outcomes are read from the REST API only (alert rows, the ``decide`` step
of the timeline, the action ledger) and follow ``lg-sotf eval``'s rules
(:mod:`lg_sotf.eval.runner`), so the numbers mean the same thing:

* ``predicted`` is the closing disposition for a closed alert,
  ``malicious`` for an alert waiting on response approval, and the analysis
  verdict (``inconclusive`` without one) for an alert handed to an analyst;
* ``route`` is the ``decide`` step's route, or ``close`` for an alert closed
  before ``decide`` ran (suppression rule or cached verdict);
* ``escalated`` is set when the alert has an escalation or waits on an
  analyst.

The first terminal state observed for an item is kept: a later analyst
decision does not change the run's score, as in ``lg-sotf eval``, which
never supplies a decision. ``failed`` is the exception: the worker retries a
failed run (``failed -> processing -> ...``) until ``worker.max_deliveries``
is used up, so a failed item is read again, and whatever its alert reaches
next (another terminal state, or processing again) replaces it.

**Agreement** (design §6, ``get_test_run``): an item agrees when its
predicted disposition equals the expected one and, when the item has an
expected route, its route equals it. Escalation agreement is reported as a
separate metric. **Contamination** (design §13.1): a run is contaminated
when the tenant held alerts before the run, or when an item joined an
escalation created before the run's first alert was ingested.
"""

from __future__ import annotations

import re
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from lg_sotf.mcp.base import ToolError
from lg_sotf.mcp.shaping import mapping
from lg_sotf.models.vocabulary import DISPOSITIONS, ROUTES, SEVERITIES

MAX_RUNS = 50
MAX_TEST_ITEMS = 25
TERMINAL_STATUSES = ("closed", "waiting_human", "waiting_approval", "failed")
RETRIED_STATUSES = ("failed",)
"""Terminal for a wait, but not final: the worker retries the run, so the outcome is read again."""
_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
UNKNOWN_HANDLE = (
    "unknown or expired run_handle: run handles live in this MCP server's memory and are lost when it restarts "
    "(only the last {max_runs} runs are kept)"
)


def code(value: Any) -> Optional[str]:
    """``value`` when it is a short machine code (``policy:close``, ``grey_zone``), else ``None``."""
    return value if isinstance(value, str) and _CODE_RE.fullmatch(value) else None


def choice(value: Any, allowed: Iterable[str]) -> Optional[str]:
    return value if isinstance(value, str) and value in allowed else None


def number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def decide_step(events: Iterable[Any]) -> Optional[Mapping[str, Any]]:
    """The data of the latest ``decide`` step in a timeline page (``node.completed`` event)."""
    found: Optional[Mapping[str, Any]] = None
    for event in events:
        event = mapping(event)
        if event.get("event_type") == "node.completed" and event.get("node") == "decide":
            found = mapping(event.get("data"))
    return found


def models_of(summary: Mapping[str, Any]) -> List[str]:
    """``provider:model`` of every agent that called a model for the alert (``summary.llm_models``)."""
    out = set()
    for entry in mapping(summary.get("llm_models")).values():
        entry = mapping(entry)
        provider, model = entry.get("provider"), entry.get("model")
        if isinstance(model, str) and model:
            out.add(f"{provider}:{model}" if isinstance(provider, str) and provider else model)
    return sorted(out)[:8]


@dataclass
class Outcome:
    """What the platform did with one alert, from its REST representation."""

    alert_id: str
    status: str
    severity: Optional[str] = None
    disposition: Optional[str] = None
    confidence: Optional[float] = None
    route: Optional[str] = None
    decision_code: Optional[str] = None
    close_reason: Optional[str] = None
    verdict: Optional[str] = None
    escalation_id: Optional[str] = None
    escalated: bool = False
    approval_requested: bool = False
    predicted: Optional[str] = None
    models: List[str] = field(default_factory=list)
    pending_actions: Optional[int] = None
    ingested_at: Optional[str] = None

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def error(self) -> bool:
        """The run failed, or the alert is gone (``missing``: deleted or erased since it was ingested)."""
        return self.status in ("failed", "missing")

    def digest(self) -> Dict[str, Any]:
        """The ``wait_for_verdict`` entry (trusted fields only)."""
        return {
            "alert_id": self.alert_id,
            "status": self.status,
            "disposition": self.disposition,
            "predicted": self.predicted,
            "route": self.route,
            "decision_code": self.decision_code,
            "confidence": self.confidence,
            "escalated": self.escalated,
            "pending_actions": self.pending_actions,
            "model": self.models,
        }


def needs_timeline(alert: Mapping[str, Any]) -> bool:
    """Whether the route must be read from the timeline (it is in the summary only once the alert closed)."""
    summary = mapping(alert.get("summary"))
    return choice(mapping(summary.get("decision")).get("route"), ROUTES) is None and alert.get("status") != "closed"


def outcome_of(alert: Mapping[str, Any], decide: Optional[Mapping[str, Any]] = None) -> Outcome:
    """An :class:`Outcome` from ``GET /alerts/{id}`` and, optionally, the timeline's ``decide`` step."""
    summary = mapping(alert.get("summary"))
    decision = mapping(summary.get("decision")) or mapping(decide)
    status = str(alert.get("status") or "")
    route = choice(decision.get("route"), ROUTES)
    if route is None and status == "closed":
        route = "close"  # closed by a suppression rule or a cached verdict before ``decide``
    verdict = choice(mapping(summary.get("analysis")).get("verdict"), DISPOSITIONS)
    disposition = choice(alert.get("disposition"), DISPOSITIONS)
    escalation_id = summary.get("escalation_id") if isinstance(summary.get("escalation_id"), str) else None
    predicted: Optional[str] = None
    if status == "closed":
        predicted = disposition or "inconclusive"
    elif status == "waiting_approval":
        predicted = "malicious"
    elif status == "waiting_human":
        predicted = verdict or "inconclusive"
    return Outcome(
        alert_id=str(alert.get("id") or ""),
        status=status,
        severity=choice(alert.get("severity"), SEVERITIES),
        disposition=disposition,
        confidence=number(alert.get("confidence")),
        route=route,
        decision_code=code(decision.get("code")),
        close_reason=code(summary.get("close_reason")),
        verdict=verdict,
        escalation_id=escalation_id if escalation_id and code(escalation_id) else None,
        escalated=bool(escalation_id) or status == "waiting_human",
        approval_requested=status == "waiting_approval",
        predicted=predicted,
        models=models_of(summary),
        ingested_at=alert.get("ingested_at") if isinstance(alert.get("ingested_at"), str) else None,
    )


@dataclass(frozen=True)
class Expected:
    disposition: Optional[str] = None
    route: Optional[str] = None
    escalation: Optional[bool] = None

    def as_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in (("disposition", self.disposition), ("route", self.route),
                                  ("escalation", self.escalation)) if v is not None}


@dataclass
class RunItem:
    index: int
    source_alert_id: str
    status: str  # ingest result: inserted, duplicate or rejected
    item_id: Optional[str] = None
    split: Optional[str] = None
    expected: Expected = field(default_factory=Expected)
    alert_id: Optional[str] = None
    reason: Optional[str] = None
    title: Optional[str] = None
    ingested_at: Optional[str] = None
    outcome: Optional[Outcome] = None
    escalation_created_at: Optional[str] = None

    @property
    def settled(self) -> bool:
        """Whether the item's outcome is final: observed, and not a ``failed`` run the worker may still retry."""
        return self.outcome is not None and self.outcome.status not in RETRIED_STATUSES

    @property
    def ingest_failed(self) -> bool:
        """Whether the API did not insert an alert for this item (rejected or duplicate): it is never triaged."""
        return self.status != "inserted" or self.alert_id is None


@dataclass
class Run:
    handle: str
    tenant_id: str
    created_at: datetime
    prior_alerts: bool
    items: List[RunItem]
    source_id: Optional[str] = None

    def alert_ids(self) -> List[str]:
        seen: Dict[str, None] = {}
        for item in self.items:
            if item.alert_id:
                seen.setdefault(item.alert_id, None)
        return list(seen)

    def started_at(self) -> Optional[datetime]:
        """The server time the run's first alert was ingested (known once outcomes were read)."""
        times = [t for t in (parse_time(i.ingested_at) for i in self.items) if t is not None]
        return min(times) if times else None


class RunStore:
    """This session's runs, newest last; at most ``max_runs``."""

    def __init__(self, max_runs: int = MAX_RUNS) -> None:
        self.max_runs = max_runs
        self._runs: OrderedDict[str, Run] = OrderedDict()

    def __len__(self) -> int:
        return len(self._runs)

    @staticmethod
    def new_handle() -> str:
        return f"run_{uuid.uuid4().hex}"

    def add(self, run: Run) -> None:
        self._runs[run.handle] = run
        while len(self._runs) > self.max_runs:
            self._runs.popitem(last=False)

    def get(self, handle: str) -> Run:
        run = self._runs.get(handle)
        if run is None:
            raise ToolError(UNKNOWN_HANDLE.format(max_runs=self.max_runs))
        return run

    def items_for(self, alert_id: str) -> List[RunItem]:
        return [i for run in self._runs.values() for i in run.items if i.alert_id == alert_id]

    def record(self, outcome: Outcome, title: Optional[str] = None) -> None:
        """Note the alert's title and ingest time on its run items, and keep their first final outcome.

        A ``failed`` outcome is replaced by the next one read: the next terminal
        state, or none while the retried run is processing again.
        """
        for item in self.items_for(outcome.alert_id):
            item.title = item.title or title
            item.ingested_at = item.ingested_at or outcome.ingested_at
            if not item.settled:
                item.outcome = outcome if outcome.terminal else None


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 4) if denominator else None


def agreement(item: RunItem) -> Tuple[Optional[bool], List[str]]:
    """(agrees, disagreeing fields) for an evaluated item; ``None`` when it has no disposition or route label."""
    outcome, expected = item.outcome, item.expected
    assert outcome is not None
    fields: List[str] = []
    labelled = False
    if expected.disposition is not None:
        labelled = True
        if outcome.predicted != expected.disposition:
            fields.append("disposition")
    if expected.route is not None:
        labelled = True
        if outcome.route != expected.route:
            fields.append("route")
    if expected.escalation is not None and (outcome.escalated or outcome.approval_requested) != expected.escalation:
        fields.append("escalation")
    agrees = None if not labelled else not any(f in ("disposition", "route") for f in fields)
    return agrees, fields


def score(run: Run) -> Dict[str, Any]:
    """Client-side metrics of a run from the outcomes observed so far."""
    evaluated = [i for i in run.items if i.outcome is not None and not i.outcome.error]
    errors = [i for i in run.items if i.ingest_failed or (i.outcome is not None and i.outcome.error)]
    pending = [i for i in run.items if i.alert_id and i.outcome is None]
    disposition_labelled = [i for i in evaluated if i.expected.disposition is not None]
    route_labelled = [i for i in evaluated if i.expected.route is not None]
    escalation_labelled = [i for i in evaluated if i.expected.escalation is not None]
    agreements = [agreement(i)[0] for i in evaluated]
    agreement_labelled = [a for a in agreements if a is not None]
    confusion: Dict[str, Dict[str, int]] = {}
    for item in disposition_labelled:
        assert item.outcome is not None and item.expected.disposition is not None
        row = confusion.setdefault(item.expected.disposition, {})
        predicted = item.outcome.predicted or "inconclusive"
        row[predicted] = row.get(predicted, 0) + 1
    return {
        "items": len(run.items),
        "evaluated": len(evaluated),
        "pending": len(pending),
        "errors": len(errors),
        "accuracy": _ratio(
            sum(1 for i in disposition_labelled if i.outcome and i.outcome.predicted == i.expected.disposition),
            len(disposition_labelled),
        ),
        "disposition_labelled_items": len(disposition_labelled),
        "route_accuracy": _ratio(
            sum(1 for i in route_labelled if i.outcome and i.outcome.route == i.expected.route), len(route_labelled)
        ),
        "route_labelled_items": len(route_labelled),
        "escalation_accuracy": _ratio(
            sum(
                1
                for i in escalation_labelled
                if i.outcome and (i.outcome.escalated or i.outcome.approval_requested) == i.expected.escalation
            ),
            len(escalation_labelled),
        ),
        "escalation_labelled_items": len(escalation_labelled),
        "agreement_rate": _ratio(sum(1 for a in agreement_labelled if a), len(agreement_labelled)),
        "agreement_labelled_items": len(agreement_labelled),
        "mismatches": sum(1 for a in agreement_labelled if not a),
        "confusion_matrix": confusion,
    }


def coverage(run: Run) -> Dict[str, Any]:
    by_split: Dict[str, Dict[str, int]] = {}
    for item in run.items:
        entry = by_split.setdefault(item.split or "unspecified", {"items": 0, "evaluated": 0})
        entry["items"] += 1
        if item.outcome is not None and not item.outcome.error:
            entry["evaluated"] += 1
    return {"by_split": dict(sorted(by_split.items())), "by_source_type": {"canonical": len(run.items)}}


def contamination(run: Run) -> Dict[str, Any]:
    started = run.started_at()
    preexisting: List[str] = []
    for item in run.items:
        created = parse_time(item.escalation_created_at)
        escalation_id = item.outcome.escalation_id if item.outcome else None
        if started is not None and created is not None and created < started and escalation_id:
            if escalation_id not in preexisting:
                preexisting.append(escalation_id)
    return {
        "contaminated": run.prior_alerts or bool(preexisting),
        "prior_alerts": run.prior_alerts,
        "preexisting_escalations": preexisting,
        "started_at": started.isoformat() if started else None,
    }


def now_utc() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "DISPOSITIONS",
    "MAX_RUNS",
    "MAX_TEST_ITEMS",
    "RETRIED_STATUSES",
    "ROUTES",
    "TERMINAL_STATUSES",
    "Expected",
    "Outcome",
    "Run",
    "RunItem",
    "RunStore",
    "agreement",
    "contamination",
    "coverage",
    "decide_step",
    "needs_timeline",
    "outcome_of",
    "score",
]
