"""What the investigation read model is assembled from: plain values of the stored rows.

The service (:mod:`lg_sotf.services.investigation`) reads the rows and builds
these; the assembly itself (:func:`lg_sotf.domain.investigation.assemble`) is a
pure function of them. Standard library only, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Mapping, Optional, Sequence

from lg_sotf.domain.investigation.model import ProposedResponse

MAX_TEXT = 2_000
MAX_CLAIM_CHARS = 300
MAX_TARGET_CHARS = 128
MAX_ACTION_TARGET_CHARS = 512
MAX_NAME_CHARS = 200
MAX_LINE_CHARS = 200
MAX_EXCERPT_LINES = 12
MAX_CLAIMS = 20
MAX_OBSERVATIONS = 50
MAX_STEPS = 200
MAX_SIGNALS = 20
MAX_CODE_CHARS = 64


def bounded(value: Any, limit: int) -> str:
    """``value`` as text of at most ``limit`` characters (``...`` when cut). Data stays data: nothing is parsed."""
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."


def mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def strings(value: Any, *, limit: int, chars: int) -> List[str]:
    """The non-empty strings of a list, at most ``limit`` of them, each cut to ``chars``."""
    if not isinstance(value, (list, tuple)):
        return []
    return [bounded(v, chars) for v in value if isinstance(v, str) and v.strip()][:limit]


@dataclass(frozen=True)
class AlertFacts:
    """The alert row. ``view`` is the workflow's view of it (normalized fields, ``mitre``, ``flags``,
    ``entities``, the ``reopened`` marker), which the closure policy reads."""

    id: str
    tenant_id: str
    status: str
    severity: str
    summary: Mapping[str, Any]
    view: Mapping[str, Any]
    ingested_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None


@dataclass(frozen=True)
class EscalationFacts:
    """The alert's newest escalation: its own, or the one of the group it is attached to (``alert_id`` differs)."""

    id: str
    alert_id: str
    status: str
    summary: Mapping[str, Any]
    decision: Optional[str] = None


@dataclass(frozen=True)
class EventFacts:
    """One timeline event (``alert_events``)."""

    ts: datetime
    event_type: str
    node: Optional[str] = None
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TraceRef:
    """A tool step of the trace store (``investigation_steps``): hashes and time, never the input."""

    tool: str
    input_hash: str
    started_at: datetime
    outcome: str
    output_hash: Optional[str] = None
    error_type: Optional[str] = None


@dataclass(frozen=True)
class Lookup:
    """One lookup the analysis recorded in ``alerts.summary.analysis`` (``tools`` or ``history``).

    ``results`` is one provider result per entry (``provider``, ``status``, ``verdict``, ``data``, ``cached``).
    ``output`` is what the trace store hashed for the call, so the service can find its step.
    """

    tool: str
    kind: str
    target: str
    results: Sequence[Mapping[str, Any]]
    output: Any
    checked_at: Optional[str] = None
    trace: Optional[TraceRef] = None


@dataclass(frozen=True)
class TrackCounts:
    """People's verdicts on one outcome category of the tenant over ``window_days``: how many, and how many
    confirmed the category (a ``true_positive`` decision, or a blind-audit label that agrees with the AI)."""

    total: int
    confirmed: int
    window_days: int
    min_samples: int


@dataclass(frozen=True)
class InvestigationFacts:
    alert: AlertFacts
    now: datetime
    escalation: Optional[EscalationFacts] = None
    events: Sequence[EventFacts] = ()
    lookups: Sequence[Lookup] = ()
    #: Tool calls that raised: the trace store has the step, the summary has no result.
    failed_tools: Sequence[TraceRef] = ()
    #: The tenant's model-led closure tier when the alert was decided (``off`` when unknown).
    tier: str = "off"
    response: ProposedResponse = ProposedResponse(source="none")
    track: Optional[TrackCounts] = None
    #: The alert waits for its blind-audit label: nobody sees the AI's side.
    hidden: bool = False
