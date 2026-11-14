"""What the case read model is assembled from: plain values of the stored rows.

The service (:mod:`lg_sotf.services.case`) reads the rows and builds these;
the assembly (:func:`lg_sotf.domain.case.assemble`) is a pure function of
them. No I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional, Sequence

from lg_sotf.domain.case.model import CaseAction
from lg_sotf.domain.investigation.facts import AlertFacts, EventFacts

MAX_ALERTS = 200
MAX_TIMELINE = 300
MAX_ENTITIES = 40
MAX_TITLE_CHARS = 300
MAX_NOTES_CHARS = 4_000
MAX_VALUE_CHARS = 128


@dataclass(frozen=True)
class CaseEvent(EventFacts):
    """A timeline event with who recorded it (``actor_type`` is ``user`` for a person)."""

    actor_type: Optional[str] = None
    actor_id: Optional[str] = None


@dataclass(frozen=True)
class AuditFacts:
    """The alert's blind-audit sample (an alert is sampled at most once)."""

    label: Optional[str] = None
    agreement: Optional[bool] = None
    labelled_at: Optional[datetime] = None


@dataclass(frozen=True)
class MemberFacts:
    """One alert of the case. ``hidden``: it waits for its blind-audit label, so nobody sees the AI's side."""

    alert: AlertFacts
    title: str
    occurred_at: datetime
    disposition: Optional[str] = None
    entities: Mapping[str, Any] = field(default_factory=dict)
    events: Sequence[CaseEvent] = ()
    audit: Optional[AuditFacts] = None
    hidden: bool = False


@dataclass(frozen=True)
class CaseEscalation:
    """The escalation row: the case itself."""

    id: str
    tenant_id: str
    alert_id: str
    status: str
    version: int
    created_at: datetime
    summary: Mapping[str, Any] = field(default_factory=dict)
    sla_deadline: Optional[datetime] = None
    assigned_to: Optional[str] = None
    claimed_at: Optional[datetime] = None
    decision: Optional[str] = None
    decision_notes: Optional[str] = None
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None


@dataclass(frozen=True)
class CaseFacts:
    escalation: CaseEscalation
    now: datetime
    #: The case's alerts that were read: the primary alert first, then in the order they joined.
    members: Sequence[MemberFacts]
    #: How many alerts the case has (``members`` may be cut to :data:`MAX_ALERTS`).
    total_alerts: int
    #: E-mail address of each user the case names, by user id.
    emails: Mapping[str, str] = field(default_factory=dict)
    actions: Sequence[CaseAction] = ()
