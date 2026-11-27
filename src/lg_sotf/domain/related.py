"""Which alerts relate to one another, and which related alert is a strong enough signal to act on (AI-E3.16).

Two questions, answered the same way in both directions of decision policy
v3: the forward check of a model-led close (:mod:`lg_sotf.domain.closure`)
and the backward safety net (:mod:`lg_sotf.core.retro_reopen`).

**Relation.** Two alerts relate when they share a host or a user, compared
by :func:`relation_keys` and never by the stored spelling: a host is its
lower-case short name (``WS-FIN-0142.corp.example.com.`` and ``ws-fin-0142``
are one host; an IP literal used as a host name is kept whole), a user is
the lower-case bare account name (``CORP\\jsmith``, ``jsmith@corp.example.com``
and ``JSmith`` are one user). What does not relate two alerts: a shared IP
address alone (a proxy, a resolver, a NAT address), and the accounts every
host has of its own (:data:`BUILT_IN_ACCOUNTS`): two alerts about ``SYSTEM``
relate only through a host they share.

**Grade** (:func:`hold_grade`). A threat only a model stands behind links;
a stronger signal acts. The stronger signal is one of:

* the alert is high or critical and a model judged it a threat (the deep
  tier's ``malicious``, the fast tier's ``likely_threat`` or
  ``confirmed_threat``; never ``suspicious``);
* a person confirmed it: an analyst's ``true_positive``, a blind-audit
  ``malicious`` label, a response to it that a person approved, or one that
  really ran (``succeeded``; AI-E3.15, #456: these confirmed backward only).

A response that waits for an approval is not one of them: a response a model
proposed and nobody has approved is still only the model's word (on dev,
three medium alerts that only waited for an approval cost 20 of 53 correct
closes). Such an alert is a threat only a model stands behind, and links.

Forward, a hold-grade related alert withholds a model-led close; backward,
an alert that reaches hold grade reopens the related alerts the models
closed. One function decides both, so the two never disagree.

:func:`classify` applies both to what the database holds about another
alert (:class:`RelatedFacts`) and gives its role for a close that is being
decided: ``hold``, ``in_progress``, ``model_only`` or none.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, FrozenSet, Iterable, List, Literal, Mapping, Optional

from lg_sotf.models.vocabulary import HIGH_SEVERITIES

__all__ = [
    "BUILT_IN_ACCOUNTS",
    "HOLD_WINDOW",
    "IN_PROGRESS_WINDOW",
    "LINK_WINDOW",
    "MAX_LISTED",
    "MODEL_THREATS",
    "RelatedFacts",
    "Role",
    "classify",
    "hold_grade",
    "host_key",
    "model_judged_threat",
    "related_digest",
    "relation_keys",
    "user_key",
]

#: Accounts every host has of its own: sharing one relates nothing.
BUILT_IN_ACCOUNTS: FrozenSet[str] = frozenset({"root", "system", "local service", "network service"})
#: Fast-tier assessments that mean a model judged the alert a threat. ``suspicious`` is absent on purpose (#352).
MODEL_THREATS: FrozenSet[str] = frozenset({"likely_threat", "confirmed_threat"})
#: A hold-grade alert holds for as long as it is open, up to this long after its ingestion.
HOLD_WINDOW = timedelta(days=7)
#: How long a threat only a model stands behind links a close forward, and how far back the safety net looks.
LINK_WINDOW = timedelta(hours=24)
#: A high or critical alert in ``processing`` holds only while it changed this recently: a stuck run stops holding.
IN_PROGRESS_WINDOW = timedelta(minutes=15)
#: Values read per entity kind, and the related alerts a digest names per role.
MAX_ENTITY_VALUES = 50
MAX_LISTED = 10

Role = Literal["hold", "in_progress", "model_only"]


def host_key(value: Any) -> Optional[str]:
    """The relation key of a host name: lower case, no trailing dot, the first label; an IP literal whole."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    if not name:
        return None
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        return name.split(".", 1)[0] or None


def user_key(value: Any) -> Optional[str]:
    """The relation key of a user: the lower-case bare account name, without a domain prefix (``CORP\\``) or a UPN
    suffix (``@corp.example.com``); ``None`` for an account every host has (:data:`BUILT_IN_ACCOUNTS`)."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rsplit("\\", 1)[-1].split("@", 1)[0].strip()
    return name if name and name not in BUILT_IN_ACCOUNTS else None


def _values(entities: Any, kind: str) -> List[Any]:
    values = entities.get(kind) if isinstance(entities, Mapping) else None
    return list(values[:MAX_ENTITY_VALUES]) if isinstance(values, list) else []


def relation_keys(entities: Any) -> FrozenSet[str]:
    """The keys an alert relates by, from its ``entities``: ``host:<short name>`` and ``user:<account>``."""
    hosts = {f"host:{key}" for key in map(host_key, _values(entities, "hosts")) if key}
    users = {f"user:{key}" for key in map(user_key, _values(entities, "users")) if key}
    return frozenset(hosts | users)


def model_judged_threat(threat_assessment: Any, verdict: Any) -> bool:
    """Whether a model judged the alert a threat: the deep verdict ``malicious`` or a fast-tier threat."""
    return verdict == "malicious" or threat_assessment in MODEL_THREATS


def hold_grade(*, severity: Any, threat_assessment: Any, verdict: Any, confirmed: bool) -> bool:
    """Whether an alert is a strong enough signal to hold a related model-led close (forward) and to reopen the
    related alerts the models closed (backward); see the module docs. A pending response approval plays no
    part."""
    return confirmed or (severity in HIGH_SEVERITIES and model_judged_threat(threat_assessment, verdict))


@dataclass(frozen=True)
class RelatedFacts:
    """What the database holds about another alert of the tenant when a close is decided."""

    id: str
    status: str
    severity: str
    entities: Mapping[str, Any]
    threat_assessment: Optional[str]
    verdict: Optional[str]
    #: A response was planned for it.
    planned: bool
    #: A person confirmed it: an analyst's true positive, a blind-audit malicious label, or a response to it that a
    #: person approved or that really ran.
    confirmed: bool
    ingested_at: datetime
    #: When the row last changed (the last progress of a run in ``processing``).
    changed_at: datetime


def classify(other: RelatedFacts, keys: FrozenSet[str], now: datetime) -> Optional[Role]:
    """The role of ``other`` for a model-led close of an alert with the relation ``keys``, decided at ``now``.

    ``hold``: hold grade, and either open and ingested within :data:`HOLD_WINDOW`, or closed with a person's
    confirmation (the reader only hands in closed alerts that were confirmed recently or whose case is open).
    ``in_progress``: high or critical, on a shared host, in ``processing`` and changed within
    :data:`IN_PROGRESS_WINDOW`. ``model_only``: open, ingested within :data:`LINK_WINDOW`, and a model judged it a
    threat or planned a response for it (also one that waits for the response's approval). ``None``: unrelated,
    ``failed`` (nothing holds on a failed run), or none of these.
    """
    shared = keys & relation_keys(other.entities)
    if not shared or other.status == "failed":
        return None
    if other.status == "closed":
        return "hold" if other.confirmed else None
    age = now - other.ingested_at
    grade = hold_grade(
        severity=other.severity, threat_assessment=other.threat_assessment, verdict=other.verdict,
        confirmed=other.confirmed,
    )
    if grade and age <= HOLD_WINDOW:
        return "hold"
    serious = other.severity in HIGH_SEVERITIES
    same_host = any(key.startswith("host:") for key in shared)
    if other.status == "processing" and serious and same_host and now - other.changed_at < IN_PROGRESS_WINDOW:
        return "in_progress"
    judged = model_judged_threat(other.threat_assessment, other.verdict)
    if (judged or other.planned or other.status == "waiting_approval") and age <= LINK_WINDOW:
        return "model_only"
    return None


def related_digest(entities: Any, others: Iterable[RelatedFacts], now: datetime) -> Dict[str, List[str]]:
    """The digest ``decide`` keeps (``related_open``): the ids of the related alerts by role, at most
    :data:`MAX_LISTED` each, in the order given (newest first)."""
    keys = relation_keys(entities)
    roles: Dict[str, List[str]] = {"hold": [], "in_progress": [], "model_only": []}
    for other in others if keys else ():
        role = classify(other, keys, now)
        if role is not None and len(roles[role]) < MAX_LISTED:
            roles[role].append(other.id)
    return {"threats": roles["hold"], "in_progress": roles["in_progress"], "model_only": roles["model_only"]}
