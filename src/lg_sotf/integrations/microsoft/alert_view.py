"""A read-only, bounded view of the alert a Microsoft action belongs to (``HandlerContext.alert()``).

Handlers get what they need to act safely (the email facts of a reported
message, the final verdict) without the raw event: the view is built from
the alert row's ``normalized`` form and ``summary`` only, and its values are
capped. Every value is still untrusted alert data: validate it with
:mod:`lg_sotf.integrations.microsoft.odata` before it reaches a request.

``disposition`` is the alert's final verdict, most authoritative first: the
analyst's decision (``true_positive`` -> ``malicious``, ``false_positive`` /
``benign_positive`` -> ``benign``), then the alert's disposition, then the
workflow's verdict. ``malicious``, ``suspicious`` and ``benign`` keep their
meaning; anything else is ``unknown``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Mapping, Optional

if TYPE_CHECKING:
    from lg_sotf.db.repos import Alert, Repositories

Disposition = Literal["malicious", "suspicious", "benign", "unknown"]
MAX_TEXT = 320
MAX_SUBJECT = 500
MAX_RECIPIENTS = 100
_VERDICTS: Mapping[str, Disposition] = {
    "true_positive": "malicious",
    "malicious": "malicious",
    "suspicious": "suspicious",
    "false_positive": "benign",
    "benign_positive": "benign",
    "benign": "benign",
}


@dataclass(frozen=True)
class AlertView:
    """What a handler may know about the action's alert (see the module docstring).

    ``email`` holds ``message_id``, ``from`` (the sender address),
    ``subject``, ``recipients`` (addresses), ``reporter`` and
    ``received_at`` (ISO 8601), or is empty for a non-email alert.
    ``received_at`` is the email's date, else the alert's creation time;
    the email's ``Date`` header is sender-controlled. ``ingested_at`` is
    when the alert reached LG-SOTF (for a reported email: when the report
    arrived), a bound the sender cannot move.
    """

    alert_id: str
    title: str
    severity: str
    disposition: Disposition
    email: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    received_at: Optional[datetime] = None
    ingested_at: Optional[datetime] = None


def _text(value: Any, limit: int = MAX_TEXT) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _email_date(value: Any) -> Optional[datetime]:
    text = _text(value, 64)
    if text is None:
        return None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def disposition_of(alert: Any) -> Disposition:
    """The final verdict of an alert row (see the module docstring)."""
    summary = _mapping(getattr(alert, "summary", None))
    for candidate in (
        summary.get("analyst_decision"),
        getattr(alert, "disposition", None),
        summary.get("verdict"),
        _mapping(summary.get("analysis")).get("verdict"),
    ):
        if isinstance(candidate, str) and candidate.lower() in _VERDICTS:
            return _VERDICTS[candidate.lower()]
    return "unknown"


def build_alert_view(alert: Alert) -> AlertView:
    """The view of an alert row (``raw`` is never read)."""
    section = _mapping(_mapping(alert.normalized).get("email"))
    email: Dict[str, Any] = {}
    received: Optional[datetime] = None
    if section:
        recipients: List[str] = [
            r.strip()[:MAX_TEXT] for r in section.get("recipients") or [] if isinstance(r, str) and r.strip()
        ][:MAX_RECIPIENTS]
        received = _email_date(section.get("date"))
        email = {
            "message_id": _text(section.get("message_id"), 998),
            "from": _text(_mapping(section.get("from")).get("address")),
            "subject": _text(section.get("subject"), MAX_SUBJECT) or "",
            "recipients": tuple(recipients),
            "reporter": _text(section.get("reporter")),
            "received_at": (received or alert.ingested_at).isoformat(),
        }
    return AlertView(
        alert_id=alert.id,
        title=alert.title[:MAX_SUBJECT],
        severity=alert.severity,
        disposition=disposition_of(alert),
        email=MappingProxyType(email),
        received_at=received or alert.ingested_at,
        ingested_at=alert.ingested_at,
    )


async def load_alert_view(repos: Repositories, tenant_id: str, alert_id: str) -> AlertView:
    """Read the alert (tenant scope) and build its view; ``NotFound`` propagates."""
    return build_alert_view(await repos.alerts.get(tenant_id, alert_id))


__all__ = ["AlertView", "Disposition", "build_alert_view", "disposition_of", "load_alert_view"]
