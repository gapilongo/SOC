"""Stream names, message fields and message parsing for the work queue (contract section 7)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, Literal, Mapping, Optional, Tuple

from lg_sotf.db.tenancy import is_valid_tenant_id

MessageKind = Literal["process", "resume"]
MESSAGE_KINDS: Tuple[str, ...] = ("process", "resume")
HIGH_PRIORITY_SEVERITIES = frozenset({"critical", "high"})
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONSUMER_GROUP = "workers"
MAX_ALERT_ID_CHARS = 256
MAX_PAYLOAD_BYTES = 64 * 1024

FIELD_TENANT = "tenant_id"
FIELD_ALERT = "alert_id"
FIELD_KIND = "kind"
FIELD_PAYLOAD = "payload"
FIELD_ENQUEUED_AT = "enqueued_at"
WORK_FIELDS = (FIELD_TENANT, FIELD_ALERT, FIELD_KIND, FIELD_PAYLOAD, FIELD_ENQUEUED_AT)


class MalformedMessage(ValueError):
    """A stream entry that is not a valid work message; it is dead-lettered on sight."""


@dataclass(frozen=True)
class QueueStreams:
    """Redis keys of the work queue for one key prefix."""

    prefix: str

    @property
    def high(self) -> str:
        return f"{self.prefix}:q:alerts:high"

    @property
    def normal(self) -> str:
        return f"{self.prefix}:q:alerts:normal"

    @property
    def dlq(self) -> str:
        return f"{self.prefix}:q:alerts:dlq"

    @property
    def work(self) -> Tuple[str, str]:
        """Work streams in read priority order."""
        return (self.high, self.normal)

    def for_severity(self, severity: str) -> str:
        return self.high if severity in HIGH_PRIORITY_SEVERITIES else self.normal

    def label(self, stream: str) -> str:
        """Short metric label (``high``/``normal``/``dlq``) for a stream key."""
        return stream.rsplit(":", 1)[-1]


@dataclass(frozen=True)
class Message:
    """A work message delivered to this consumer."""

    stream: str
    entry_id: str
    tenant_id: str
    alert_id: str
    kind: MessageKind
    payload: Dict[str, Any]
    enqueued_at: Optional[datetime]
    deliveries: int
    raw_fields: Dict[str, str] = field(repr=False, default_factory=dict)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def decode_fields(fields: Mapping[Any, Any]) -> Dict[str, str]:
    return {_text(k): _text(v) for k, v in fields.items()}


def check_alert_id(alert_id: object) -> str:
    if not isinstance(alert_id, str) or not alert_id or len(alert_id) > MAX_ALERT_ID_CHARS:
        raise ValueError("alert_id must be a non-empty string of at most 256 characters")
    return alert_id


def encode_work(tenant_id: str, alert_id: str, kind: str, payload: Mapping[str, Any]) -> Dict[str, str]:
    """Field map for ``XADD``; raises ``ValueError`` for invalid input."""
    if not is_valid_tenant_id(tenant_id):
        raise ValueError(f"invalid tenant id: {tenant_id!r}")
    check_alert_id(alert_id)
    if kind not in MESSAGE_KINDS:
        raise ValueError(f"invalid message kind: {kind!r}")
    body = json.dumps(dict(payload), separators=(",", ":"), default=str)
    if len(body.encode()) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    return {
        FIELD_TENANT: tenant_id,
        FIELD_ALERT: alert_id,
        FIELD_KIND: kind,
        FIELD_PAYLOAD: body,
        FIELD_ENQUEUED_AT: utc_now_iso(),
    }


def parse_message(stream: str, entry_id: Any, fields: Mapping[Any, Any], deliveries: int) -> Message:
    """Build a :class:`Message` from a raw stream entry or raise :class:`MalformedMessage`."""
    data = decode_fields(fields)
    tenant_id = data.get(FIELD_TENANT, "")
    if not is_valid_tenant_id(tenant_id):
        raise MalformedMessage("invalid or missing tenant_id")
    alert_id = data.get(FIELD_ALERT, "")
    try:
        check_alert_id(alert_id)
    except ValueError as exc:
        raise MalformedMessage("invalid or missing alert_id") from exc
    kind = data.get(FIELD_KIND, "")
    if kind not in MESSAGE_KINDS:
        raise MalformedMessage("invalid or missing kind")
    try:
        payload = json.loads(data.get(FIELD_PAYLOAD) or "{}")
    except json.JSONDecodeError as exc:
        raise MalformedMessage("payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise MalformedMessage("payload must be a JSON object")
    if kind == "resume" and not isinstance(payload.get("type"), str):
        raise MalformedMessage("resume payload needs a 'type'")
    enqueued_at: Optional[datetime] = None
    raw_ts = data.get(FIELD_ENQUEUED_AT)
    if raw_ts:
        try:
            enqueued_at = datetime.fromisoformat(raw_ts)
        except ValueError:
            enqueued_at = None
    return Message(
        stream=stream,
        entry_id=_text(entry_id),
        tenant_id=tenant_id,
        alert_id=alert_id,
        kind=kind,  # type: ignore[arg-type]
        payload=payload,
        enqueued_at=enqueued_at,
        deliveries=max(int(deliveries), 1),
        raw_fields=data,
    )
