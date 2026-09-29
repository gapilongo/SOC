from __future__ import annotations

import json

import pytest

from lg_sotf.queue.streams import MalformedMessage, QueueStreams, encode_work, parse_message


def _fields(**overrides: object) -> dict:
    base = encode_work("tenant-a", "alert-1", "process", {})
    base.update({k: v for k, v in overrides.items()})
    return {k.encode(): (v.encode() if isinstance(v, str) else v) for k, v in base.items()}


def test_stream_names_and_priority_routing() -> None:
    s = QueueStreams("pfx")
    assert s.high == "pfx:q:alerts:high"
    assert s.normal == "pfx:q:alerts:normal"
    assert s.dlq == "pfx:q:alerts:dlq"
    assert s.work == (s.high, s.normal)
    assert s.for_severity("critical") == s.high
    assert s.for_severity("high") == s.high
    for severity in ("medium", "low", "info"):
        assert s.for_severity(severity) == s.normal
    assert s.label(s.high) == "high"


def test_encode_then_parse_roundtrip_from_bytes() -> None:
    payload = {"type": "approval", "approved_action_ids": ["a1"], "rejected_action_ids": [], "decided_by": "u"}
    fields = encode_work("tenant-a", "alert-1", "resume", payload)
    raw = {k.encode(): v.encode() for k, v in fields.items()}
    msg = parse_message("pfx:q:alerts:high", b"1-0", raw, 3)
    assert msg.entry_id == "1-0"
    assert msg.tenant_id == "tenant-a"
    assert msg.alert_id == "alert-1"
    assert msg.kind == "resume"
    assert msg.payload == payload
    assert msg.deliveries == 3
    assert msg.enqueued_at is not None and msg.enqueued_at.tzinfo is not None
    assert msg.raw_fields["payload"] == json.dumps(payload, separators=(",", ":"))


@pytest.mark.parametrize(
    ("tenant", "alert", "kind"),
    [("Bad Tenant", "a", "process"), ("tenant-a", "", "process"), ("tenant-a", "a", "delete")],
)
def test_encode_rejects_invalid_input(tenant: str, alert: str, kind: str) -> None:
    with pytest.raises(ValueError):
        encode_work(tenant, alert, kind, {})


def test_encode_rejects_oversized_payload() -> None:
    with pytest.raises(ValueError, match="payload exceeds"):
        encode_work("tenant-a", "a", "resume", {"type": "approval", "blob": "x" * 70_000})


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"tenant_id": "../etc"}, "tenant_id"),
        ({"alert_id": ""}, "alert_id"),
        ({"kind": "explode"}, "kind"),
        ({"payload": "{not json"}, "JSON"),
        ({"payload": "[1, 2]"}, "object"),
        ({"kind": "resume", "payload": "{}"}, "type"),
    ],
)
def test_parse_rejects_malformed_entries(overrides: dict, reason: str) -> None:
    with pytest.raises(MalformedMessage, match=reason):
        parse_message("s", "1-0", _fields(**overrides), 1)


def test_parse_tolerates_bad_timestamp_and_zero_deliveries() -> None:
    msg = parse_message("s", "1-0", _fields(enqueued_at="yesterday"), 0)
    assert msg.enqueued_at is None
    assert msg.deliveries == 1
