"""Event payload summaries and the per-channel formatters: summary only, escaped, signed."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.channels import (
    email_message,
    facts,
    slack_escape,
    slack_message,
    teams_message,
    webhook_request,
)
from lg_sotf.integrations.events import (
    MAX_ENTITIES_PER_KIND,
    SCHEMA,
    alert_summary,
    capped_entities,
    make_test_event,
    severity_at_least,
    with_links,
)
from lg_sotf.services.connectors.webhook import (
    EVENT_HEADER,
    IDEMPOTENCY_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    verify_signature,
)
from tests.unit.integrations._support import alert_row, event, fake_secret

pytestmark = pytest.mark.unit

BASE = "https://soc.example.com"


def _action(status: str = "awaiting_approval", **extra: object) -> ResponseAction:
    now = datetime.now(UTC)
    values = {
        "id": uuid.uuid4(), "tenant_id": "tenant-a", "alert_id": "alert-1", "action_type": "isolate_host",
        "target": "ws-042", "params": {"approval_reason": "admin_approval_required", "alert": {"title": "x"}},
        "risk_level": "high", "idempotency_key": "k", "status": status, "blocked_reason": None,
        "requested_by": "agent:workflow", "approved_by": None, "approved_at": None, "executed_at": None,
        "connector": None, "result": {"error": "http_status", "secret": "nope"}, "rollback_of": None,
        "created_at": now, "updated_at": now,
    }
    values.update(extra)
    return ResponseAction.model_validate(values)


def test_summary_never_carries_raw_data_or_command_lines() -> None:
    payload = event()
    text = json.dumps(payload)
    assert payload["schema"] == SCHEMA and payload["event"] == "escalation.created"
    assert "must-never-appear" not in text and "raw" not in payload["alert"]
    assert "command_lines" not in payload["alert"]["entities"]
    assert len(payload["alert"]["entities"]["hosts"]) == MAX_ENTITIES_PER_KIND
    assert payload["alert"]["verdict"] == "malicious"  # from summary when no disposition yet


def test_entities_are_redacted_and_capped() -> None:
    token = "Bearer " + "Z" * 40
    capped = capped_entities({"users": [f"svc {token}"], "hosts": ["h" * 500], "unknown": ["x"]})
    assert "Z" * 40 not in json.dumps(capped)
    assert len(capped["hosts"][0]) <= 200 and "unknown" not in capped


def test_severity_threshold_treats_unknown_as_highest() -> None:
    assert severity_at_least("high", "medium") and not severity_at_least("low", "medium")
    assert severity_at_least("weird", "critical")


def test_alert_overrides_win_over_row_values() -> None:
    summary = alert_summary(alert_row(confidence=None), {"confidence": 55, "verdict": "suspicious"})
    assert summary["confidence"] == 55.0 and summary["verdict"] == "suspicious"


def test_slack_message_escapes_untrusted_text_and_links_to_the_alert() -> None:
    message = slack_message(event(), BASE)
    blocks = message["blocks"]
    assert blocks[0]["type"] == "header" and blocks[0]["text"]["type"] == "plain_text"
    assert "<!channel>" not in json.dumps(message["text"])  # fallback text is mrkdwn: escaped
    field_text = " ".join(f["text"] for f in blocks[1]["fields"])
    assert "*Severity*\nHIGH" in field_text and "*Confidence*\n72%" in field_text and "L2" in field_text
    buttons = [e for b in blocks if b["type"] == "actions" for e in b["elements"]]
    assert buttons[0]["url"] == f"{BASE}/alerts?alert=alert-1"
    assert slack_escape("<a&b>") == "&lt;a&amp;b&gt;"


def test_slack_approval_buttons_only_when_interactive() -> None:
    payload = event("action.awaiting_approval", with_escalation=False, action=_action())
    plain = slack_message(payload, BASE)
    interactive = slack_message(payload, BASE, interactive=True)
    ids = lambda m: [e.get("action_id") for b in m["blocks"] if b["type"] == "actions" for e in b["elements"]]  # noqa: E731
    assert ids(plain) == ["lgsotf_open"]
    assert ids(interactive) == ["lgsotf_open", "lgsotf_approve", "lgsotf_reject"]
    values = {e.get("value") for b in interactive["blocks"] if b["type"] == "actions" for e in b["elements"]}
    assert payload["action"]["id"] in values


def test_action_summary_has_no_params_or_connector_result() -> None:
    payload = event("action.failed", with_escalation=False, action=_action("failed"))
    text = json.dumps(payload)
    assert "nope" not in text and "params" not in payload["action"]
    assert payload["action"]["error"] == "http_status"
    assert ("Error", "http_status") in facts(payload)


def test_teams_card_is_an_adaptive_card_with_neutralised_markdown() -> None:
    payload = event(alert=alert_row(title="Click [here](https://evil.example) *now*"))
    message = teams_message(payload, BASE)
    card = message["attachments"][0]["content"]
    assert message["type"] == "message"
    assert message["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["type"] == "AdaptiveCard" and card["actions"][0]["url"].startswith(BASE)
    title = card["body"][1]["text"]
    assert "[here](" not in title and "\\[here\\]" in title


def test_email_has_text_and_escaped_html_parts() -> None:
    payload = event(alert=alert_row(title="<script>alert(1)</script> beacon"))
    msg = email_message(payload, BASE, sender="soc@example.com", recipients=["a@example.com", "b@example.com"])
    assert msg["To"] == "a@example.com, b@example.com" and msg["Subject"].startswith("[LG-SOTF] Escalation opened")
    text = msg.get_body(("plain",)).get_content()
    html = msg.get_body(("html",)).get_content()
    assert "Severity: HIGH" in text and f"{BASE}/alerts?alert=alert-1" in text
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_webhook_request_is_signed_with_the_response_connector_scheme() -> None:
    secret = fake_secret("hmac")
    payload = event()
    body, headers = webhook_request(payload, BASE, secret, delivery_id="d-1", clock=lambda: 1_790_000_000.0)
    sent = json.loads(body)
    assert sent["schema"] == SCHEMA and sent["links"]["alert"] == f"{BASE}/alerts?alert=alert-1"
    assert headers[EVENT_HEADER] == "escalation.created" and headers[IDEMPOTENCY_HEADER] == payload["id"]
    assert verify_signature(secret, headers[TIMESTAMP_HEADER], body, headers[SIGNATURE_HEADER], now=1_790_000_010.0)
    assert not verify_signature(secret, headers[TIMESTAMP_HEADER], body + b" ", headers[SIGNATURE_HEADER],
                                now=1_790_000_010.0)


def test_links_are_escaped_and_test_event_has_no_tenant_data() -> None:
    linked = with_links(event(alert=alert_row(id="a/b?c")), BASE + "/")
    assert linked["links"]["alert"] == f"{BASE}/alerts?alert=a%2Fb%3Fc"
    test = make_test_event("tenant-a", "My <Slack>")
    assert test["alert"]["entities"] == {} and test["event"] == "integration.test"
