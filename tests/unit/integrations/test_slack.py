"""Slack request signing (v0) and interaction parsing."""

from __future__ import annotations

import json
import uuid
from urllib.parse import urlencode

import pytest

from lg_sotf.integrations.slack import SlackRequestError, parse_interaction, slack_signature, verify_slack_request
from tests.unit.integrations._support import fake_secret

pytestmark = pytest.mark.unit

NOW = 1_790_000_000


def test_v0_signature_and_timestamp_window() -> None:
    secret = fake_secret("signing")
    body = b"payload=%7B%7D"
    signature = slack_signature(secret, str(NOW), body)
    assert signature.startswith("v0=") and len(signature) == 67
    assert verify_slack_request(secret, str(NOW), body, signature, now=NOW + 299)
    assert not verify_slack_request(secret, str(NOW), body, signature, now=NOW + 301)
    assert not verify_slack_request(secret, str(NOW), body + b"x", signature, now=NOW)
    assert not verify_slack_request(fake_secret("other"), str(NOW), body, signature, now=NOW)
    assert not verify_slack_request(secret, "not-a-time", body, signature, now=NOW)
    assert not verify_slack_request(secret, str(NOW), body, None, now=NOW)


def _body(payload: object) -> bytes:
    return urlencode({"payload": json.dumps(payload)}).encode()


def test_parse_button_click() -> None:
    action_id = uuid.uuid4()
    parsed = parse_interaction(_body({
        "type": "block_actions", "user": {"id": "U1"}, "team": {"id": "T1"}, "response_url": "https://hooks.slack.com/a",
        "actions": [{"action_id": "lgsotf_reject", "value": str(action_id)}],
    }))
    assert parsed.action_id == action_id and not parsed.approve and parsed.slack_user_id == "U1"


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "view_submission"},
        {"type": "block_actions", "user": {"id": "U1"}, "actions": []},
        {"type": "block_actions", "user": {"id": "U1"}, "actions": [{"action_id": "other", "value": "x"}]},
        {"type": "block_actions", "user": {"id": "U1"}, "actions": [{"action_id": "lgsotf_approve", "value": "nope"}]},
        {"type": "block_actions", "actions": [{"action_id": "lgsotf_approve", "value": str(uuid.uuid4())}]},
    ],
)
def test_parse_refuses_anything_else(payload: object) -> None:
    with pytest.raises(SlackRequestError):
        parse_interaction(_body(payload))
    with pytest.raises(SlackRequestError):
        parse_interaction(b"payload=%7Bnot-json")
