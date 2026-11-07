"""The MCP client's error text: the API's error envelope is redacted before it is truncated (X1.4)."""

from __future__ import annotations

import json

from lg_sotf.mcp.client import MAX_ERROR_MESSAGE_CHARS, _error_from

# Built at runtime so no committed string looks like a credential.
FAKE_JWT = "eyJ" + "x" * 20 + "." + "eyJ" + "y" * 20 + "." + "z" * 24


def _body(message: str, **extra: str) -> bytes:
    return json.dumps({"error": {"message": message, **extra}}).encode()


def test_the_message_is_redacted() -> None:
    err = _error_from(400, _body("rejected bearer " + FAKE_JWT, code="invalid_request", request_id="req-1"))
    text = str(err)
    assert "eyJ" not in text
    assert "rejected bearer" in text and "(invalid_request)" in text and "[request id req-1]" in text


def test_a_token_at_the_cut_is_redacted_not_split() -> None:
    message = "m" * (MAX_ERROR_MESSAGE_CHARS - 20) + " bearer " + FAKE_JWT
    text = str(_error_from(422, _body(message)))
    assert "eyJ" not in text and "xxxxx" not in text


def test_whitespace_is_collapsed_and_the_message_bounded() -> None:
    text = str(_error_from(500, _body("a\n\tb  " + "c" * 5_000)))
    assert ": a b ccc" in text and text.endswith("...")
    assert len(text) <= len("the LG-SOTF API answered HTTP 500: ") + MAX_ERROR_MESSAGE_CHARS
