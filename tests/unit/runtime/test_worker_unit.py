from __future__ import annotations

from typing import Optional

import pytest

from lg_sotf.runtime.worker import sanitize_error, waiting_status_to_restore


@pytest.mark.parametrize(
    ("claimed_from", "alert_status", "expected"),
    [
        ("waiting_human", "waiting_human", "waiting_human"),
        ("waiting_approval", "processing", "waiting_approval"),
        ("failed", "waiting_human", "waiting_human"),
        ("running", "waiting_approval", "waiting_approval"),
        ("failed", "processing", None),
        ("queued", "queued", None),
        (None, None, None),
        ("failed", None, None),
    ],
)
def test_waiting_status_to_restore(
    claimed_from: Optional[str], alert_status: Optional[str], expected: Optional[str]
) -> None:
    assert waiting_status_to_restore(claimed_from, alert_status) == expected


def test_sanitize_error_is_short_single_line_and_redacted() -> None:
    exc = RuntimeError("line one\nAuthorization: Bearer sk-ant-api03-" + "a" * 60 + "\n" + "x" * 1000)
    text = sanitize_error(exc)
    assert text.startswith("RuntimeError: ")
    assert "\n" not in text
    assert "sk-ant-api03" not in text
    assert len(text) <= 300


def test_sanitize_error_redacts_before_cutting() -> None:
    # Cutting first would leave the token's head, too short for the JWT pattern, in last_error.
    jwt = "eyJ" + "x" * 20 + "." + "eyJ" + "y" * 20 + "." + "z" * 24
    text = sanitize_error(RuntimeError("m" * 270 + " " + jwt))
    assert "eyJ" not in text and "xxxxx" not in text and len(text) <= 300


def test_sanitize_error_without_message() -> None:
    assert sanitize_error(TimeoutError()) == "TimeoutError"
