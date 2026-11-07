"""safe_text and safe_error_text: redact first, collapse whitespace, then truncate."""

from __future__ import annotations

import pytest

from lg_sotf.security.redaction import safe_error_text, safe_text

# Built at runtime so no committed string looks like a credential.
FAKE_JWT = "eyJ" + "x" * 20 + "." + "eyJ" + "y" * 20 + "." + "z" * 24


def test_redacts_before_truncating() -> None:
    # Truncating first would cut the token below the JWT pattern's minimum and let its head through.
    text = "a" * 280 + " bearer " + FAKE_JWT
    out = safe_text(text, 300)
    assert "eyJ" not in out and "xxxxx" not in out
    assert len(out) <= 300


def test_collapses_whitespace_and_marks_the_cut() -> None:
    assert safe_text("  a\n\tb   c \r\n", 50) == "a b c"
    out = safe_text("word " * 100, 20)
    assert out == "word word word wo..." and len(out) == 20


@pytest.mark.parametrize("limit", [0, 1, 3])
def test_tiny_limits(limit: int) -> None:
    assert safe_text("abcdef", limit) == "abcdef"[:limit]


def test_whitespace_runs_cannot_pull_an_unscanned_tail_into_view() -> None:
    out = safe_text(" " * 10_000 + "token=" + "q" * 40, 300)
    assert "q" * 8 not in out


def test_safe_error_text() -> None:
    assert safe_error_text(TimeoutError()) == "TimeoutError"
    assert safe_error_text(ValueError("  ")) == "ValueError"
    out = safe_error_text(ValueError("bad\nrequest bearer " + FAKE_JWT))
    assert out.startswith("ValueError: bad request bearer ") and FAKE_JWT not in out


def test_safe_error_text_limit_covers_the_type_name() -> None:
    out = safe_error_text(RuntimeError("x" * 1000), limit=50)
    assert len(out) == 50 and out.startswith("RuntimeError: ") and out.endswith("...")
    assert safe_error_text(RuntimeError("x"), limit=5) == "Runti"
