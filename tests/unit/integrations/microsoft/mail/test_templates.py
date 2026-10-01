"""The fixed reporter reply: no links, no HTML, no alert internals; the echoed subject is sanitised."""

from __future__ import annotations

import re

import pytest

from lg_sotf.integrations.microsoft.mail import templates

LINK = re.compile(r"(?i)(://|\bwww\.|href|<|>|&[a-z]+;)")


@pytest.mark.parametrize("disposition", ["malicious", "suspicious", "benign", "unknown", "something-else"])
def test_every_reply_is_plain_fixed_text(disposition: str) -> None:
    subject, body = templates.render(disposition, "Invoice overdue")  # type: ignore[arg-type]
    assert subject == "Update on the email you reported: Invoice overdue"
    assert not LINK.search(body) and not LINK.search(subject)
    assert body.endswith(templates.CLOSING + "\n")
    expected = templates.PARAGRAPHS.get(disposition, templates.PARAGRAPHS["unknown"])
    assert body.startswith(expected)


def test_each_verdict_has_its_own_paragraph() -> None:
    bodies = {d: templates.render(d, "x")[1] for d in ("malicious", "suspicious", "benign", "unknown")}
    assert len(set(bodies.values())) == 4
    assert "confirmed that it is malicious" in bodies["malicious"]
    assert "normal message" in bodies["benign"]


@pytest.mark.parametrize(
    ("reported", "echoed"),
    [
        ("Pay now: https://evil.example/login", "Pay now: hxxps[:]//evil.example/login"),
        ("See www.evil.example today", "See www[.]evil.example today"),
        ("HTTP://EVIL.example", "hxxp[:]//EVIL.example"),
        ("ftp://files.example/x", "ftp[:]//files.example/x"),
        ("<b>Urgent</b> <script>x</script>", "bUrgent/b scriptx/script"),
        ("Line one\r\nBcc: victim@example.com", "Line one Bcc: victim@example.com"),
        ("Invoice‮gpj.exe", "Invoicegpj.exe"),  # bidirectional override removed
        ("zero​width\x00null\x1bescape", "zerowidthnullescape"),
        ("ｈｔｔｐｓ：／／evil.example", "hxxps[:]//evil.example"),  # fullwidth
        ("   ", "(no subject)"),
        ("", "(no subject)"),
    ],
)
def test_the_reported_subject_is_sanitised(reported: str, echoed: str) -> None:
    subject, _ = templates.render("malicious", reported)
    assert subject == templates.SUBJECT_PREFIX + echoed
    assert not LINK.search(subject)


def test_the_echoed_subject_is_cut_to_120_characters() -> None:
    subject, _ = templates.render("benign", "A" * 500)
    assert subject == templates.SUBJECT_PREFIX + "A" * 120
    assert templates.sanitize_subject(None) == "(no subject)"
