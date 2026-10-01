"""The fixed reply ``mail.notify`` sends to the user who reported an email.

The text is fixed English: one paragraph per final verdict of the alert
(:attr:`~lg_sotf.integrations.microsoft.alert_view.AlertView.disposition`)
and a fixed closing. It has no links, no HTML (the body is sent as
``Text``), no model-written text and nothing internal to the alert (no
scores, ids or analyst notes).

The only reported content it repeats is the subject of the reported email,
in the reply's subject line, and that subject is attacker-controlled: it is
stripped of control, format and private-use characters (bidirectional
overrides included), of ``<`` and ``>``, has web addresses defanged
(``https://`` becomes ``hxxps[:]//``, ``www.`` becomes ``www[.]``) so no
client turns it into a link, and is cut to 120 characters.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Mapping, Tuple

from lg_sotf.integrations.microsoft.alert_view import Disposition

SUBJECT_PREFIX = "Update on the email you reported: "
MAX_REPORTED_SUBJECT_CHARS = 120
NO_SUBJECT = "(no subject)"

PARAGRAPHS: Mapping[str, str] = {
    "malicious": (
        "Thank you for reporting this email. Our security team reviewed it and confirmed that it is malicious. "
        "Do not open its links or attachments and do not reply to it; if it is still in your mailbox, delete it. "
        "If you already clicked a link, opened an attachment or entered your password, contact the security team "
        "or the IT service desk right away."
    ),
    "suspicious": (
        "Thank you for reporting this email. Our security team reviewed it and considers it suspicious. "
        "Treat it with caution: do not open its links or attachments and do not reply to it. If you already "
        "interacted with it, contact the security team or the IT service desk."
    ),
    "benign": (
        "Thank you for reporting this email. Our security team reviewed it and found no sign that it is "
        "malicious, so you can treat it as a normal message. Please keep reporting emails that look suspicious "
        "to you."
    ),
    "unknown": (
        "Thank you for reporting this email. Our security team has received your report and is reviewing it. "
        "Until you hear otherwise, do not open its links or attachments and do not reply to it."
    ),
}
CLOSING = "This is an automated message from the security team. Please do not reply to it."

# Unicode categories removed from the echoed subject: control, format (bidi overrides, zero-width
# characters), surrogates, private use and unassigned code points.
_DROPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_LINE_BREAKS = "\t\n\r\x0b\x0c"
_SCHEME = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,15}):/+")
_WWW = re.compile(r"(?i)\bwww\.")
_SPACES = re.compile(r"\s+")


def _defang_scheme(match: re.Match[str]) -> str:
    scheme = match.group(1)
    if scheme.lower().startswith("http"):
        scheme = "hxxp" + scheme[4:]
    return f"{scheme}[:]//"


def _visible(text: str) -> str:
    out = []
    for ch in text:
        category = unicodedata.category(ch)
        if ch in _LINE_BREAKS or category in ("Zl", "Zp"):
            out.append(" ")
        elif category not in _DROPPED_CATEGORIES and ch not in "<>":
            out.append(ch)
    return "".join(out)


def sanitize_subject(value: object) -> str:
    """The reported subject made safe to repeat: see the module docstring (never empty)."""
    text = _visible(unicodedata.normalize("NFKC", value if isinstance(value, str) else ""))
    text = _SCHEME.sub(_defang_scheme, text)
    text = _WWW.sub(lambda m: m.group(0)[:-1] + "[.]", text)
    text = _SPACES.sub(" ", text).strip()
    if len(text) > MAX_REPORTED_SUBJECT_CHARS:
        text = text[:MAX_REPORTED_SUBJECT_CHARS].rstrip()
    return text or NO_SUBJECT


def render(disposition: Disposition, reported_subject: object) -> Tuple[str, str]:
    """``(subject, plain-text body)`` of the reply for a verdict (anything unexpected gets the ``unknown`` text)."""
    paragraph = PARAGRAPHS.get(disposition, PARAGRAPHS["unknown"])
    subject = SUBJECT_PREFIX + sanitize_subject(reported_subject)
    body = f"{paragraph}\n\n{CLOSING}\n"
    return subject, body


__all__ = ["CLOSING", "PARAGRAPHS", "SUBJECT_PREFIX", "render", "sanitize_subject"]
