"""User-reported email documents (:mod:`lg_sotf.ingestion.email`) to canonical alerts.

The input is never a vendor payload: it is the document the platform's own
MIME parser produced (``schema = "lgsotf.email.v1"``) for the push endpoint
``POST /ingest/email`` or the ``m365_mailbox``/``imap`` pull sources. Webhook
and file sources cannot select this format, so a pushed JSON event can
never pose as a parsed email with, say, forged authentication results.

The alert: ``source_type`` ``email`` (whichever path delivered it),
``category`` ``phishing``, rule name ``user_reported_email``, the subject in
the title, ``occurred_at`` the time the report was received. The title and
description carry sender-controlled text, so the alert is flagged
``title_from_message`` and triage takes no keyword evidence from them.

Entities: sender, Reply-To and Return-Path addresses (``emails``) and their
domains, URLs (suspicious ones first) with their hosts, the relay IP,
attachment SHA-256 hashes, and the reporter (``users``). Recipients are kept
in the email section, not as entities, and so are the URLs only shown as the
text of another link (``display_only``, listed last): they are not where the
message leads, so they are never indicators or response targets.

Severity comes from facts that need no tenant context: ``high`` for a risky
attachment, or a failed DMARC check together with a deceptive or raw-IP
link; ``medium`` for failed SPF/DMARC, deceptive, raw-IP or shortened links,
a Reply-To on another domain or credential-harvest wording, and for
messages that could not be analysed; ``low`` otherwise (most reports are
benign). The email section (``CanonicalAlert.email``) keeps the compact facts
the triage signals, the analyst UI and the response planner read.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Mapping, Optional

from lg_sotf.domain.urls import site
from lg_sotf.ingestion.email.parser import SCHEMA
from lg_sotf.ingestion.errors import NormalizationError, UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import AlertBuilder, NormalizeContext, require_mapping
from lg_sotf.models.alert import CanonicalAlert, Severity

SOURCE_TYPE = "email"
CATEGORY = "phishing"
RULE_NAME = "user_reported_email"
FLAG_TITLE_FROM_MESSAGE = "title_from_message"
FLAG_UNPARSED = "email_unparsed"
ERROR_KEY = "_lgsotf_email_error"
MAX_SECTION_URLS = 25
MAX_SECTION_ATTACHMENTS = 10
MAX_SECTION_AUTH = 3
MAX_SECTION_RECIPIENTS = 10
MAX_ENTITY_URLS = 25
MAX_EXCERPT_CHARS = 1_500
MAX_SUBJECT_CHARS = 256
_FLAG_PREFIX = "email_"
_KNOWN_FLAGS = frozenset(
    {
        "url_cap_reached", "attachment_cap_reached", "part_cap_reached", "depth_capped", "header_truncated",
        "header_count_capped", "scan_truncated",
    }
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else []


def _str(value: Any, limit: int = 512) -> Optional[str]:
    return value[:limit] if isinstance(value, str) and value else None


def topmost_auth(doc: Mapping[str, Any]) -> Mapping[str, Any]:
    results = _list(_mapping(doc.get("authentication")).get("results"))
    return _mapping(results[0]) if results else {}


def _suspicious_url(url: Mapping[str, Any]) -> bool:
    return bool(url.get("mismatch") or url.get("ip_host") or url.get("shortener") or url.get("punycode"))


def ordered_urls(doc: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """URLs with the suspicious ones (deceptive text, raw IP, shortener, punycode) first, display-only ones last."""
    urls = [_mapping(u) for u in _list(doc.get("urls")) if isinstance(u, Mapping) and _str(u.get("url"), 2_048)]
    return sorted(urls, key=lambda u: 2 if u.get("display_only") else 0 if _suspicious_url(u) else 1)


def link_urls(doc: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """:func:`ordered_urls` without the display-only ones: what the message really links to."""
    return [u for u in ordered_urls(doc) if not u.get("display_only")]


def _reply_to_elsewhere(doc: Mapping[str, Any]) -> bool:
    sender = _str(_mapping(doc.get("from")).get("domain"), 255)
    if not sender:
        return False
    for entry in _list(doc.get("reply_to")):
        address = _str(_mapping(entry).get("address"), 320) or ""
        if "@" in address and site(address.rsplit("@", 1)[1]) != site(sender):
            return True
    return False


def email_severity(doc: Mapping[str, Any]) -> Severity:
    """See the module docs; attacker-controlled facts can only raise it above ``low``."""
    if doc.get("parse_error"):
        return "medium"
    auth = topmost_auth(doc)
    urls = link_urls(doc)
    deceptive_link = any(u.get("mismatch") or u.get("ip_host") for u in urls)
    risky_attachment = any(_list(_mapping(a).get("risks")) for a in _list(doc.get("attachments")))
    dmarc_failed = auth.get("dmarc") == "fail"
    if risky_attachment or (dmarc_failed and deceptive_link):
        return "high"
    if (
        dmarc_failed
        or auth.get("spf") in ("fail", "softfail")
        or deceptive_link
        or any(u.get("shortener") for u in urls)
        or _reply_to_elsewhere(doc)
        or _list(doc.get("credential_wording"))
    ):
        return "medium"
    return "low"


def email_section(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """The compact facts stored as ``CanonicalAlert.email`` (see the module docs)."""
    sender = _mapping(doc.get("from"))
    report = _mapping(doc.get("report"))
    received = _mapping(doc.get("received"))
    auth = _mapping(doc.get("authentication"))
    body = _mapping(doc.get("body"))
    recipients = [a for a in _list(doc.get("to")) + _list(doc.get("cc")) if isinstance(a, str)]
    section: Dict[str, Any] = {
        "message_id": _str(doc.get("message_id")),
        "subject": _str(doc.get("subject"), MAX_SUBJECT_CHARS) or "",
        "date": _str(doc.get("date"), 40),
        "from": {
            "address": _str(sender.get("address"), 320) or "",
            "display_name": _str(sender.get("display_name"), 256) or "",
            "domain": _str(sender.get("domain"), 255),
        },
        "reply_to": [
            a for a in (_str(_mapping(e).get("address"), 320) for e in _list(doc.get("reply_to"))[:5]) if a
        ],
        "return_path": _str(doc.get("return_path"), 320),
        "recipients": recipients[:MAX_SECTION_RECIPIENTS],
        "recipient_count": len(recipients),
        "auth": [dict(_mapping(r)) for r in _list(auth.get("results"))[:MAX_SECTION_AUTH]],
        "relay_ip": _str(received.get("relay_ip"), 64),
        "relay_host": _str(received.get("relay_host"), 255),
        "urls": [
            {
                k: u[k]
                for k in (
                    "url", "display", "host", "source", "mismatch", "mismatch_text_host", "ip_host", "shortener",
                    "punycode", "display_only",
                )
                if k in u
            }
            for u in ordered_urls(doc)[:MAX_SECTION_URLS]
        ],
        "url_count": doc.get("url_count") if isinstance(doc.get("url_count"), int) else len(_list(doc.get("urls"))),
        "attachments": [
            {
                k: a[k]
                for k in ("filename", "extension", "declared_type", "sniffed_type", "size", "sha256", "risks")
                if k in a
            }
            for a in (_mapping(x) for x in _list(doc.get("attachments"))[:MAX_SECTION_ATTACHMENTS])
        ],
        "attachment_count": doc.get("attachment_count")
        if isinstance(doc.get("attachment_count"), int)
        else len(_list(doc.get("attachments"))),
        "reported": bool(report.get("wrapped")) or bool(report.get("reporter")),
        "reporter": _str(report.get("reporter"), 320),
        "reporter_source": _str(report.get("reporter_source"), 16),
        "credential_wording": [w for w in _list(doc.get("credential_wording")) if isinstance(w, str)][:8],
        "body_excerpt": (_str(body.get("excerpt"), 65_536) or "")[:MAX_EXCERPT_CHARS],
        "flags": [f for f in _list(doc.get("flags")) if isinstance(f, str)][:16],
    }
    if isinstance(auth.get("received_spf"), Mapping):
        section["received_spf"] = dict(auth["received_spf"])
    if doc.get("parse_error"):
        section["parse_error"] = _str(doc.get("parse_error"), 200)
    return section


def _flags(doc: Mapping[str, Any]) -> List[str]:
    out = [FLAG_TITLE_FROM_MESSAGE]
    if doc.get("parse_error"):
        out.append(FLAG_UNPARSED)
    out.extend(_FLAG_PREFIX + f for f in _list(doc.get("flags")) if f in _KNOWN_FLAGS)
    return out


def _title(section: Mapping[str, Any], unparsed: bool) -> str:
    subject = section.get("subject") or "(no subject)"
    if unparsed:
        return f"Reported email could not be analysed: {subject}"
    prefix = "Reported email" if section.get("reported") else "Email"
    return f"{prefix}: {subject}"


def _description(section: Mapping[str, Any], error: Optional[str]) -> str:
    sender = _mapping(section.get("from"))
    who = sender.get("address") or "an unknown sender"
    if sender.get("display_name"):
        who = f"\"{sender['display_name']}\" <{who}>"
    parts = [f"Email from {who} to {section.get('recipient_count', 0)} recipient(s)"]
    if section.get("reporter"):
        parts.append(f"reported by {section['reporter']}")
    text = ", ".join(parts) + "."
    if error:
        text += f" The message could not be analysed: {error}."
    return text


class EmailNormalizer:
    name = "email"

    def normalize(self, event: Mapping[str, Any], ctx: NormalizeContext) -> CanonicalAlert:
        event = require_mapping(event, self.name)
        if ERROR_KEY in event:
            raise NormalizationError(str(event[ERROR_KEY])[:200] or "email could not be parsed")
        if event.get("schema") != SCHEMA:
            raise UnrecognizedEvent("not a parsed email document")
        dedup_key = _str(event.get("dedup_key"), 256)
        if not dedup_key:
            raise NormalizationError("parsed email has no dedup key")
        error = _str(event.get("parse_error"), 200)
        section = email_section(event)
        b = AlertBuilder(event, replace(ctx, source_type=SOURCE_TYPE))
        b.consume(*event.keys())
        b.flags.extend(_flags(event))
        sender = _mapping(section.get("from"))
        b.entities.add_email([sender.get("address"), *section["reply_to"], section.get("return_path")])
        b.entities.add_domain(
            [sender.get("domain")]
            + [a.rsplit("@", 1)[1] for a in [*section["reply_to"], section.get("return_path") or ""] if "@" in a]
        )
        b.entities.add_url([u["url"] for u in link_urls(event)[:MAX_ENTITY_URLS]])
        b.entities.add_ip(section.get("relay_ip"))
        b.entities.add_hash([a.get("sha256") for a in _list(event.get("attachments")) if isinstance(a, Mapping)])
        b.entities.add_user(section.get("reporter"))
        return b.build(
            title=_title(section, error is not None),
            severity=email_severity(event),
            time_candidates=(event.get("received_at"),),
            source_alert_id=dedup_key,
            description=_description(section, error),
            category=CATEGORY,
            rule_name=RULE_NAME,
            email=section,
        )


def email_error_event(reason: str) -> Dict[str, Any]:
    """A placeholder the normalizer rejects with ``reason`` (a message the push API could not parse)."""
    return {ERROR_KEY: reason[:200]}


__all__ = [
    "CATEGORY",
    "EmailNormalizer",
    "FLAG_TITLE_FROM_MESSAGE",
    "RULE_NAME",
    "SOURCE_TYPE",
    "email_error_event",
    "email_section",
    "email_severity",
    "link_urls",
    "ordered_urls",
    "topmost_auth",
]
