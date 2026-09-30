"""The email normalizer: severity, entities, the email section and who may use the format."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from lg_sotf.ingestion.email import parse_email, unparsed_email
from lg_sotf.ingestion.errors import NormalizationError, SourceConfigError, UnrecognizedEvent
from lg_sotf.ingestion.fingerprint import compute_fingerprint
from lg_sotf.ingestion.normalizers import get_normalizer, resolve_format
from lg_sotf.ingestion.normalizers.email import email_error_event
from lg_sotf.models.alert import CanonicalAlert
from lg_sotf.security.redaction import redact
from tests.unit.ingestion._email import HARVEST, PDF, auth, build, wrap
from tests.unit.ingestion._support import ctx


def normalize(doc: Dict[str, Any], source_type: str = "m365_mailbox") -> CanonicalAlert:
    redacted, _ = redact(doc)
    return get_normalizer("email").normalize(redacted, ctx(source_type, source_id="phish-box"))


def test_reported_email_becomes_a_phishing_alert() -> None:
    inner = build(
        sender="helpdesk@examp1e.test", display="IT", subject="Scheduled maintenance test",
        reply_to="collect@attacker.test", ar=[auth("examp1e.test", spf="fail", dmarc="fail")],
        received=["from mail.examp1e.test (mail.examp1e.test [203.0.113.7]) by mx.example.com; Mon"],
        html="<a href='http://198.51.100.9/login'>https://login.example.com</a>",
        attachments=[("invoice.pdf", "application", "pdf", PDF)],
    )
    alert = normalize(parse_email(wrap(inner)))
    assert alert.source_type == "email" and alert.category == "phishing" and alert.rule_name == "user_reported_email"
    assert alert.title == "Reported email: Scheduled maintenance test"
    assert "title_from_message" in alert.flags
    assert alert.severity == "high"  # DMARC failure together with a deceptive raw-IP link
    assert alert.source_alert_id.startswith("email:")
    entities = alert.entities
    assert entities.emails == ["helpdesk@examp1e.test", "collect@attacker.test"]
    assert {"examp1e.test", "attacker.test"} <= set(entities.domains)
    assert entities.urls[0] == "http://198.51.100.9/login"  # suspicious links first
    assert entities.ips[:1] == ["198.51.100.9"] and "203.0.113.7" in entities.ips
    assert len(entities.hashes) == 1 and entities.users == ["bob@example.com"]
    section = alert.email or {}
    assert section["from"]["address"] == "helpdesk@examp1e.test" and section["reporter"] == "bob@example.com"
    assert section["reported"] is True and section["relay_ip"] == "203.0.113.7"
    assert section["auth"][0]["dmarc"] == "fail"
    assert section["urls"][0]["mismatch"] is True and section["urls"][0]["display"].startswith("hxxp://")
    assert section["attachments"][0]["filename"] == "invoice.pdf" and "sha256" in section["attachments"][0]
    assert alert.unmapped == {}
    doc = alert.normalized_document()
    assert doc["email"]["subject"] == "Scheduled maintenance test"
    assert CanonicalAlert.from_stored(doc).email == section


def test_severity_follows_tenant_independent_facts() -> None:
    assert normalize(parse_email(build(ar=[auth("partner.test")]).as_bytes())).severity == "low"
    medium = build(ar=[auth("partner.test", spf="softfail")])
    assert normalize(parse_email(medium.as_bytes())).severity == "medium"
    assert normalize(parse_email(build(text="Verify your account now").as_bytes())).severity == "medium"
    assert normalize(parse_email(build(reply_to="x@other.test").as_bytes())).severity == "medium"
    risky = build(attachments=[("page.htm", "text", "html", HARVEST)])
    assert normalize(parse_email(risky.as_bytes())).severity == "high"


def test_non_email_alerts_have_no_email_section() -> None:
    canonical = get_normalizer("canonical").normalize(
        {"title": "t", "severity": "low", "email": {"from": {"address": "forged@example.com"}}}, ctx("webhook")
    )
    assert canonical.email is None and "email" not in canonical.normalized_document()
    assert canonical.unmapped["email"] == {"from": {"address": "forged@example.com"}}


def test_the_email_format_is_only_for_email_sources() -> None:
    assert resolve_format("m365_mailbox") == resolve_format("imap") == resolve_format("email") == "email"
    for source_type in ("webhook", "file"):
        with pytest.raises(SourceConfigError, match="email format"):
            resolve_format(source_type, {"format": "email"})
    with pytest.raises(UnrecognizedEvent):
        get_normalizer("email").normalize({"title": "not parsed"}, ctx("m365_mailbox"))


def test_placeholders_and_unparsed_messages() -> None:
    with pytest.raises(NormalizationError, match="too deep"):
        get_normalizer("email").normalize(email_error_event("message nesting is too deep"), ctx("email"))
    alert = normalize(unparsed_email("message is larger than 10 bytes", dedup_key="email:imap:1",
                                     metadata={"subject": "Huge", "reporter": "bob@example.com"}))
    assert alert.title == "Reported email could not be analysed: Huge"
    assert alert.severity == "medium" and "email_unparsed" in alert.flags
    assert alert.entities.users == ["bob@example.com"]
    assert (alert.email or {})["parse_error"].startswith("message is larger")


def test_fingerprint_is_stable_across_delivery_paths_and_subjects() -> None:
    push = normalize(parse_email(wrap(build(subject="one"))), "email")
    pulled = normalize(parse_email(wrap(build(subject="two"))), "imap")
    assert push.source_type == pulled.source_type == "email"
    assert compute_fingerprint(push) == compute_fingerprint(pulled)


def test_email_section_is_size_capped() -> None:
    urls = " ".join(f"https://h{i}.partner.test/{'p' * 1_500}" for i in range(100))
    alert = normalize(parse_email(build(text=urls).as_bytes()))
    section = alert.email or {}
    assert len(section.get("urls", [])) <= 25
    assert len(alert.entities.urls) <= 25
