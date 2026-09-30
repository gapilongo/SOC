"""The reported-email parser: report wrappers, authentication, relays, links, attachments and hard caps."""

from __future__ import annotations

import ipaddress
import json
from email.message import EmailMessage
from typing import Any, Dict

import pytest

from lg_sotf.ingestion.email import EmailLimits, EmailParseError, EmailTooLarge, parse_email, unparsed_email
from lg_sotf.ingestion.email.attachments import classify, sniff
from lg_sotf.ingestion.email.auth import parse_authentication_results, parse_received, relay_hop
from lg_sotf.ingestion.email.urls import defang, ip_host, link_mismatch, site
from tests.unit.ingestion._email import HARVEST, LNK, PDF, PE, auth, build, wrap, zip_bytes


def parse(data: bytes, **kwargs: Any) -> Dict[str, Any]:
    return parse_email(data, **kwargs)


# -- report wrappers -------------------------------------------------------------------


def test_forwarded_report_analyses_the_inner_message_and_records_the_reporter() -> None:
    inner = build(sender="helpdesk@examp1e.test", display="IT Helpdesk", subject="Password expiry")
    doc = parse(wrap(inner))
    assert doc["schema"] == "lgsotf.email.v1"
    assert doc["from"] == {"address": "helpdesk@examp1e.test", "display_name": "IT Helpdesk", "domain": "examp1e.test"}
    assert doc["subject"] == "Password expiry"
    assert doc["message_id"] == "<m1@partner.test>"
    assert doc["report"] == {
        "wrapped": True, "envelope_subject": "FW: suspicious", "reporter": "bob@example.com", "reporter_source": "envelope",
    }
    # The reporter's own note is not part of the analysed body.
    assert "Reporting this one" not in doc["body"]["excerpt"]


def test_reporter_parameter_wins_and_unwrapped_messages_are_analysed_directly() -> None:
    doc = parse(wrap(build()), reporter="Carol@Example.com")
    assert doc["report"]["reporter"] == "carol@example.com" and doc["report"]["reporter_source"] == "param"
    direct = parse(build(subject="Direct").as_bytes(), reporter="carol@example.com")
    assert direct["report"] == {"wrapped": False, "reporter": "carol@example.com", "reporter_source": "param"}
    assert direct["subject"] == "Direct"
    assert parse(build().as_bytes())["report"] == {"wrapped": False}


def test_an_eml_attachment_is_a_report_too() -> None:
    outer = EmailMessage()
    outer["From"] = "bob@example.com"
    outer["Subject"] = "look at this"
    outer.set_content("see attached")
    outer.add_attachment(build(subject="Inner via eml").as_bytes(), maintype="application", subtype="octet-stream",
                         filename="suspicious.eml")
    doc = parse(outer.as_bytes())
    assert doc["subject"] == "Inner via eml" and doc["report"]["reporter"] == "bob@example.com"


def test_dedup_key_is_message_id_plus_reporter() -> None:
    first = parse(wrap(build(), reporter="bob@example.com"))
    again = parse(wrap(build(), reporter="bob@example.com"))
    other = parse(wrap(build(), reporter="carol@example.com"))
    assert first["dedup_key"] == again["dedup_key"] != other["dedup_key"]
    assert first["dedup_key"].startswith("email:")
    no_id = parse(build(message_id=None, text="body one").as_bytes())
    no_id_other = parse(build(message_id=None, text="body two").as_bytes())
    assert no_id["message_id"] is None and no_id["dedup_key"] != no_id_other["dedup_key"]


# -- headers -------------------------------------------------------------------------------


def test_addresses_reply_to_return_path_recipients_and_encoded_subject() -> None:
    msg = build(
        sender="ceo@partner.test", display="Chief", reply_to="Collector <collect@attacker.test>",
        return_path="bounce@mailer.test", to="alice@example.com, Bob <bob@example.com>",
    )
    del msg["Subject"]
    msg["Subject"] = "=?utf-8?q?Caf=C3=A9_invoice?="
    doc = parse(msg.as_bytes())
    assert doc["reply_to"] == [{"address": "collect@attacker.test", "display_name": "Collector"}]
    assert doc["return_path"] == "bounce@mailer.test"
    assert doc["to"] == ["alice@example.com", "bob@example.com"]
    assert doc["subject"] == "Café invoice"
    assert doc["date"] == "2026-09-28T09:30:00Z"


def test_gmail_style_authentication_results() -> None:
    parsed = parse_authentication_results(
        "mx.google.com; dkim=pass header.i=@partner.test header.s=s1 header.b=abc; "
        "dkim=fail header.d=other.test; spf=pass (google.com: domain of a@partner.test designates 198.51.100.7 "
        "as permitted sender) smtp.mailfrom=a@partner.test; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=partner.test"
    )
    assert parsed["authserv_id"] == "mx.google.com"
    assert (parsed["spf"], parsed["dkim"], parsed["dmarc"]) == ("pass", "pass", "pass")
    assert parsed["dkim_domains"] == ["partner.test"]
    assert parsed["smtp_mailfrom"] == "partner.test" and parsed["header_from"] == "partner.test"
    assert parsed["client_ip"] == "198.51.100.7"


def test_m365_style_authentication_results_have_no_authserv_id() -> None:
    parsed = parse_authentication_results(
        "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=examp1e.test; dkim=none (message not signed) "
        "header.d=none;dmarc=fail action=quarantine header.from=examp1e.test;compauth=fail reason=000"
    )
    assert parsed["authserv_id"] is None
    assert (parsed["spf"], parsed["dkim"], parsed["dmarc"], parsed["compauth"]) == ("fail", "none", "fail", "fail")
    assert parsed["client_ip"] == "203.0.113.9"


def test_every_authentication_results_header_is_kept_top_first() -> None:
    msg = build(ar=[auth("partner.test", dmarc="fail"), auth("partner.test", authserv="forged.test")])
    results = parse(msg.as_bytes())["authentication"]["results"]
    assert [r["authserv_id"] for r in results] == [MX_ID, "forged.test"]
    assert results[0]["dmarc"] == "fail" and results[1]["dmarc"] == "pass"


MX_ID = "mx.example.com"


def test_relay_is_the_first_external_hop_from_the_top() -> None:
    received = [
        "from mx-internal.example.com (mx-internal.example.com [10.0.0.5]) by store.example.com; Mon, 28 Sep 2026",
        "from gw.example.com (gw.example.com [192.0.2.10]) by mx-internal.example.com; Mon, 28 Sep 2026",
        "from mail.attacker.test (mail.attacker.test [203.0.113.7]) by gw.example.com; Mon, 28 Sep 2026",
        "from forged.test ([198.51.100.99]) by mail.attacker.test; Mon, 28 Sep 2026",
    ]
    doc = parse(build(received=received).as_bytes())
    assert doc["received"]["hops"] == 4 and doc["received"]["relay_ip"] == "192.0.2.10"
    trusted = [ipaddress.ip_network("192.0.2.0/24")]
    doc = parse(build(received=received).as_bytes(), trusted_relays=trusted)
    assert doc["received"]["relay_ip"] == "203.0.113.7" and doc["received"]["relay_host"] == "mail.attacker.test"


def test_received_parsing_variants() -> None:
    assert parse_received("from a.test (198.51.100.1) by b.test with SMTP")["ip"] == "198.51.100.1"
    assert parse_received("from a.test ([IPv6:2001:db8::1]) by b.test")["ip"] == "2001:db8::1"
    assert parse_received("by b.test with LMTP; Mon").get("ip") is None
    assert relay_hop([{"ip": "127.0.0.1"}, {"ip": "fd00::1"}]) is None


# -- bodies and links ----------------------------------------------------------------------


def test_html_link_text_that_names_another_domain_is_a_mismatch() -> None:
    html = (
        "<html><head><title>x</title><script>var u='https://script.attacker.test/'</script></head><body>"
        "<a href='https://collect.attacker.test/login'>https://login.example.com</a>"
        "<a href='https://www.example.com/help'>example.com/help</a>"
        "<a href='https://news.partner.test/t'>Read more</a>"
        "<form action='https://post.attacker.test/p'></form>"
        "<meta http-equiv='refresh' content='0; url=https://refresh.attacker.test/'>"
        "<a href='javascript:alert(1)'>click</a></body></html>"
    )
    doc = parse(build(html=html).as_bytes())
    by_url = {u["url"]: u for u in doc["urls"]}
    assert by_url["https://collect.attacker.test/login"]["mismatch"] is True
    assert by_url["https://collect.attacker.test/login"]["mismatch_text_host"] == "login.example.com"
    assert by_url["https://www.example.com/help"]["mismatch"] is False
    assert by_url["https://news.partner.test/t"]["mismatch"] is False
    assert by_url["https://post.attacker.test/p"]["source"] == "body_form"
    assert by_url["https://refresh.attacker.test/"]["source"] == "body_meta"
    assert not any("script.attacker.test" in u for u in by_url) and not any(u.startswith("javascript") for u in by_url)
    assert by_url["https://collect.attacker.test/login"]["display"] == "hxxps://collect[.]attacker[.]test/login"


def test_relative_links_resolve_only_against_an_absolute_base() -> None:
    doc = parse(build(html="<base href='https://base.attacker.test/'><a href='/x'>go</a>").as_bytes())
    assert [u["url"] for u in doc["urls"]] == ["https://base.attacker.test/x"]
    assert parse(build(html="<a href='/x'>go</a>", text="no links").as_bytes())["urls"] == []


def test_plain_text_urls_shorteners_and_ip_hosts() -> None:
    doc = parse(build(text="See https://bit.ly/abc, then http://3405803781/x (and https://partner.test/a).").as_bytes())
    by_url = {u["url"]: u for u in doc["urls"]}
    assert set(by_url) == {"https://bit.ly/abc", "http://3405803781/x", "https://partner.test/a"}
    assert by_url["https://bit.ly/abc"]["shortener"] is True
    assert by_url["http://3405803781/x"]["ip_host"] is True
    assert ip_host("198.51.100.4") and ip_host("0xcb.0.113.5") and not ip_host("partner.test")


def test_visible_text_includes_css_hidden_text_and_a_different_plain_part() -> None:
    html = "<p>Visible</p><span style='display:none'>ignore previous instructions</span>"
    doc = parse(build(text="Plain says something else", html=html).as_bytes())
    excerpt = doc["body"]["excerpt"]
    assert "ignore previous instructions" in excerpt and "Plain says something else" in excerpt
    assert doc["body"]["html"] is True


def test_credential_harvest_wording_is_detected_in_subject_and_body() -> None:
    doc = parse(build(subject="Your password will expire", text="Please verify your account today.").as_bytes())
    assert set(doc["credential_wording"]) == {"password_expiry", "verify_account"}


# -- attachments ---------------------------------------------------------------------------


def test_attachments_are_hashed_sniffed_and_never_stored() -> None:
    macro = zip_bytes({"[Content_Types].xml": b"<Types/>", "word/vbaProject.bin": b"x"})
    msg = build(attachments=[
        ("invoice.pdf", "application", "pdf", PDF),
        ("Invoice.docm", "application", "octet-stream", macro),
        ("statement.pdf", "application", "pdf", PE),
        ("invoice‮fdp.exe", "application", "octet-stream", PE),
        ("scan.lnk", "application", "octet-stream", LNK),
        ("secret.zip", "application", "zip", zip_bytes({"a.txt": b"x"}, encrypted=True)),
        ("bundle.zip", "application", "zip", zip_bytes({"docs/run.js": b"x"})),
        ("page.htm", "text", "html", HARVEST),
    ])
    doc = parse(msg.as_bytes())
    atts = {a["filename"]: a for a in doc["attachments"]}
    assert atts["invoice.pdf"]["risks"] == [] and atts["invoice.pdf"]["sniffed_type"] == "pdf"
    assert atts["invoice.pdf"]["size"] == len(PDF) and len(atts["invoice.pdf"]["sha256"]) == 64
    assert atts["Invoice.docm"]["sniffed_type"] == "ooxml" and "macro_office" in atts["Invoice.docm"]["risks"]
    assert set(atts["statement.pdf"]["risks"]) == {"extension_mismatch", "script_or_executable"}
    assert "deceptive_filename" in atts["invoicefdp.exe"]["risks"]
    assert atts["scan.lnk"]["risks"] == ["shortcut"]
    assert atts["secret.zip"]["risks"] == ["encrypted_archive"]
    assert atts["bundle.zip"]["risks"] == ["archive_with_risky_content"]
    assert atts["page.htm"]["risks"] == ["html"]
    # Links in an HTML attachment are analysed; content itself is never kept.
    assert any(u["url"] == "https://collect.attacker.test/post" and u["source"] == "attachment_form" for u in doc["urls"])
    serialised = json.dumps(doc)
    assert "vbaProject" not in serialised and "This program" not in serialised and "<form" not in serialised


def test_sniffing_and_classification_units() -> None:
    assert sniff(b"%PDF-1.4") == "pdf" and sniff(PE) == "pe" and sniff(b"\x7fELF") == "elf"
    assert sniff(b"<!DOCTYPE html><html>") == "html" and sniff(b"\xff\xfe\x00") == "unknown"
    iso = b"\x00" * 0x8001 + b"CD001" + b"\x00" * 16
    assert classify("disk.bin", "application/octet-stream", iso)[0] == "iso"
    assert "disk_image" in classify("disk.bin", "application/octet-stream", iso)[1]
    assert classify("x.xls", "application/vnd.ms-excel", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1_VBA_PROJECT")[1] == [
        "macro_office"
    ]
    assert "encrypted_document" in classify("x.docx", "", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + "EncryptedPackage".encode("utf-16-le"))[1]
    assert classify("broken.zip", "application/zip", b"PK\x03\x04garbage")[1] == []


# -- malformed and hostile input -------------------------------------------------------------


def test_malformed_mime_never_raises() -> None:
    samples = [
        b"",
        b"not an email at all",
        b"Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nunterminated",
        b"Content-Type: text/plain; charset=no-such-charset\n\nhello \xff\xfe",
        b"Content-Transfer-Encoding: base64\nContent-Type: application/pdf; name=a.pdf\n\n!!!not base64!!!",
        b"From: =?bogus?x?abc?=\nSubject: =?utf-8?b?not-base64?=\n\nbody",
        b"From: <<<>>>@@@\nTo: ,,,\nReply-To: \"unterminated\n\nbody",
    ]
    for data in samples:
        doc = parse(data)
        assert doc["schema"] == "lgsotf.email.v1"
        json.dumps(doc)


def test_oversized_messages_are_refused() -> None:
    limits = EmailLimits(max_message_bytes=2_048)
    with pytest.raises(EmailTooLarge):
        parse(b"Subject: x\n\n" + b"a" * 4_096, limits=limits)
    parse(build().as_bytes(), limits=limits)


def test_implausibly_many_boundaries_are_refused_before_parsing() -> None:
    limits = EmailLimits(max_parts=5)
    body = b"Content-Type: multipart/mixed; boundary=b\n\n" + b"\n--b\n\nx" * 200
    with pytest.raises(EmailParseError, match="too many MIME parts"):
        parse(body, limits=limits)


def test_part_count_and_depth_are_capped() -> None:
    msg = build(attachments=[(f"f{i}.txt", "application", "octet-stream", b"x") for i in range(6)])
    doc = parse(msg.as_bytes(), limits=EmailLimits(max_parts=3))
    assert "part_cap_reached" in doc["flags"] and len(doc["attachments"]) < 6
    limits = EmailLimits(max_parts=10, max_depth=2)
    nested = b"Content-Type: multipart/mixed; boundary=a\n\n--a\nContent-Type: multipart/mixed; boundary=b\n\n" \
             b"--b\nContent-Type: multipart/mixed; boundary=c\n\n--c\nContent-Type: text/plain\n\ndeep https://deep.test/x\n" \
             b"--c--\n--b--\n--a--\n"
    doc = parse(nested, limits=limits)
    assert "depth_capped" in doc["flags"] and doc["urls"] == []


def test_deep_nesting_that_exhausts_the_parser_is_refused() -> None:
    depth = 3_000
    parts = b"".join(f"--b{i}\nContent-Type: multipart/mixed; boundary=b{i + 1}\n\n".encode() for i in range(depth))
    data = b"Content-Type: multipart/mixed; boundary=b0\n\n" + parts
    limits = EmailLimits(max_parts=5_000)
    try:
        doc = parse(data, limits=limits)
    except EmailParseError as exc:
        assert "too deep" in str(exc) or "parts" in str(exc)
    else:
        assert "depth_capped" in doc["flags"]


def test_url_header_and_attachment_caps() -> None:
    limits = EmailLimits(max_urls=3, max_header_chars=300, max_attachments=2)
    text = " ".join(f"https://h{i}.partner.test/" for i in range(10))
    msg = build(text=text, attachments=[(f"f{i}.bin", "application", "octet-stream", b"x") for i in range(4)])
    msg["X-Padding"] = "y"
    del msg["To"]
    msg["To"] = ", ".join(f"user{i}@example.com" for i in range(60))
    doc = parse(msg.as_bytes(), limits=limits)
    assert len(doc["urls"]) == 3 and doc["url_count"] == 10 and "url_cap_reached" in doc["flags"]
    assert "header_truncated" in doc["flags"]
    assert len(doc["attachments"]) == 2 and doc["attachment_count"] == 4 and "attachment_cap_reached" in doc["flags"]


def test_body_excerpt_is_capped() -> None:
    doc = parse(build(text="word " * 5_000).as_bytes(), limits=EmailLimits(max_body_excerpt_chars=100))
    assert len(doc["body"]["excerpt"]) == 100 and doc["body"]["chars"] > 100


def test_unparsed_placeholder_document() -> None:
    doc = unparsed_email(
        "message is larger than 10 bytes", dedup_key="email:m365:abc",
        metadata={"subject": "Big one", "from": "Bob@Example.com", "message_id": "<x@y.test>", "reporter": "bob@example.com"},
    )
    assert doc["parse_error"].startswith("message is larger")
    assert doc["from"]["address"] == "bob@example.com" and doc["report"]["reporter"] == "bob@example.com"
    assert doc["message_id"] == "<x@y.test>" and doc["flags"] == ["unparsed"]


def test_url_helpers() -> None:
    assert site("mail.example.co.uk") == "example.co.uk" and site("a.b.partner.test") == "partner.test"
    assert link_mismatch("https://login.example.com", "evil.test") == "login.example.com"
    assert link_mismatch("Click here", "evil.test") is None
    assert link_mismatch("www.example.com", "cdn.example.com") is None
    assert defang("HTTPS://Evil.Test:8443/a.b?c.d") == "hxxpS://Evil[.]Test:8443/a.b?c.d"


# -- parser cost ------------------------------------------------------------------------


def _headers(name: str, count: int, width: int = 16_000) -> bytes:
    value = ", ".join(f"user{i}@example.com" for i in range(width // 18))[:width]
    return f"{name}: {value}\r\n".encode() * count


def _forward(inner: bytes) -> bytes:
    return (
        b"From: Bob <bob@example.com>\r\nTo: phish@example.com\r\nSubject: FW: suspicious\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=OUTER\r\n\r\n--OUTER\r\nContent-Type: text/plain\r\n\r\nsee\r\n"
        b"--OUTER\r\nContent-Type: message/rfc822\r\n\r\n" + inner + b"\r\n--OUTER--\r\n"
    )


def _timed(data: bytes) -> tuple[Dict[str, Any], float]:
    import time

    start = time.perf_counter()
    doc = parse(data)
    return doc, time.perf_counter() - start


def test_megabytes_of_recipient_headers_parse_quickly_and_recipients_are_capped() -> None:
    # About 2 MB of To/Cc headers: the joined value used to go through the stdlib address parser whole
    # (super-linear: minutes of CPU and gigabytes of memory).
    inner = (
        _headers("To", 128) + _headers("Cc", 8)
        + b"From: sender@partner.test\r\nSubject: hi\r\nMessage-ID: <m1@partner.test>\r\n\r\nbody\r\n"
    )
    assert len(inner) > 2_000_000
    for data in (inner, _forward(inner)):
        doc, elapsed = _timed(data)
        assert elapsed < 5.0
        assert len(doc["to"]) == EmailLimits().max_recipients and doc["to"][0] == "user0@example.com"
        assert "header_truncated" in doc["flags"]


def test_an_attached_message_with_huge_headers_is_hashed_without_reparsing_them() -> None:
    # A forwarded report whose message carries another message as an attachment: that attachment is hashed,
    # not analysed, so no header cap applies to its (single, 2 MB) To header or its Content-Type.
    params = "; ".join(f"p{i}=v{i}" for i in range(150_000))
    attached = (
        _headers("To", 1, width=2_000_000) + f"Content-Type: text/plain; {params}\r\n".encode()
        + b"From: x@partner.test\r\nSubject: s\r\n\r\nbody\r\n"
    )
    inner = (
        b"From: sender@partner.test\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=INNER"
        b"\r\n\r\n--INNER\r\nContent-Type: text/plain\r\n\r\nhello\r\n--INNER\r\nContent-Type: message/rfc822\r\n\r\n"
        + attached + b"\r\n--INNER--\r\n"
    )
    doc, elapsed = _timed(_forward(inner))
    assert elapsed < 5.0
    [attachment] = doc["attachments"]
    assert attachment["sniffed_type"] == "message"
    # Measured as received: the part (its own short headers, then the message; line endings normalised).
    assert 0 <= attachment["size"] - len(attached.replace(b"\r\n", b"\n")) <= 64


def test_a_huge_content_type_parses_quickly() -> None:
    params = "; ".join(f"p{i}=v{i}" for i in range(150_000))
    data = f"From: sender@partner.test\r\nContent-Type: text/plain; {params}\r\n\r\nhello\r\n".encode()
    doc, elapsed = _timed(data)
    assert elapsed < 5.0
    assert doc["body"]["excerpt"] == "hello"
