"""OData and path encoding of untrusted targets: validated first, encoded once, injection-proof."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone

import httpx
import pytest

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.odata import InvalidTarget


def test_string_literals_double_quotes_and_refuse_control_characters() -> None:
    assert odata.odata_string("o'brien") == "'o''brien'"
    assert odata.odata_string("x' or 1 eq 1 or 'a") == "'x'' or 1 eq 1 or ''a'"
    assert odata.odata_string("Grüße 👋") == "'Grüße 👋'"
    for bad in ("a\nb", "a\x00b", "a\x7fb", "a b", "", "x" * 1025):
        with pytest.raises(InvalidTarget) as exc:
            odata.odata_string(bad)
        assert exc.value.code == "invalid_target"


def test_eq_only_on_allowed_fields_and_datetimes_unquoted() -> None:
    assert odata.odata_eq("internetMessageId", "<a'b@x>") == "internetMessageId eq '<a''b@x>'"
    when = datetime(2026, 9, 30, 2, 0, tzinfo=timezone(timedelta(hours=2)))
    assert odata.odata_eq("receivedDateTime", when) == "receivedDateTime eq 2026-09-30T00:00:00Z"
    assert odata.graph_datetime(datetime(2026, 9, 30, tzinfo=UTC)) == "2026-09-30T00:00:00Z"
    assert odata.odata_any_eq("proxyAddresses", "smtp:a@b.example") == "proxyAddresses/any(x:x eq 'smtp:a@b.example')"
    with pytest.raises(ValueError):
        odata.odata_eq("displayName", "x")
    with pytest.raises(ValueError):
        odata.odata_eq("mail eq 'a' or true", "x")
    with pytest.raises(InvalidTarget):
        odata.graph_datetime(datetime(2026, 9, 30))  # naive


def test_wire_bytes_of_special_characters() -> None:
    """The finished filter is percent-encoded exactly once by the client (quote(v, safe=""))."""
    from urllib.parse import quote

    value = "a+b#c&d%e'f$g"
    flt = odata.odata_eq("userPrincipalName", value)
    encoded = quote(flt, safe="")
    assert encoded == "userPrincipalName%20eq%20%27a%2Bb%23c%26d%25e%27%27f%24g%27"
    url = httpx.URL(f"https://graph.microsoft.com/v1.0/users?$filter={encoded}")
    assert url.raw_path.endswith(b"$filter=" + encoded.encode())


def test_segments_and_user_paths() -> None:
    assert odata.segment("a/b?c#d") == "a%2Fb%3Fc%23d"
    for bad in (".", "..", "", "a\nb"):
        with pytest.raises(InvalidTarget):
            odata.segment(bad)
    guid = str(uuid.uuid4()).upper()
    assert odata.user_path(guid) == f"/v1.0/users/{guid.lower()}"
    assert odata.user_path("a.b+c@contoso.example") == "/v1.0/users/a.b%2Bc%40contoso.example"
    assert odata.user_path("$adele'x@contoso.example") == "/v1.0/users('%24adele%27%27x%40contoso.example')"
    for unsupported in ("CONTOSO\\jdoe", "jdoe"):
        with pytest.raises(InvalidTarget) as exc:
            odata.user_path(unsupported)
        assert exc.value.code == "unsupported_target"
    with pytest.raises(InvalidTarget):
        odata.user_path("a@b@c")
    assert odata.is_guid(guid) and not odata.is_guid("not-a-guid")


def test_email_message_id_and_host_formats() -> None:
    assert odata.email_address(" Alice@Contoso.Example ") == "alice@contoso.example"
    with pytest.raises(InvalidTarget):
        odata.email_address("alice@")
    assert odata.upn("Alice@Contoso.Example") == "Alice@Contoso.Example"
    assert odata.internet_message_id("abc@mail.example") == "<abc@mail.example>"
    assert odata.internet_message_id("<abc@mail.example>") == "<abc@mail.example>"
    for bad in ("<a b@x>", "<noat>", "<a@x>\r\nBcc: x", "<" + "a" * 1000 + "@x>"):
        with pytest.raises(InvalidTarget):
            odata.internet_message_id(bad)
    assert odata.hostname("WS-042.Corp.Example.") == "ws-042.corp.example"
    assert odata.hostname("ws-042") == "ws-042"
    with pytest.raises(InvalidTarget) as exc:
        odata.hostname("10.0.0.5")
    assert exc.value.code == "unsupported_target"
    for bad in ("-bad", "a_b", "a..b", "a/b"):
        with pytest.raises(InvalidTarget):
            odata.hostname(bad)


def test_indicators() -> None:
    assert odata.public_ip("185.220.101.44") == "185.220.101.44"
    assert odata.public_ip("::ffff:185.220.101.44") == "185.220.101.44"
    # Defender needs all eight IPv6 segments: never the "::" form.
    assert odata.public_ip("2606:4700:4700::1111") == "2606:4700:4700:0000:0000:0000:0000:1111"
    assert odata.public_ip("[2606:4700:4700:0:0:0:0:1111]") == "2606:4700:4700:0000:0000:0000:0000:1111"
    for private in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "fd00::1"):
        with pytest.raises(InvalidTarget) as exc:
            odata.public_ip(private)
        assert exc.value.code == "unsupported_target"
    with pytest.raises(InvalidTarget):
        odata.public_ip("185.220.101.0/24")
    assert odata.domain("Bücher.Example") == "xn--bcher-kva.example"
    for bad in ("localhost", "1.2.3.4", "a..b", "-x.example"):
        with pytest.raises(InvalidTarget):
            odata.domain(bad)
    assert odata.http_url("https://evil.example/x?y=1") == "https://evil.example/x?y=1"
    for bad in ("ftp://x.example", "https://user:pw@x.example", "https:///nohost", "https://x.example/a b"):
        with pytest.raises(InvalidTarget):
            odata.http_url(bad)
    assert odata.file_hash("A" * 64) == ("FileSha256", "a" * 64)
    assert odata.file_hash("b" * 40) == ("FileSha1", "b" * 40)
    assert odata.file_hash("c" * 32) == ("FileMd5", "c" * 32)
    with pytest.raises(InvalidTarget) as exc:
        odata.file_hash("d" * 128)
    assert exc.value.code == "unsupported_target"
    with pytest.raises(InvalidTarget):
        odata.file_hash("xyz")
