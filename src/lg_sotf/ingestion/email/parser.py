"""Parse a user-reported email (RFC 5322 bytes) into a bounded, JSON-safe document.

:func:`parse_email` is the only entry point. It uses the stdlib ``email``
package with ``policy.default`` and never renders, executes or stores
content: HTML is tokenised with ``html.parser``, attachments are hashed and
sniffed, and only a short, whitespace-collapsed body excerpt is kept.

Reported emails. A user usually reports by forwarding the suspicious email
*as an attachment* (``message/rfc822``); the Microsoft 365 report button
and Outlook/Gmail "forward as attachment" all do this. When the message has
such an attachment (or an ``.eml`` attachment) the first one is the message
analysed, and the outer message's sender is recorded as the reporter
(``report.reporter_source = "envelope"``). A reporter given by the caller
(the push API's ``reporter`` parameter) takes precedence (``"param"``).

Hard limits (:class:`EmailLimits`, overridable under ``ingestion.email`` in
the settings):

* messages larger than ``max_message_bytes`` are refused
  (:class:`EmailTooLarge`); so are messages with implausibly many MIME
  boundaries or nesting deep enough to exhaust the parser
  (:class:`EmailParseError`);
* parts beyond ``max_parts`` or ``max_depth`` are not visited, headers beyond
  ``max_headers`` are ignored, header values longer than
  ``max_header_chars`` are truncated, URLs beyond ``max_urls``, attachments
  beyond ``max_attachments`` and text beyond the scan limits are dropped;
  every cap that was reached is listed in ``flags``.

The document (``schema = "lgsotf.email.v1"``) is what the ingestion service
redacts, stores as the alert's ``raw`` and hands to the ``email`` normalizer.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.policy import EmailPolicy
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lg_sotf.ingestion.email.attachments import classify, clean_filename, extension
from lg_sotf.ingestion.email.auth import (
    IPNetwork,
    parse_authentication_results,
    parse_received,
    parse_received_spf,
    relay_hop,
)
from lg_sotf.ingestion.email.html import scan_html
from lg_sotf.ingestion.email.urls import (
    MAX_URL_CHARS,
    ascii_host,
    defang,
    ip_host,
    is_punycode,
    link_mismatch,
    shortener,
    split_url,
    urls_in_text,
)

SCHEMA = "lgsotf.email.v1"
MAX_SUBJECT_CHARS = 512
MAX_DISPLAY_NAME_CHARS = 256
MAX_ADDRESS_CHARS = 320
MAX_MESSAGE_ID_CHARS = 512
MAX_WORDING_MATCHES = 8
# A boundary-looking line count far beyond any real message (part cap x generous factor): refuse before parsing.
BOUNDARY_LINES_FACTOR = 20
_WANTED_HEADERS = frozenset(
    {
        "from", "sender", "reply-to", "return-path", "to", "cc", "subject", "date", "message-id",
        "authentication-results", "received", "received-spf",
    }
)
# Longest header value the stdlib parses on its own (Content-Type, Content-Disposition, ... of every part, several
# times each): generous for real RFC 2231 file names, small enough that parsing cost stays bounded.
MAX_MIME_HEADER_CHARS = 4_096
_ADDRESS_HEADERS = frozenset({"from", "sender", "reply-to", "to", "cc"})
_FOLD_RE = re.compile(r"\r?\n[ \t]+")
_SPACE_RE = re.compile(r"\s+")
_MESSAGE_ID_RE = re.compile(r"<([^<>\s]{1,995})>")
_ADDR_SPEC_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")

# Credential-harvest and urgency wording: a weak signal only (legitimate security notices use it too).
CREDENTIAL_WORDING: Tuple[Tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        ("verify_account", r"\b(?:verify|validate|confirm)\s+your\s+(?:account|identity|mailbox|email|login|credentials)\b"),
        ("password_expiry", r"\bpassword\s+(?:will\s+)?(?:expire|expires|expired|expiring)\b"),
        ("account_suspension", r"\baccount\s+(?:has\s+been|will\s+be|is)\s+(?:suspended|locked|disabled|closed|deactivated|restricted)\b"),
        ("unusual_sign_in", r"\bunusual\s+(?:sign[\s-]?in|login|activity)\b"),
        ("update_payment", r"\bupdate\s+your\s+(?:payment|billing|bank(?:ing)?)\s+(?:information|details|method)\b"),
        ("reset_password", r"\b(?:reset|change|update)\s+your\s+password\b"),
        ("mailbox_quota", r"\bmailbox\s+(?:is\s+)?(?:full|quota|storage)\b"),
        ("sign_in_to_view", r"\b(?:sign|log)\s*[\s-]?in\s+to\s+(?:view|access|download|open)\b"),
        ("shared_document", r"\bshared\s+(?:a\s+)?(?:document|file|folder)\s+with\s+you\b"),
        ("urgent_action", r"\b(?:urgent|immediate)\s+action\s+(?:is\s+)?required\b"),
        ("gift_card", r"\bgift\s*cards?\b"),
        ("wire_transfer", r"\b(?:wire|bank)\s+transfer\b.{0,80}\b(?:urgent|today|asap|immediately)\b"),
    )
)


class _BoundedPolicy(EmailPolicy):
    """``policy.default`` whose own header parsing sees at most :data:`MAX_MIME_HEADER_CHARS` of a value."""

    def header_fetch_parse(self, name: str, value: Any) -> Any:
        if isinstance(value, str) and len(value) > MAX_MIME_HEADER_CHARS:
            value = value[:MAX_MIME_HEADER_CHARS]
        return super().header_fetch_parse(name, value)


_POLICY = _BoundedPolicy()


class EmailParseError(ValueError):
    """The message cannot be analysed (message is safe to return: it never contains content)."""


class EmailTooLarge(EmailParseError):
    pass


class EmailLimits(BaseModel):
    """Hard caps for :func:`parse_email` (``settings.ingestion.email``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_message_bytes: int = Field(default=10 * 1024 * 1024, ge=1_024, le=50 * 1024 * 1024)
    max_parts: int = Field(default=200, ge=1, le=5_000)
    max_depth: int = Field(default=8, ge=1, le=32)
    max_headers: int = Field(default=1_000, ge=10, le=20_000)
    max_header_chars: int = Field(default=16_384, ge=256, le=1_048_576)
    max_received: int = Field(default=30, ge=1, le=200)
    max_auth_results: int = Field(default=10, ge=1, le=50)
    max_recipients: int = Field(default=100, ge=1, le=10_000)
    max_urls: int = Field(default=100, ge=1, le=1_000)
    max_attachments: int = Field(default=50, ge=1, le=500)
    max_body_excerpt_chars: int = Field(default=4_096, ge=0, le=65_536)
    max_scan_chars: int = Field(default=1_000_000, ge=1_024, le=20_000_000)
    max_total_scan_chars: int = Field(default=4_000_000, ge=1_024, le=50_000_000)

    @classmethod
    def from_settings(cls, ingestion: Optional[Mapping[str, Any]]) -> EmailLimits:
        section = (ingestion or {}).get("email") if isinstance(ingestion, Mapping) else None
        try:
            return cls.model_validate(dict(section or {}))
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
            raise ValueError(f"invalid ingestion.email settings: {', '.join(fields)}") from exc


@dataclass
class _Scan:
    """Mutable state of one parse (URLs, attachments, text budget, flags)."""

    limits: EmailLimits
    flags: Set[str] = field(default_factory=set)
    urls: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    urls_seen: int = 0
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    attachments_seen: int = 0
    parts: int = 0
    scanned_chars: int = 0
    plain: List[str] = field(default_factory=list)
    html_text: List[str] = field(default_factory=list)
    wording: Dict[str, None] = field(default_factory=dict)

    def budget(self) -> int:
        return max(0, min(self.limits.max_scan_chars, self.limits.max_total_scan_chars - self.scanned_chars))

    def take(self, text: str) -> str:
        room = self.budget()
        if len(text) > room:
            self.flags.add("scan_truncated")
            text = text[:room]
        self.scanned_chars += len(text)
        return text

    def add_url(self, url: str, *, text: str = "", source: str = "text") -> None:
        url = url.strip()
        parsed = split_url(url)
        if parsed is None or len(url) > MAX_URL_CHARS:
            return
        _, host = parsed
        entry = self.urls.get(url)
        if entry is None:
            self.urls_seen += 1
            if len(self.urls) >= self.limits.max_urls:
                self.flags.add("url_cap_reached")
                return
            entry = {
                "url": url,
                "host": ascii_host(host),
                "display": defang(url),
                "source": source,
                "ip_host": ip_host(host),
                "shortener": shortener(ascii_host(host)),
                "punycode": is_punycode(host),
            }
            self.urls[url] = entry
        if text and "text" not in entry:
            entry["text"] = text
        shown = link_mismatch(text, host) if text else None
        if shown is not None and "mismatch_text_host" not in entry:
            entry["mismatch_text_host"] = shown
        entry["mismatch"] = "mismatch_text_host" in entry


# --------------------------------------------------------------------------- headers


def _unfold(value: Any) -> str:
    return _FOLD_RE.sub(" ", str(value)).strip()


def _raw_headers(msg: Message, limits: EmailLimits, flags: Set[str]) -> Dict[str, List[str]]:
    """Unfolded raw values of the headers this module reads, capped in count and length."""
    out: Dict[str, List[str]] = {}
    for count, (name, value) in enumerate(msg.raw_items(), start=1):
        if count > limits.max_headers:
            flags.add("header_count_capped")
            break
        key = str(name).strip().lower()
        if key not in _WANTED_HEADERS:
            continue
        text = _unfold(value)
        if len(text) > limits.max_header_chars:
            flags.add("header_truncated")
            text = text[: limits.max_header_chars]
        out.setdefault(key, []).append(text)
    return out


def _clean_text(value: str, limit: int) -> str:
    text = "".join(ch if unicodedata.category(ch) != "Cc" else " " for ch in value)
    return _SPACE_RE.sub(" ", text).strip()[:limit]


def _decoded(name: str, raw: str) -> str:
    """RFC 2047-decoded header text; the raw value when decoding fails."""
    try:
        return str(policy.default.header_factory(name, raw))
    except Exception:  # noqa: BLE001 - a malformed encoded word must not fail the parse
        return raw


def _addresses(name: str, raw: str, limit: int) -> List[Dict[str, str]]:
    """``[{"address", "display_name"}]`` of an address header (policy.default parser, stdlib fallback)."""
    pairs: List[Tuple[str, str]] = []
    try:
        header = policy.default.header_factory(name, raw)
        for addr in getattr(header, "addresses", ())[: limit + 1]:
            pairs.append((str(addr.display_name or ""), str(addr.addr_spec or "")))
    except Exception:  # noqa: BLE001 - fall back to the lenient parser for malformed address lists
        pairs = [(d, a) for d, a in getaddresses([raw])[: limit + 1]]
    out: List[Dict[str, str]] = []
    for display, address in pairs[:limit]:
        addr = address.strip().strip("<>").lower()[:MAX_ADDRESS_CHARS]
        if not _ADDR_SPEC_RE.match(addr):
            addr = ""
        entry = {"address": addr, "display_name": _clean_text(display, MAX_DISPLAY_NAME_CHARS)}
        if addr or entry["display_name"]:
            out.append(entry)
    return out


def _address_list(name: str, values: Sequence[str], limits: EmailLimits, flags: Set[str]) -> List[Dict[str, str]]:
    """Addresses of a repeatable header (To, Cc), all instances together bounded by ``max_header_chars``.

    The stdlib address parser is super-linear in its input, so the joined
    value is capped before parsing (each instance is already capped alone).
    A cut value ends at the last complete list separator.
    """
    budget = limits.max_header_chars
    parts: List[str] = []
    used = 0
    for value in values:
        if used + len(value) > budget:
            flags.add("header_truncated")
            room = value[: max(0, budget - used)]
            cut = room.rfind(",")
            if cut > 0:
                parts.append(room[:cut])
            break
        parts.append(value)
        used += len(value) + 3
    return _addresses(name, " , ".join(parts), limits.max_recipients)


def _first(headers: Mapping[str, List[str]], key: str) -> Optional[str]:
    values = headers.get(key)
    return values[0] if values else None


def _message_id(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    match = _MESSAGE_ID_RE.search(raw)
    value = f"<{match.group(1)}>" if match else raw.strip()
    value = "".join(ch for ch in value if 32 < ord(ch) < 127)
    return value[:MAX_MESSAGE_ID_CHARS] or None


def _date(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    try:
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _domain(address: str) -> Optional[str]:
    return address.rsplit("@", 1)[1] if "@" in address else None


# --------------------------------------------------------------------------- bodies and attachments


def _text_of(part: Message) -> str:
    content: Any = None
    try:
        content = part.get_content()  # type: ignore[attr-defined]
    except (LookupError, UnicodeError, AttributeError, ValueError, AssertionError, KeyError):
        content = None  # unknown charset or broken transfer encoding: decode the raw payload below
    if isinstance(content, str):
        return content
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, "replace")
        except LookupError:
            return payload.decode("utf-8", "replace")
    return ""


# Serialises a parsed part as it was received: the default policy re-folds long header lines, which runs the
# (super-linear) structured header parsers over values that no header cap has bounded.
_VERBATIM = _POLICY.clone(refold_source="none")


def _payload_bytes(part: Message) -> bytes:
    if part.get_content_type() == "message/rfc822" or part.is_multipart():
        # The stdlib parser keeps no raw offsets; serialising without re-folding reproduces the received
        # bytes (up to line endings) in linear time.
        try:
            return part.as_bytes(policy=_VERBATIM)
        except Exception:  # noqa: BLE001 - an unserialisable embedded message is recorded without content
            return b""
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def _is_attachment(part: Message) -> bool:
    disposition = part.get_content_disposition()
    if disposition == "attachment" or part.get_filename():
        return True
    ctype = part.get_content_type()
    return part.get_content_maintype() not in ("text", "multipart") and not (
        ctype.startswith("image/") and disposition == "inline"
    )


def _scan_text(scan: _Scan, text: str, *, html: bool, source: str) -> None:
    text = scan.take(text)
    if not text:
        return
    if html:
        result = scan_html(text, max_links=scan.limits.max_urls * 4, max_text_chars=scan.limits.max_scan_chars)
        if result.links_dropped:
            scan.flags.add("url_cap_reached")
        for link in result.links:
            scan.add_url(link.url, text=link.text, source=source if link.kind == "a" else f"{source}_{link.kind}")
        visible = result.text
        if source == "body":
            scan.html_text.append(visible)
    else:
        visible = text
        if source == "body":
            scan.plain.append(text)
    for url in urls_in_text(visible, scan.limits.max_urls * 4):
        scan.add_url(url, source=source)
    _wording(scan, visible)


def _wording(scan: _Scan, text: str) -> None:
    if len(scan.wording) >= MAX_WORDING_MATCHES:
        return
    lowered = unicodedata.normalize("NFKC", text).lower()
    for name, pattern in CREDENTIAL_WORDING:
        if name not in scan.wording and pattern.search(lowered):
            scan.wording[name] = None


def _record_attachment(scan: _Scan, part: Message, depth: int) -> None:
    scan.attachments_seen += 1
    if len(scan.attachments) >= scan.limits.max_attachments:
        scan.flags.add("attachment_cap_reached")
        return
    filename, deceptive = clean_filename(part.get_filename())
    declared = part.get_content_type()
    data = _payload_bytes(part)
    sniffed, risks = classify(filename, declared, data, deceptive_name=deceptive)
    if declared == "message/rfc822":
        sniffed = "message"
    scan.attachments.append(
        {
            "filename": filename,
            "extension": extension(filename),
            "declared_type": declared[:128],
            "sniffed_type": sniffed,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "risks": risks,
        }
    )
    # HTML attachments are classic credential-harvest pages: their links and forms are analysed too.
    if "html" in risks and data:
        _scan_text(scan, data.decode("utf-8", "replace"), html=True, source="attachment")


def _walk(scan: _Scan, part: Message, depth: int, *, top: bool) -> None:
    if depth > scan.limits.max_depth:
        scan.flags.add("depth_capped")
        return
    scan.parts += 1
    if scan.parts > scan.limits.max_parts:
        scan.flags.add("part_cap_reached")
        return
    ctype = part.get_content_type()
    if ctype == "message/rfc822" and not top:
        _record_attachment(scan, part, depth)
        return
    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for sub in payload:
                if scan.parts >= scan.limits.max_parts:
                    scan.flags.add("part_cap_reached")
                    break
                if isinstance(sub, Message):
                    _walk(scan, sub, depth + 1, top=False)
        return
    if _is_attachment(part):
        _record_attachment(scan, part, depth)
        return
    if ctype == "text/plain":
        _scan_text(scan, _text_of(part), html=False, source="body")
    elif ctype == "text/html":
        _scan_text(scan, _text_of(part), html=True, source="body")


# --------------------------------------------------------------------------- report wrapper


def _embedded_message(msg: Message, limits: EmailLimits, depth: int = 0) -> Optional[Message]:
    """The first ``message/rfc822`` (or ``.eml``) attachment of a report wrapper, searched a few levels deep."""
    if depth > min(3, limits.max_depth) or not msg.is_multipart():
        return None
    payload = msg.get_payload()
    if not isinstance(payload, list):
        return None
    for sub in payload[: limits.max_parts]:
        if not isinstance(sub, Message):
            continue
        if sub.get_content_type() == "message/rfc822":
            inner = sub.get_payload()
            if isinstance(inner, list) and inner and isinstance(inner[0], Message):
                return inner[0]
        filename = (sub.get_filename() or "").lower()
        if filename.endswith(".eml") and not sub.is_multipart():
            data = sub.get_payload(decode=True)
            if isinstance(data, bytes) and data:
                return _parse_bytes(data, limits)
        if sub.is_multipart():
            found = _embedded_message(sub, limits, depth + 1)
            if found is not None:
                return found
    return None


# --------------------------------------------------------------------------- entry point


def _parse_bytes(data: bytes, limits: EmailLimits) -> EmailMessage:
    if len(data) > limits.max_message_bytes:
        raise EmailTooLarge(f"message is larger than {limits.max_message_bytes} bytes")
    if data.count(b"\n--") > limits.max_parts * BOUNDARY_LINES_FACTOR:
        raise EmailParseError("message has too many MIME parts")
    try:
        msg = BytesParser(policy=_POLICY).parsebytes(data)
    except RecursionError as exc:
        raise EmailParseError("message nesting is too deep") from exc
    except Exception as exc:  # noqa: BLE001 - the stdlib parser is lenient; anything it raises is a malformed message
        raise EmailParseError(f"message could not be parsed ({type(exc).__name__})") from exc
    if not isinstance(msg, EmailMessage):
        raise EmailParseError("message could not be parsed")
    return msg


def _auth(headers: Mapping[str, List[str]], limits: EmailLimits) -> Dict[str, Any]:
    results = [parse_authentication_results(v) for v in headers.get("authentication-results", [])[: limits.max_auth_results]]
    out: Dict[str, Any] = {"results": results}
    spf = _first(headers, "received-spf")
    if spf:
        out["received_spf"] = parse_received_spf(spf)
    return out


def _received(headers: Mapping[str, List[str]], limits: EmailLimits, trusted: Sequence[IPNetwork]) -> Dict[str, Any]:
    values = headers.get("received", [])
    hops = [parse_received(v) for v in values[: limits.max_received]]
    relay = relay_hop(hops, trusted)
    out: Dict[str, Any] = {"hops": len(values), "chain": hops}
    if relay is not None:
        out["relay_ip"] = relay.get("ip")
        if relay.get("from"):
            out["relay_host"] = relay["from"]
    return out


def _dedup_key(message_id: Optional[str], reporter: Optional[str], fallback: Iterable[str]) -> str:
    if message_id:
        material = f"mid\x00{message_id.strip().lower()}\x00{(reporter or '').lower()}"
    else:
        material = "content\x00" + "\x00".join(fallback) + f"\x00{(reporter or '').lower()}"
    return "email:" + hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()


def parse_email(
    data: bytes,
    *,
    limits: Optional[EmailLimits] = None,
    reporter: Optional[str] = None,
    received_at: Optional[datetime] = None,
    trusted_relays: Sequence[IPNetwork] = (),
    transport: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """The email document for ``data`` (see the module docs). Raises :class:`EmailParseError`.

    ``received_at`` is when the platform (or the mailbox it reads) received
    the report; it becomes the alert's ``occurred_at``. ``transport`` holds
    small, trusted facts from the source (for example the mailbox message id).
    """
    limits = limits or EmailLimits()
    outer = _parse_bytes(data, limits)
    flags: Set[str] = set()
    outer_headers = _raw_headers(outer, limits, flags)
    inner = _embedded_message(outer, limits)
    report: Dict[str, Any] = {"wrapped": inner is not None}
    envelope_reporter: Optional[str] = None
    if inner is not None:
        senders = _addresses("from", _first(outer_headers, "from") or "", 1)
        envelope_reporter = senders[0]["address"] if senders and senders[0]["address"] else None
        report["envelope_subject"] = _clean_text(_decoded("subject", _first(outer_headers, "subject") or ""), 256)
        msg: Message = inner
        headers = _raw_headers(inner, limits, flags)
    else:
        msg = outer
        headers = outer_headers
    chosen = (reporter or "").strip().lower() or envelope_reporter
    if chosen:
        report["reporter"] = chosen[:MAX_ADDRESS_CHARS]
        report["reporter_source"] = "param" if reporter else "envelope"

    scan = _Scan(limits=limits, flags=flags)
    _walk(scan, msg, 0, top=True)

    from_list = _addresses("from", _first(headers, "from") or "", 1)
    sender = from_list[0] if from_list else {"address": "", "display_name": ""}
    reply_to = _addresses("reply-to", _first(headers, "reply-to") or "", 5)
    # Return-Path holds one address; the "sender" header class parses exactly that shape.
    return_path = _addresses("sender", _first(headers, "return-path") or "", 1)
    to = _address_list("to", headers.get("to", []), limits, scan.flags)
    cc = _address_list("cc", headers.get("cc", []), limits, scan.flags)
    subject = _clean_text(_decoded("subject", _first(headers, "subject") or ""), MAX_SUBJECT_CHARS)
    message_id = _message_id(_first(headers, "message-id"))

    # The HTML text is what the recipient saw (including text hidden with CSS, which the model and the
    # injection checks must see too). A plain-text alternative that says something else is appended:
    # a sender can put different content in each part.
    html_text = _SPACE_RE.sub(" ", " ".join(scan.html_text)).strip()
    plain_text = _SPACE_RE.sub(" ", " ".join(scan.plain)).strip()
    visible = html_text or plain_text
    if html_text and plain_text and plain_text not in html_text:
        visible = f"{html_text} {plain_text}"
    _wording(scan, subject)
    body_hash = hashlib.sha256(visible.encode("utf-8", "surrogatepass")).hexdigest()

    doc: Dict[str, Any] = {
        "schema": SCHEMA,
        "message_id": message_id,
        "subject": subject,
        "date": _date(_first(headers, "date")),
        "from": {**sender, "domain": _domain(sender["address"])},
        "reply_to": reply_to,
        "return_path": return_path[0]["address"] if return_path and return_path[0]["address"] else None,
        "to": [a["address"] for a in to if a["address"]],
        "cc": [a["address"] for a in cc if a["address"]],
        "authentication": _auth(headers, limits),
        "received": _received(headers, limits, trusted_relays),
        "urls": list(scan.urls.values()),
        "url_count": scan.urls_seen,
        "attachments": scan.attachments,
        "attachment_count": scan.attachments_seen,
        "body": {
            "excerpt": visible[: limits.max_body_excerpt_chars],
            "chars": len(visible),
            "sha256": body_hash,
            "html": bool(scan.html_text),
        },
        "credential_wording": list(scan.wording),
        "report": report,
        "received_at": (received_at or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "size": len(data),
        "flags": sorted(scan.flags),
        "dedup_key": _dedup_key(message_id, report.get("reporter"), (sender["address"], subject, body_hash)),
    }
    if transport:
        doc["transport"] = {str(k)[:64]: v for k, v in list(transport.items())[:10]}
    return doc


def unparsed_email(
    reason: str,
    *,
    dedup_key: str,
    received_at: Optional[datetime] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    transport: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """The document for a reported message that could not be analysed (too large, malformed).

    Pull sources still turn it into an alert, so a report is never dropped
    silently; ``metadata`` holds what the mailbox API said about the message.
    """
    meta = dict(metadata or {})
    doc: Dict[str, Any] = {
        "schema": SCHEMA,
        "parse_error": reason[:200],
        "message_id": _message_id(str(meta.get("message_id") or "")) if meta.get("message_id") else None,
        "subject": _clean_text(str(meta.get("subject") or ""), MAX_SUBJECT_CHARS),
        "from": {"address": "", "display_name": "", "domain": None},
        "report": {"wrapped": False},
        "received_at": (received_at or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "flags": ["unparsed"],
        "dedup_key": dedup_key,
    }
    sender = str(meta.get("from") or "").strip().lower()
    if _ADDR_SPEC_RE.match(sender):
        doc["from"] = {"address": sender, "display_name": "", "domain": _domain(sender)}
    reporter = str(meta.get("reporter") or "").strip().lower()
    if _ADDR_SPEC_RE.match(reporter):
        doc["report"] = {"wrapped": False, "reporter": reporter, "reporter_source": "envelope"}
    if transport:
        doc["transport"] = {str(k)[:64]: v for k, v in list(transport.items())[:10]}
    return doc
