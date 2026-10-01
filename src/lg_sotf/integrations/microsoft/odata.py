"""Validating and encoding untrusted targets for Microsoft Graph and Defender requests.

Every value that comes from an alert or the ledger (a user principal name, a
host name, a Message-ID, an indicator) reaches a Microsoft URL only through
this module: it is first checked against the format of its kind, then
encoded for the place it goes to. Handlers never build paths or filters by
string concatenation of raw input.

* Path segments: :func:`segment` percent-encodes everything outside the
  RFC 3986 unreserved set (``quote(value, safe="")``) and refuses ``.`` and
  ``..``; :func:`user_path` builds the three shapes Graph accepts for a user.
* Filter literals: :func:`odata_string` doubles embedded single quotes and
  wraps the value in quotes; :func:`odata_eq` combines it with a field from
  :data:`ALLOWED_FILTER_FIELDS`. DateTimeOffset values go unquoted
  (:func:`graph_datetime`). The finished ``$filter`` text is passed raw to
  :meth:`~lg_sotf.integrations.microsoft.http.MicrosoftApi.request`, which
  percent-encodes query values exactly once (``+`` -> ``%2B``, ``'`` ->
  ``%27``, ``#`` -> ``%23``, ``&`` -> ``%26``, ``%`` -> ``%25``). Never
  pre-encode.

Every helper raises :class:`InvalidTarget` with ``code`` ``invalid_target``
(malformed for its kind) or ``unsupported_target`` (well formed, but not
something the Microsoft API can act on, e.g. a ``DOMAIN\\sam`` account or a
SHA-512 hash). Both are ledger ``result.error`` codes.

A connector package that needs another filter field adds it here through the
framework (it is an allowlist on purpose).
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Dict, FrozenSet, Literal, Tuple, Union
from urllib.parse import quote, urlsplit

TargetError = Literal["invalid_target", "unsupported_target"]
HashType = Literal["FileSha1", "FileSha256", "FileMd5"]

MAX_LITERAL_CHARS = 1_024
MAX_EMAIL_CHARS = 320
MAX_MESSAGE_ID_CHARS = 998
MAX_URL_CHARS = 2_048

# Fields handlers may filter on (mail, Entra, Defender). Anything else is refused.
ALLOWED_FILTER_FIELDS: FrozenSet[str] = frozenset(
    {
        # Microsoft Graph mail
        "internetMessageId",
        "messageId",
        "receivedDateTime",
        # Microsoft Entra ID
        "userPrincipalName",
        "mail",
        "proxyAddresses",
        "principalId",
        # Defender for Endpoint
        "computerDnsName",
        "machineId",
        "type",
        "indicatorValue",
        "indicatorType",
    }
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LOCAL = r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}"
_DOMAIN = r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_EMAIL = re.compile(rf"^{_LOCAL}@{_DOMAIN}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MESSAGE_ID = re.compile(r"^<[\x21-\x3b\x3d\x3f-\x7e]+@[\x21-\x3b\x3d\x3f-\x7e]+>$")
_HEX = re.compile(r"^[0-9a-f]+$")
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")


class InvalidTarget(ValueError):
    """A target cannot be sent to Microsoft; ``code`` is the ledger error code (message is safe to store)."""

    def __init__(self, code: TargetError, message: str) -> None:
        super().__init__(message[:300])
        self.code: TargetError = code


def _text(value: object, *, what: str, limit: int = MAX_LITERAL_CHARS) -> str:
    if not isinstance(value, str):
        raise InvalidTarget("invalid_target", f"{what} must be text")
    if not value or len(value) > limit:
        raise InvalidTarget("invalid_target", f"{what} must be 1-{limit} characters")
    if _CONTROL.search(value):
        raise InvalidTarget("invalid_target", f"{what} contains control characters")
    return value


def odata_string(value: str) -> str:
    """An OData string literal: ``'`` + value with ``'`` doubled + ``'`` (control characters and > 1024 chars refused)."""
    text = _text(value, what="filter value")
    return "'" + text.replace("'", "''") + "'"


def graph_datetime(dt: datetime) -> str:
    """A DateTimeOffset for ``$filter`` (unquoted): ``2026-09-30T00:00:00Z``; ``dt`` must be timezone-aware."""
    if not isinstance(dt, datetime) or dt.tzinfo is None:
        raise InvalidTarget("invalid_target", "timestamps in filters must be timezone-aware")
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _field(field: str) -> str:
    if field not in ALLOWED_FILTER_FIELDS or not _FIELD.match(field):
        raise ValueError(f"filter field {str(field)[:64]!r} is not allowed (see ALLOWED_FILTER_FIELDS)")
    return field


def odata_eq(field: str, value: Union[str, datetime]) -> str:
    """``field eq 'value'`` for an allowed field; a ``datetime`` value is written unquoted.

    An unknown field is a programming error (``ValueError``), not a target error.
    """
    name = _field(field)
    literal = graph_datetime(value) if isinstance(value, datetime) else odata_string(value)
    return f"{name} eq {literal}"


def odata_any_eq(field: str, value: str) -> str:
    """``field/any(x:x eq 'value')`` for a collection field (e.g. ``proxyAddresses``)."""
    return f"{_field(field)}/any(x:x eq {odata_string(value)})"


def segment(value: str) -> str:
    """One URL path segment: ``quote(value, safe="")``; empty, ``.``, ``..`` and control characters refused."""
    text = _text(value, what="path segment")
    if text in (".", ".."):
        raise InvalidTarget("invalid_target", "path segment may not be . or ..")
    return quote(text, safe="")


def is_guid(value: str) -> bool:
    return isinstance(value, str) and bool(_GUID.match(value))


def email_address(value: str) -> str:
    """A mailbox address, lower-cased (RFC 5321-ish: ASCII local part and domain, at most 320 characters)."""
    text = _text(value, what="email address", limit=MAX_EMAIL_CHARS).strip().lower()
    if not _EMAIL.match(text):
        raise InvalidTarget("invalid_target", "not an email address")
    return text


def upn(value: str) -> str:
    """A user principal name (``user@domain``). ``DOMAIN\\sam`` and bare account names are ``unsupported_target``."""
    text = _text(value, what="user principal name", limit=MAX_EMAIL_CHARS).strip()
    if "\\" in text or "@" not in text:
        raise InvalidTarget(
            "unsupported_target", "the account is not a user principal name (user@domain); Graph cannot resolve it"
        )
    if not _EMAIL.match(text):
        raise InvalidTarget("invalid_target", "not a valid user principal name")
    return text


def user_path(user: str) -> str:
    """The Graph path of a user: ``/v1.0/users/{object id}`` or ``/v1.0/users/{upn}``.

    A UPN starting with ``$`` uses the key syntax Graph requires for it,
    ``/v1.0/users('{upn}')`` (quotes doubled, then percent-encoded).
    """
    if is_guid(user):
        return f"/v1.0/users/{user.lower()}"
    name = upn(user)
    if name.startswith("$"):
        return f"/v1.0/users('{quote(name.replace(chr(39), chr(39) * 2), safe='')}')"
    return f"/v1.0/users/{segment(name)}"


def internet_message_id(value: str) -> str:
    """An Internet Message-ID as ``<local@domain>`` (brackets added when missing; at most 998 characters)."""
    text = _text(value, what="Message-ID", limit=MAX_MESSAGE_ID_CHARS).strip()
    if not text.startswith("<"):
        text = f"<{text}>"
    if len(text) > MAX_MESSAGE_ID_CHARS or not _MESSAGE_ID.match(text):
        raise InvalidTarget("invalid_target", "not an Internet Message-ID (<local@domain>)")
    return text


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True


def hostname(value: str) -> str:
    """A host name (fully qualified or a single label, RFC 1123), lower-cased, trailing dot removed.

    IP addresses are ``unsupported_target`` (machines are looked up by name).
    """
    text = _text(value, what="host name", limit=253).strip().lower().rstrip(".")
    if _is_ip(text):
        raise InvalidTarget("unsupported_target", "an IP address is not a host name")
    labels = text.split(".")
    if not text or len(text) > 253 or not all(_LABEL.match(label) for label in labels):
        raise InvalidTarget("invalid_target", "not a valid host name")
    return text


def domain(value: str) -> str:
    """A DNS domain (at least two labels), lower-cased and IDNA-encoded."""
    text = _text(value, what="domain", limit=253).strip().lower().rstrip(".")
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTarget("invalid_target", "not a valid domain name") from exc
    labels = ascii_name.split(".")
    if len(labels) < 2 or len(ascii_name) > 253 or not all(_LABEL.match(label) for label in labels):
        raise InvalidTarget("invalid_target", "not a valid domain name")
    if _is_ip(ascii_name):
        raise InvalidTarget("invalid_target", "an IP address is not a domain")
    return ascii_name


def public_ip(value: str) -> str:
    """One global IPv4 or IPv6 address (no CIDR); non-global addresses are unsupported.

    IPv4 in dotted form; IPv6 in its full eight-group form
    (``2606:4700:4700:0000:0000:0000:0000:1111``): Defender for Endpoint
    needs all eight segments in an IP indicator, so ``::`` is never sent.
    """
    text = _text(value, what="IP address", limit=64).strip().strip("[]")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise InvalidTarget("invalid_target", "not a single IP address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not address.is_global:
        raise InvalidTarget("unsupported_target", "only public IP addresses can be blocked in Defender")
    return address.exploded if isinstance(address, ipaddress.IPv6Address) else address.compressed


def http_url(value: str) -> str:
    """An ``http``/``https`` URL with a host and no credentials (at most 2048 characters, no whitespace)."""
    text = _text(value, what="URL", limit=MAX_URL_CHARS).strip()
    if any(ch.isspace() for ch in text):
        raise InvalidTarget("invalid_target", "a URL may not contain whitespace")
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError as exc:
        raise InvalidTarget("invalid_target", "not a valid URL") from exc
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise InvalidTarget("invalid_target", "not an http(s) URL with a host")
    if parts.username or parts.password:
        raise InvalidTarget("invalid_target", "a URL with credentials is not accepted")
    return text


def file_hash(value: str) -> Tuple[HashType, str]:
    """(``FileSha1`` | ``FileSha256`` | ``FileMd5``, lower-case hex); SHA-512 is ``unsupported_target``."""
    text = _text(value, what="file hash", limit=128).strip().lower()
    if not _HEX.match(text):
        raise InvalidTarget("invalid_target", "not a hexadecimal file hash")
    kinds: Dict[int, HashType] = {40: "FileSha1", 64: "FileSha256", 32: "FileMd5"}
    kind = kinds.get(len(text))
    if kind is None:
        if len(text) == 128:
            raise InvalidTarget("unsupported_target", "Defender indicators do not support SHA-512 hashes")
        raise InvalidTarget("invalid_target", "not an MD5, SHA-1 or SHA-256 hash")
    return kind, text


__all__ = [
    "ALLOWED_FILTER_FIELDS",
    "HashType",
    "InvalidTarget",
    "TargetError",
    "domain",
    "email_address",
    "file_hash",
    "graph_datetime",
    "hostname",
    "http_url",
    "internet_message_id",
    "is_guid",
    "odata_any_eq",
    "odata_eq",
    "odata_string",
    "public_ip",
    "segment",
    "upn",
    "user_path",
]
