"""Deterministic, validated entity and MITRE extraction.

Normalizers feed candidate values into an :class:`EntityCollector`; each
``add_*`` method accepts a scalar or a list, validates every value and drops
what does not parse (counted in :attr:`EntityCollector.dropped`). Output order
is insertion order, so the same event always yields the same lists.

Work per event is bounded: at most :data:`MAX_SCALARS_PER_FIELD` values are
read from one field, and a kind stops collecting once it holds
``MAX_ENTITY_ITEMS`` values (counted in :attr:`EntityCollector.truncated`),
so a single event with a huge multivalue field cannot stall the event loop.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlsplit

from lg_sotf.models.alert import (
    MAX_COMMAND_LINE_CHARS,
    MAX_ENTITY_CHARS,
    MAX_ENTITY_ITEMS,
    MAX_MITRE_ITEMS,
    MAX_URL_CHARS,
    Entities,
    Mitre,
    strip_nul,
)

_HEX = re.compile(r"^[0-9a-fA-F]+$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@([A-Za-z0-9.-]{1,253})$")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TACTIC_ID = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)
_PLACEHOLDERS = frozenset({"", "-", "--", "n/a", "na", "null", "none", "unknown", "(null)", "nil", "undefined"})
_URL_SCHEMES = frozenset({"http", "https", "ftp", "ftps", "ws", "wss", "smb", "file"})
_SYSMON_HASH = re.compile(r"(?:^|,)\s*(?:MD5|SHA1|SHA256|IMPHASH|SHA384|SHA512)=([0-9A-Fa-f]+)")


MAX_SCALARS_PER_FIELD = 1_000


def _scalars(value: Any, limit: int = MAX_SCALARS_PER_FIELD) -> List[Any]:
    """Scalars of a value or a (one level nested) list, at most ``limit`` of them."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set, frozenset)):
        return [value]
    out: List[Any] = []
    for item in value:
        if isinstance(item, (list, tuple)):
            out.extend(item[: limit - len(out)])
        else:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def _text(value: Any) -> Optional[str]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return None
    text = strip_nul(value).strip()
    if text.lower() in _PLACEHOLDERS:
        return None
    return text


def normalize_ip(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None or len(text) > 64:
        return None
    candidate = text
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.split(":", 1)[0]
    candidate = candidate.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def normalize_hash(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None:
        return None
    if ":" in text and text.split(":", 1)[0].lower() in {"md5", "sha1", "sha256", "sha512", "sha384"}:
        text = text.split(":", 1)[1].strip()
    if len(text) not in HASH_LENGTHS or not _HEX.match(text):
        return None
    lowered = text.lower()
    if set(lowered) == {"0"}:
        return None
    return lowered


def hash_type(value: str) -> Optional[str]:
    return HASH_LENGTHS.get(len(value)) if _HEX.match(value) else None


def normalize_domain(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None or len(text) > 255:
        return None
    text = text.rstrip(".").lower()
    if not text or "." not in text or normalize_ip(text) is not None:
        return None
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_name) > 253:
        return None
    labels = ascii_name.split(".")
    if not all(_DOMAIN_LABEL.match(label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return text


def normalize_url(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None or len(text) > MAX_URL_CHARS or any(ch.isspace() for ch in text):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in _URL_SCHEMES or not parts.netloc or not host:
        return None
    if normalize_domain(host) is None and normalize_ip(host) is None and "." in host:
        return None
    return text


def url_host(url: str) -> Optional[str]:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def normalize_email(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None or len(text) > 320:
        return None
    if text.lower().startswith("mailto:"):
        text = text[7:]
    match = _EMAIL.match(text)
    if match is None or normalize_domain(match.group(1)) is None:
        return None
    return text.lower()


def normalize_host(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None or len(text) > 255 or any(ch.isspace() or ord(ch) < 32 for ch in text):
        return None
    if "/" in text or "@" in text:
        return None
    return text.lower()


def normalize_user(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None or len(text) > 256 or any(ord(ch) < 32 for ch in text):
        return None
    return text


def normalize_process(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None or any(ord(ch) < 32 for ch in text):
        return None
    return text[:MAX_ENTITY_CHARS]


def normalize_command_line(value: Any) -> Optional[str]:
    text = _text(value)
    if text is None:
        return None
    return text[:MAX_COMMAND_LINE_CHARS]


def sysmon_hashes(value: Any) -> List[str]:
    """Hashes from a Sysmon ``Hashes`` string (``SHA256=...,MD5=...``)."""
    text = _text(value)
    if text is None:
        return []
    return [m.group(1) for m in _SYSMON_HASH.finditer(text)]


ENTITY_KINDS = ("hosts", "users", "ips", "domains", "urls", "hashes", "processes", "command_lines", "emails")


class _Bucket:
    """Insertion-ordered unique values with O(1) membership."""

    __slots__ = ("items", "seen")

    def __init__(self) -> None:
        self.items: List[str] = []
        self.seen: Set[str] = set()

    def full(self) -> bool:
        return len(self.items) >= MAX_ENTITY_ITEMS

    def add(self, value: str) -> None:
        if value not in self.seen:
            self.seen.add(value)
            self.items.append(value)


class EntityCollector:
    def __init__(self) -> None:
        self._buckets: Dict[str, _Bucket] = {kind: _Bucket() for kind in ENTITY_KINDS}
        self.dropped = 0
        self.truncated = 0

    @property
    def hosts(self) -> List[str]:
        return self._buckets["hosts"].items

    @property
    def users(self) -> List[str]:
        return self._buckets["users"].items

    @property
    def ips(self) -> List[str]:
        return self._buckets["ips"].items

    @property
    def domains(self) -> List[str]:
        return self._buckets["domains"].items

    @property
    def urls(self) -> List[str]:
        return self._buckets["urls"].items

    @property
    def hashes(self) -> List[str]:
        return self._buckets["hashes"].items

    @property
    def processes(self) -> List[str]:
        return self._buckets["processes"].items

    @property
    def command_lines(self) -> List[str]:
        return self._buckets["command_lines"].items

    @property
    def emails(self) -> List[str]:
        return self._buckets["emails"].items

    def _add(self, kind: str, value: Any, normalize: Callable[[Any], Optional[str]]) -> List[str]:
        """Adds the valid values; returns the ones that were new."""
        bucket = self._buckets[kind]
        added: List[str] = []
        for item in _scalars(value):
            if _text(item) is None:
                continue
            if bucket.full():
                self.truncated += 1
                continue
            normalized = normalize(item)
            if normalized is None:
                self.dropped += 1
            elif normalized not in bucket.seen:
                bucket.add(normalized)
                added.append(normalized)
        return added

    def _add_one(self, kind: str, value: str) -> None:
        bucket = self._buckets[kind]
        if value in bucket.seen:
            return
        if bucket.full():
            self.truncated += 1
            return
        bucket.add(value)

    def add_ip(self, value: Any) -> None:
        self._add("ips", value, normalize_ip)

    def add_hash(self, value: Any) -> None:
        self._add("hashes", value, normalize_hash)

    def add_domain(self, value: Any) -> None:
        self._add("domains", value, normalize_domain)

    def add_url(self, value: Any) -> None:
        for url in self._add("urls", value, normalize_url):
            host = url_host(url)
            if host is None:
                continue
            ip = normalize_ip(host)
            if ip is not None:
                self._add_one("ips", ip)
            else:
                domain = normalize_domain(host)
                if domain is not None:
                    self._add_one("domains", domain)

    def add_email(self, value: Any) -> None:
        self._add("emails", value, normalize_email)

    def add_host(self, value: Any) -> None:
        self._add("hosts", value, normalize_host)

    def add_user(self, value: Any) -> None:
        self._add("users", value, normalize_user)

    def add_process(self, value: Any) -> None:
        self._add("processes", value, normalize_process)

    def add_command_line(self, value: Any) -> None:
        self._add("command_lines", value, normalize_command_line)

    def add_host_or_ip(self, value: Any) -> None:
        """Fields such as Splunk ``src``/``dest`` hold either an address or a host name."""
        for item in _scalars(value):
            if normalize_ip(item) is not None:
                self.add_ip(item)
            else:
                self.add_host(item)

    def add_by_kind(self, kind: str, value: Any) -> None:
        adder = {
            "hosts": self.add_host,
            "users": self.add_user,
            "ips": self.add_ip,
            "domains": self.add_domain,
            "urls": self.add_url,
            "hashes": self.add_hash,
            "processes": self.add_process,
            "command_lines": self.add_command_line,
            "emails": self.add_email,
        }.get(kind)
        if adder is None:
            raise ValueError(f"unknown entity kind {kind!r}")
        adder(value)

    def build(self) -> Entities:
        return Entities(**{kind: list(bucket.items) for kind, bucket in self._buckets.items()})


class MitreCollector:
    """Technique ids (``T1059``/``T1059.001``) are extracted from free text; tactics keep their names."""

    def __init__(self) -> None:
        self.tactics: List[str] = []
        self.techniques: List[str] = []

    def add_technique(self, value: Any) -> None:
        for item in _scalars(value):
            text = _text(item)
            if text is None:
                continue
            for match in _TECHNIQUE.findall(text[:4096]):
                technique = match.upper()
                if len(self.techniques) >= MAX_MITRE_ITEMS:
                    return
                if technique not in self.techniques:
                    self.techniques.append(technique)

    def add_tactic(self, value: Any) -> None:
        for item in _scalars(value):
            text = _text(item)
            if text is None:
                continue
            parts = [p.strip() for p in text.split(",")] if "," in text else [text]
            for part in parts:
                if not part or len(part) > 128:
                    continue
                tactic = part.upper() if _TACTIC_ID.fullmatch(part) else part
                if len(self.tactics) >= MAX_MITRE_ITEMS:
                    return
                if tactic not in self.tactics:
                    self.tactics.append(tactic)

    def build(self) -> Mitre:
        return Mitre(tactics=self.tactics, techniques=self.techniques)
