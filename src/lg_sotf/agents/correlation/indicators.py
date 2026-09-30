"""Indicator extraction for correlation.

Only low-cardinality indicator types are indexed: ``ip``, ``domain``, ``url``,
``hash``, ``user``, ``host`` and ``process``. They come from the canonical
alert's ``entities`` and from a fixed list of well-known raw field names,
never from arbitrary scalar fields. Every value is syntax-checked and the
number of indicators per type and per alert is capped.

The reporter of a user-reported email (``alert["email"]["reporter"]``, kept in
``entities.users``) is context, not an indicator: every report from the same
person would otherwise correlate as one campaign, and response planning would
target the person who reported the threat.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from lg_sotf.security.hashing import normalize_indicator
from lg_sotf.security.redaction import redact_text

INDICATOR_TYPES = ("ip", "domain", "url", "hash", "user", "host", "process")
MAX_PER_TYPE = 10
MAX_TOTAL = 50
MAX_VALUE_CHARS = 512
DISPLAY_CHARS = 128

ENTITY_KEYS: Dict[str, str] = {
    "ips": "ip",
    "domains": "domain",
    "urls": "url",
    "hashes": "hash",
    "users": "user",
    "hosts": "host",
    "processes": "process",
}
RAW_FIELDS: Dict[str, str] = {
    "source_ip": "ip",
    "src_ip": "ip",
    "destination_ip": "ip",
    "dest_ip": "ip",
    "dst_ip": "ip",
    "domain": "domain",
    "url": "url",
    "file_hash": "hash",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "user": "user",
    "username": "user",
    "hostname": "host",
    "host": "host",
    "process_name": "process",
}

_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$")
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str

    @property
    def display(self) -> str:
        text, _ = redact_text(self.value)
        return text[:DISPLAY_CHARS]


def _valid(itype: str, value: str) -> bool:
    if itype == "ip":
        try:
            ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            return False
        return True
    if itype == "hash":
        return bool(_HASH_RE.match(value))
    if itype == "domain":
        return bool(_DOMAIN_RE.match(value))
    if itype == "url":
        try:
            parts = urlsplit(value)
        except ValueError:
            return False
        return parts.scheme in ("http", "https", "ftp") and bool(parts.netloc)
    return bool(_NAME_RE.match(value))


def _values(item: Any) -> Iterable[Any]:
    if isinstance(item, (list, tuple)):
        return item
    return [item]


def _scalar(item: Any) -> Optional[str]:
    if isinstance(item, Mapping):
        item = item.get("value", item.get("name"))
    if isinstance(item, (str, int)) and not isinstance(item, bool):
        text = str(item).strip()
        return text if 0 < len(text) <= MAX_VALUE_CHARS else None
    return None


def extract_indicators(alert: Mapping[str, Any]) -> List[Indicator]:
    """Deduplicated, validated indicators in a stable order."""
    candidates: List[Tuple[str, Any]] = []
    email = alert.get("email")
    reporter = email.get("reporter") if isinstance(email, Mapping) else None
    entities = alert.get("entities")
    if isinstance(entities, Mapping):
        for key, itype in ENTITY_KEYS.items():
            for item in _values(entities.get(key) or []):
                if itype == "user" and isinstance(reporter, str) and isinstance(item, str) and item.lower() == reporter:
                    continue
                candidates.append((itype, item))
    raw = alert.get("raw")
    if isinstance(raw, Mapping):
        sources = [raw]
        nested = raw.get("raw_data")
        if isinstance(nested, Mapping):
            sources.append(nested)
        for source in sources:
            for key, itype in RAW_FIELDS.items():
                if key in source:
                    for item in _values(source[key]):
                        candidates.append((itype, item))

    seen: set[Tuple[str, str]] = set()
    per_type: Dict[str, int] = {}
    out: List[Indicator] = []
    for itype, item in candidates:
        value = _scalar(item)
        if value is None or value.upper() in ("N/A", "NONE", "NULL", "-") or not _valid(itype, value):
            continue
        seen_key = (itype, normalize_indicator(itype, value))
        if seen_key in seen or per_type.get(itype, 0) >= MAX_PER_TYPE:
            continue
        seen.add(seen_key)
        per_type[itype] = per_type.get(itype, 0) + 1
        out.append(Indicator(itype, value))
        if len(out) >= MAX_TOTAL:
            break
    return out


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return ip.is_global
