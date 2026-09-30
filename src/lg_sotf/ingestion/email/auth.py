"""Authentication-Results (RFC 8601), Received-SPF and Received header parsing.

Authentication-Results headers are prepended by each receiving server, so
the first one is the closest to the mailbox. A sender can put forged
``Authentication-Results`` headers in its message, below the ones the
receiving servers add; this module records every header (top first, capped)
with its ``authserv-id`` and leaves the choice of which one to trust to the
triage policy (the topmost one, or the first one from a tenant's configured
``trusted_authserv_ids``).

Microsoft 365 writes ``Authentication-Results`` without an ``authserv-id``
(``spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=...``); such headers are
parsed with ``authserv_id`` ``None``.

The relay IP is the first address outside internal networks (RFC 1918,
CGNAT, unique-local, loopback, link-local), reading the ``Received`` chain
from the top, that is not in the caller's trusted relay networks: the
server that handed the message to your infrastructure. Every ``Received``
line below that one is written by servers you do not control and is
recorded but never trusted.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

AUTH_METHODS = ("spf", "dkim", "dmarc", "arc", "compauth")
RESULT_VALUES = frozenset(
    {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "hardfail", "bestguesspass"}
)
MAX_SEGMENTS = 40
MAX_DKIM_DOMAINS = 5
MAX_VALUE_CHARS = 255
_COMMENT_RE = re.compile(r"\([^()]*\)")
_CLIENT_IP_RES = (
    re.compile(r"(?i)sender\s+ip\s+is\s+\[?([0-9a-f:.]{3,45})\]?"),
    re.compile(r"(?i)client-ip=\[?([0-9a-f:.]{3,45})\]?"),
    re.compile(r"(?i)designates\s+\[?([0-9a-f:.]{3,45})\]?\s+as\s+permitted"),
    re.compile(r"(?i)smtp\.remote-ip=\[?([0-9a-f:.]{3,45})\]?"),
)
_PROPERTY_RE = re.compile(r"(?i)\b([a-z]+\.[a-z0-9_-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)")
_METHOD_RE = re.compile(r"(?i)^\s*([a-z][a-z0-9_-]*)(?:/\d+)?\s*=\s*([a-z]+)")
_RECEIVED_IP_RE = re.compile(r"\[(?:ipv6:)?([0-9a-fA-F:.]{3,45})\]|\(([0-9a-fA-F:.]{3,45})\)", re.IGNORECASE)
_RECEIVED_BARE_IP_RE = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3})(?![\w.:])")
_RECEIVED_FROM_RE = re.compile(r"(?i)^\s*from\s+([^\s;()]{1,255})")
_RECEIVED_BY_RE = re.compile(r"(?i)\bby\s+([^\s;()]{1,255})")


def _address(value: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def _strip_comments(text: str) -> str:
    """Remove (possibly nested) parenthesised comments; bounded by the header length cap."""
    for _ in range(8):
        stripped = _COMMENT_RE.sub(" ", text)
        if stripped == text:
            break
        text = stripped
    return text


def _domain_of(value: str) -> Optional[str]:
    text = value.strip().strip('"').strip("<>").lower()
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = text.strip(".")
    return text[:MAX_VALUE_CHARS] or None


def parse_authentication_results(value: str) -> Dict[str, Any]:
    """One ``Authentication-Results`` header as ``{"authserv_id", "spf", "dkim", "dmarc", ...}``.

    Results are lowercased; ``dkim`` is ``pass`` when any signature passed
    (``dkim_domains`` lists their ``header.d``), otherwise the first result.
    """
    client_ip: Optional[str] = None
    for pattern in _CLIENT_IP_RES:
        match = pattern.search(value)
        if match and _address(match.group(1)) is not None:
            client_ip = str(_address(match.group(1)))
            break
    segments = [s.strip() for s in _strip_comments(value).split(";")][:MAX_SEGMENTS]
    out: Dict[str, Any] = {"authserv_id": None}
    if segments and segments[0] and not _METHOD_RE.match(segments[0]):
        first = segments.pop(0).split()
        out["authserv_id"] = first[0].lower()[:MAX_VALUE_CHARS] if first else None
    dkim_results: List[str] = []
    dkim_domains: List[str] = []
    for segment in segments:
        match = _METHOD_RE.match(segment)
        if not match:
            continue
        method, result = match.group(1).lower(), match.group(2).lower()
        if method not in AUTH_METHODS or result not in RESULT_VALUES:
            continue
        props = {k.lower(): v.strip('"') for k, v in _PROPERTY_RE.findall(segment)}
        if method == "dkim":
            dkim_results.append(result)
            domain = props.get("header.d") or props.get("header.i")
            if result == "pass" and domain and len(dkim_domains) < MAX_DKIM_DOMAINS:
                d = _domain_of(domain)
                if d and d not in dkim_domains:
                    dkim_domains.append(d)
            continue
        if method in out:
            continue
        out[method] = result
        if method == "spf":
            mailfrom = props.get("smtp.mailfrom") or props.get("smtp.helo")
            if mailfrom:
                out["smtp_mailfrom"] = _domain_of(mailfrom)
        elif method == "dmarc":
            header_from = props.get("header.from")
            if header_from:
                out["header_from"] = _domain_of(header_from)
    if dkim_results:
        out["dkim"] = "pass" if "pass" in dkim_results else dkim_results[0]
        if dkim_domains:
            out["dkim_domains"] = dkim_domains
    if client_ip:
        out["client_ip"] = client_ip
    return out


def parse_received_spf(value: str) -> Dict[str, Any]:
    """``Received-SPF: pass (...) client-ip=192.0.2.1; envelope-from=...``."""
    match = re.match(r"\s*([a-z]+)", value, re.IGNORECASE)
    result = match.group(1).lower() if match else None
    out: Dict[str, Any] = {"result": result if result in RESULT_VALUES else None}
    for pattern in _CLIENT_IP_RES:
        found = pattern.search(value)
        if found and _address(found.group(1)) is not None:
            out["client_ip"] = str(_address(found.group(1)))
            break
    return out


def parse_received(value: str) -> Dict[str, Any]:
    """``{"from": helo, "ip": first address of the from-clause, "by": host}`` of one ``Received`` header."""
    text = " ".join(value.split())
    head = text.split(";", 1)[0]
    by_at = re.search(r"(?i)\sby\s", head)
    from_clause = head[: by_at.start()] if by_at else head
    hop: Dict[str, Any] = {}
    match = _RECEIVED_FROM_RE.match(from_clause)
    if match:
        hop["from"] = match.group(1).lower()[:MAX_VALUE_CHARS]
    by = _RECEIVED_BY_RE.search(head)
    if by:
        hop["by"] = by.group(1).lower()[:MAX_VALUE_CHARS]
    for found in _RECEIVED_IP_RE.finditer(from_clause):
        address = _address(found.group(1) or found.group(2))
        if address is not None:
            hop["ip"] = str(address)
            break
    else:
        bare = _RECEIVED_BARE_IP_RE.search(from_clause)
        if bare and _address(bare.group(1)) is not None:
            hop["ip"] = str(_address(bare.group(1)))
    return hop


_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def internal_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback, link-local, multicast, unspecified, RFC 1918, CGNAT or unique-local: a hop inside a network."""
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        return True
    return any(address.version == net.version and address in net for net in _INTERNAL_NETWORKS)


def relay_hop(hops: Sequence[Dict[str, Any]], trusted: Sequence[IPNetwork] = ()) -> Optional[Dict[str, Any]]:
    """The first hop (top down) whose sending address is neither internal nor in ``trusted`` networks."""
    for hop in hops:
        address = _address(str(hop.get("ip") or ""))
        if address is None:
            continue
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if internal_address(address):
            continue
        if any(address.version == net.version and address in net for net in trusted):
            continue
        return hop
    return None


def parse_networks(values: Any, limit: int = 64) -> List[IPNetwork]:
    """CIDR strings to networks; invalid entries raise ``ValueError`` (configuration errors)."""
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > limit:
        raise ValueError(f"must be a list of at most {limit} CIDR networks")
    out: List[IPNetwork] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("networks must be CIDR strings")
        out.append(ipaddress.ip_network(value.strip(), strict=False))
    return out
