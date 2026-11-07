"""Response targets: syntax, IP classes and the comparison forms of names (standard library only).

:func:`validate_target` checks a target's syntax for its kind and
:func:`ip_block_class` whether an address is a sensible block target (also
when an IPv6 address embeds an IPv4 one). Hosts, users, domains and
processes are compared in every spelling a target may take
(:func:`host_forms`, :func:`user_forms`, :func:`domain_key`,
:func:`process_forms`): Unicode NFKC, invisible format characters removed,
case-folded (:func:`clean`). :func:`parse_address` and :func:`url_hosts`
read IP literals and URL hosts the way network stacks and browsers do.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import FrozenSet, List, Optional, Tuple, Union
from urllib.parse import unquote, urlsplit

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$")
_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?=.{1,253}$)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")
_MESSAGE_ID_RE = re.compile(r"^<?[\x21-\x3b\x3d\x3f-\x7e]{1,995}>?$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")

# Operating-system and security-agent processes no response ever terminates, whatever the
# tenant configured: killing them crashes or blinds the host, and malware routinely borrows
# their names (an implant called lsass.exe in a Temp folder is still named lsass.exe).
# Compared by base name, NFKC-normalised and case-folded, with and without ".exe".
CRITICAL_PROCESSES: FrozenSet[str] = frozenset(
    {
        "system", "system idle process", "registry", "memory compression", "secure system",
        "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsaiso", "svchost", "explorer",
        "dwm", "fontdrvhost", "spoolsv", "taskhostw", "sihost", "ctfmon", "conhost", "userinit",
        "msmpeng", "mssense", "sensecncproxy", "nissrv", "securityhealthservice", "senseir",
        "csfalconservice", "csfalconcontainer", "sentinelagent", "sentinelservicehost", "cbdefense", "repmgr",
        "cylancesvc", "xagt", "elastic-agent", "elastic-endpoint", "osqueryd", "sysmon", "sysmon64",
        "init", "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "kthreadd", "sshd", "dbus-daemon",
        "launchd", "kernel_task", "windowserver", "loginwindow", "falcon-sensor", "auditd",
    }
)


def target_key(kind: str, value: str) -> Tuple[str, ...]:
    """Comparison forms of a target, so evidence and plan targets match whatever their spelling."""
    if kind == "process":
        return (process_base(value),)
    if kind == "host":
        return host_forms(value)
    if kind == "user":
        return user_forms(value)
    if kind == "domain":
        return (domain_key(value),)
    if kind == "ip":
        address = parse_address(value)
        return (str(address),) if address is not None else (clean(value),)
    if kind == "message":
        return (value.strip(),)
    return (clean(value),)


def target_corroborated(kind: str, value: str, corroborated: FrozenSet[Tuple[str, str]]) -> bool:
    keys = {(k, form) for k, v in corroborated for form in target_key(k, v)}
    return any((kind, form) in keys for form in target_key(kind, value))


def validate_target(kind: str, target: str) -> Optional[str]:
    """Syntax only: ``None`` when the target is well formed for its kind, otherwise the reason code."""
    if not target or len(target) > 2_048:
        return "invalid_target"
    if kind == "ip":
        try:
            ipaddress.ip_address(target.strip("[]"))
        except ValueError:
            return "invalid_ip"
        return None
    if kind == "domain":
        return None if _DOMAIN_RE.match(target.lower().rstrip(".")) else "invalid_domain"
    if kind == "url":
        try:
            parts = urlsplit(target)
            host = parts.hostname
        except ValueError:
            return "invalid_url"
        return None if parts.scheme in ("http", "https") and host else "invalid_url"
    if kind == "hash":
        return None if _HASH_RE.match(target.lower()) else "invalid_hash"
    if kind == "host":
        return None if _HOST_RE.match(target) else "invalid_host"
    if kind in ("user", "process"):
        return None if _NAME_RE.match(target) else f"invalid_{kind}"
    if kind == "email":
        return None if _EMAIL_RE.match(target.lower()) else "invalid_email"
    if kind == "message":
        return None if _MESSAGE_ID_RE.match(target) else "invalid_message"
    if kind == "alert":
        return None if target.startswith("alert:") else "invalid_target"
    return "invalid_target"


_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_PREFIX = ipaddress.IPv6Network("64:ff9b:1::/48")
# Characters URL parsers (WHATWG/UTS 46) treat as a label separator in host names.
_DOT_EQUIVALENTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_CLASS_RANK = {"public": 0, "internal": 1, "unroutable": 2}

_DN_VALUE_RE = re.compile(r"^(?:cn|uid)\s*=\s*((?:\\.|[^,+\\])+)")
_DN_ESCAPE_RE = re.compile(r"\\(.)")


def embedded_ipv4(address: IPAddress) -> List[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 address carries (6to4, Teredo client, NAT64 well-known prefix, IPv4-compatible)."""
    if not isinstance(address, ipaddress.IPv6Address):
        return []
    out: List[ipaddress.IPv4Address] = []
    if address.sixtofour is not None:
        out.append(address.sixtofour)
    if address.teredo is not None:
        out.append(address.teredo[1])
    value = int(address)
    if address in _NAT64_PREFIX:
        out.append(ipaddress.IPv4Address(value & 0xFFFFFFFF))
    if address in _NAT64_LOCAL_PREFIX:
        # RFC 8215 local-use prefix 64:ff9b:1::/48 with the RFC 6052 /48 layout: the IPv4
        # address sits in bits 48-63 and 72-87 (bits 64-71 are the reserved "u" octet).
        # Some translators put it in the low 32 bits instead; both readings are checked.
        packed = address.packed
        out.append(ipaddress.IPv4Address(packed[6:8] + packed[9:11]))
        out.append(ipaddress.IPv4Address(value & 0xFFFFFFFF))
    if value >> 32 == 0 and value > 1:
        out.append(ipaddress.IPv4Address(value))
    return out


def _single_class(address: IPAddress) -> str:
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return "unroutable"
    return "public" if address.is_global else "internal"


def ip_block_class(address: IPAddress) -> str:
    """``public``, ``internal`` (private/CGNAT/ULA) or ``unroutable`` (never a sensible block target).

    An IPv4-mapped address is classified as its IPv4 address; any other IPv6
    address that embeds an IPv4 address takes the stricter of the two classes.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _single_class(address.ipv4_mapped)
    classes = [_single_class(a) for a in (address, *embedded_ipv4(address))]
    return max(classes, key=_CLASS_RANK.__getitem__)


def _ipv4_part(part: str) -> Optional[int]:
    if part[:2] in ("0x", "0X"):
        digits, base, allowed = part[2:], 16, "0123456789abcdefABCDEF"
        if not digits:
            return 0
    elif len(part) > 1 and part.startswith("0"):
        digits, base, allowed = part[1:], 8, "01234567"
    else:
        digits, base, allowed = part, 10, "0123456789"
    if not digits or len(digits) > 32 or any(ch not in allowed for ch in digits):
        return None
    return int(digits, base)


def loose_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 address a browser or curl connects to for a numeric host, else ``None``.

    Follows the WHATWG URL IPv4 parser: one to four dot-separated parts, each
    decimal, ``0x`` hex or ``0``-prefixed octal, the last part filling the
    remaining bytes (``3405803781``, ``0xcb.0.113.5`` and ``203.28933``
    are all ``203.0.113.5``).
    """
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts = parts[:-1]
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    numbers = [_ipv4_part(p) for p in parts]
    if any(n is None for n in numbers):
        return None
    values = [int(n) for n in numbers if n is not None]
    *head, last = values
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(values)):
        return None
    address = last
    for index, number in enumerate(head):
        address += number << (8 * (3 - index))
    return ipaddress.IPv4Address(address)


def parse_address(text: str) -> Optional[IPAddress]:
    """An IP literal in any spelling a network stack accepts (brackets, zone ids, numeric IPv4 forms)."""
    candidate = text.strip().strip("[]").split("%", 1)[0]
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return loose_ipv4(candidate)


def clean(text: str) -> str:
    """Compare form of a name: NFKC, invisible format characters removed, trimmed, lowercased."""
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in normalized if unicodedata.category(ch) != "Cf").strip().lower()


def _short_host(name: str) -> str:
    return name.split(".", 1)[0]


def host_forms(name: str) -> Tuple[str, ...]:
    cleaned = clean(name).rstrip(".")
    return tuple(dict.fromkeys((cleaned, _short_host(cleaned))))


def domain_key(name: str) -> str:
    cleaned = clean(name).strip(".")
    try:
        return cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return cleaned


def user_forms(name: str) -> Tuple[str, ...]:
    """An account as written, as the CN/UID of a DN, and as the bare account name.

    ``DOMAIN\\user``, ``domain/user``, ``user@domain`` and
    ``CN=user,OU=...,DC=...`` all also compare as ``user``.
    """
    cleaned = clean(name)
    match = _DN_VALUE_RE.match(cleaned)
    base = _DN_ESCAPE_RE.sub(r"\1", match.group(1)).strip() if match else cleaned
    bare = base.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].split("@", 1)[0].strip()
    return tuple(dict.fromkeys(f for f in (cleaned, base, bare) if f))


def process_base(name: str) -> str:
    """Compare form of a process's base name (``C:\\x\\LSASS.EXE`` -> ``lsass.exe``)."""
    return re.split(r"[\\/]", clean(name).strip("\"'"))[-1].strip()


def process_forms(name: str) -> Tuple[str, ...]:
    """A process as written, its base name and the base name without ``.exe``."""
    cleaned = clean(name).strip("\"'")
    base = process_base(name)
    stem = base[:-4] if base.endswith(".exe") else base
    return tuple(dict.fromkeys(f for f in (cleaned, base, stem) if f))


def critical_process(name: str) -> bool:
    """Whether ``name`` (any path, case or Unicode spelling) is a built-in never-terminate process."""
    return any(form in CRITICAL_PROCESSES for form in process_forms(name))


def canonical_host(host: str) -> str:
    """A URL host the way browsers and proxies resolve it: percent-decoded, NFKC (full-width
    digits and letters to ASCII), ideographic/full-width dots to ``.``, invisible format
    characters removed, lowercased."""
    decoded = unquote(host).translate(_DOT_EQUIVALENTS)
    return clean(decoded).translate(_DOT_EQUIVALENTS).rstrip(".")


def url_hosts(target: str) -> List[str]:
    """Every host a client could connect to for ``target``: Python's reading of the URL and the
    WHATWG one (``\\`` is a path separator in http(s) URLs, so ``http://1.2.3.4\\@evil.com/``
    goes to 1.2.3.4), each in its literal and canonical form."""
    text = target.strip()
    hosts: List[str] = []
    candidates = [text]
    if "\\" in text and text.lower().startswith(("http:", "https:")):
        candidates.append(text.replace("\\", "/"))
    for candidate in candidates:
        try:
            host = urlsplit(candidate).hostname or ""
        except ValueError:
            continue
        if host:
            hosts += [unquote(host), canonical_host(host)]
    return list(dict.fromkeys(h for h in hosts if h))
