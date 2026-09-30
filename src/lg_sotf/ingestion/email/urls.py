"""URL facts for reported emails: extraction from text, site comparison, shorteners, defanging.

Only ``http``/``https`` URLs are kept. Nothing here resolves, fetches or
follows a URL. :func:`defang` is for display: stored URLs and entities keep
their original form so indicators still match threat intelligence.

``site`` is an approximation of the registrable domain (the last two labels,
or three under a common two-level public suffix such as ``co.uk``) without
shipping the Public Suffix List; it is only used to compare two hosts.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

__all__ = [
    "MAX_URL_CHARS",
    "SHORTENERS",
    "ascii_host",
    "dedup",
    "defang",
    "ip_host",
    "is_punycode",
    "link_mismatch",
    "shortener",
    "site",
    "site_label",
    "split_url",
    "text_domain",
    "unicode_host",
    "urls_in_text",
]

MAX_URL_CHARS = 2_048
MAX_LINK_TEXT_CHARS = 256
# Characters that end a bare URL in plain text; trailing sentence punctuation is trimmed afterwards.
_TEXT_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'`{}|\\^\[\]]+")
_TRAILING = ".,;:!?)]}'\">"
# A domain (optionally with scheme/path) written as link text, e.g. "www.example.com/login".
_TEXT_DOMAIN_RE = re.compile(
    r"(?i)^\s*(?:https?://)?(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+"
    r"(?:[a-z¡-￿]{2,63}|xn--[a-z0-9-]{1,59})(?::\d{1,5})?(?:[/?#][^\s]*)?\s*$"
)
_NUMERIC_HOST_RE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}\.?$", re.IGNORECASE)

TWO_LEVEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp",
        "co.kr", "or.kr",
        "com.br", "net.br", "org.br",
        "com.cn", "net.cn", "org.cn",
        "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn",
        "co.in", "net.in", "org.in", "co.za", "co.il", "co.id", "or.id", "com.pl", "com.ua",
    }
)

# Well-known URL shortening services (compared on the host without a leading "www.").
SHORTENERS = frozenset(
    {
        "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink", "t.ly", "s.id", "lnkd.in",
        "qrco.de", "x.co", "trib.al", "soo.gd", "clck.ru", "shorte.st", "adf.ly", "bit.do", "mcaf.ee",
        "1url.com", "tr.im", "t2m.io", "short.io", "tinu.be", "u.to", "urlz.fr", "yourls.org", "ln.run",
        "surl.li", "shorturl.com", "gg.gg", "linktr.ee", "snip.ly", "dub.sh", "rotf.lol",
    }
)


def strip_trailing(url: str) -> str:
    """Remove sentence punctuation that followed a URL in running text (keeps balanced parentheses)."""
    while url and url[-1] in _TRAILING:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def urls_in_text(text: str, limit: int) -> Iterator[str]:
    """Absolute http(s) URLs in plain text, in order, at most ``limit`` (duplicates included)."""
    count = 0
    for match in _TEXT_URL_RE.finditer(text):
        url = strip_trailing(match.group(0))
        if url:
            yield url
            count += 1
            if count >= limit:
                return


def split_url(url: str) -> Optional[Tuple[str, str]]:
    """(scheme, lowercase host) of an absolute http(s) URL, else ``None``."""
    if not url or len(url) > MAX_URL_CHARS or any(ch.isspace() or ord(ch) < 32 for ch in url):
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not host:
        return None
    return scheme, host.rstrip(".").lower()


def ascii_host(host: str) -> str:
    """IDNA (punycode) form of a host; the input when it cannot be encoded."""
    if host.isascii():
        return host.lower()
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host.lower()


def unicode_host(host: str) -> str:
    """Unicode form of a punycode host (for homoglyph comparison); the input when it cannot be decoded."""
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split(".")) or not host.isascii()


def ip_host(host: str) -> bool:
    """An IP literal, including the numeric IPv4 spellings browsers accept (``3405803781``, ``0xcb.0.113.5``)."""
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST_RE.match(candidate))


def site(host: str) -> str:
    """Approximate registrable domain of ``host`` (see module docs)."""
    labels = [label for label in ascii_host(host).strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def site_label(host: str) -> str:
    """The distinguishing label of a host's site (``mail.example.co.uk`` -> ``example``)."""
    return site(host).split(".", 1)[0]


def shortener(host: str) -> bool:
    name = host[4:] if host.startswith("www.") else host
    return name in SHORTENERS


def text_domain(text: str) -> Optional[str]:
    """The host written in link text when the text itself looks like a URL or domain name, else ``None``."""
    candidate = text.strip()
    if not candidate or len(candidate) > MAX_LINK_TEXT_CHARS or not _TEXT_DOMAIN_RE.match(candidate):
        return None
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    return host.rstrip(".").lower() if host else None


def link_mismatch(text: str, href_host: str) -> Optional[str]:
    """The domain shown in the link text when it points somewhere other than the href's site."""
    shown = text_domain(text)
    if shown is None or ip_host(shown):
        return None
    return shown if site(shown) != site(href_host) else None


def defang(url: str) -> str:
    """Display form that cannot be clicked or auto-linked: ``hxxps://example[.]com/path``."""
    text = re.sub(r"(?i)^http", "hxxp", url, count=1)
    scheme, sep, rest = text.partition("://")
    if not sep:
        return text.replace(".", "[.]")
    end = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
    return f"{scheme}{sep}{rest[:end].replace('.', '[.]')}{rest[end:]}"


def dedup(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(v for v in values if v))
