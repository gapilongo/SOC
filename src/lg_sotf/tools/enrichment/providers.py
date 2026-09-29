"""Threat-intelligence providers: VirusTotal (hash/ip/domain/url) and AbuseIPDB (ip).

Both need only configuration: an API key per tenant (``tenants.settings``,
encrypted) or per install (``settings.tools``). Before anything is sent to a
third party the indicator is validated and reduced:

* IPs must be globally routable; private, loopback, link-local and other
  internal addresses are never sent (``skipped``).
* Domains must be syntactically valid, multi-label and not under an
  internal suffix (``.local``, ``.internal``, ``.corp`` ...).
* URLs are reduced to ``scheme://host/path``: user info, query string and
  fragment (where tokens and personal data usually live) are dropped, and
  the host must itself be public. A URL whose path carries a segment that
  looks like a secret (a long token-like run: password-reset and share
  links, signed paths, session ids) is not sent at all; its domain can
  still be looked up on its own.
* Hashes must be MD5, SHA-1 or SHA-256 hex.

The enrichment service adds the tenant's own internal domains to these
rules (see :mod:`lg_sotf.tools.enrichment.service`).
"""

from __future__ import annotations

import base64
import ipaddress
import math
import re
from datetime import UTC, datetime
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import httpx

from lg_sotf.tools.enrichment.base import EnrichmentResult, LookupRequest, Verdict
from lg_sotf.tools.enrichment.http import (
    DEFAULT_RETRY_AFTER_S,
    DEFAULT_TIMEOUT_S,
    JsonHttpClient,
    ProviderHTTPError,
    as_int,
    as_mapping,
    validate_base_url,
)

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
# URL path segments: token-like runs of at least MIN_TOKEN_CHARS characters.
MIN_TOKEN_CHARS = 16
_TOKEN_RUN_RE = re.compile(rf"[A-Za-z0-9_\-+=~]{{{MIN_TOKEN_CHARS},}}")
_HEX_RUN_RE = re.compile(rf"[0-9a-fA-F]{{{MIN_TOKEN_CHARS},}}")
_LOWER_RE = re.compile(r"[a-z]")
_UPPER_RE = re.compile(r"[A-Z]")
_DIGIT_RE = re.compile(r"[0-9]")
INTERNAL_SUFFIXES: Tuple[str, ...] = (
    ".local", ".localdomain", ".internal", ".intranet", ".corp", ".home", ".lan", ".localhost", ".test",
    ".invalid", ".example", ".arpa", ".home.arpa",
)


def public_ip(value: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return True


def public_domain(value: str) -> Optional[str]:
    """A syntactically valid, multi-label, non-internal domain name (never an IP literal)."""
    domain = value.strip().rstrip(".").lower()
    if not _DOMAIN_RE.match(domain) or domain.endswith(INTERNAL_SUFFIXES) or _is_ip_literal(domain):
        return None
    return domain


def _entropy_bits(text: str) -> float:
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def secret_like_segment(segment: str) -> bool:
    """Whether a (percent-decoded) URL path segment looks like a token rather than a name.

    Long runs of token characters that mix letter case and digits, long hex
    runs (ids, signatures, digests), or long high-entropy strings.
    """
    text = unquote(segment)
    for run in _TOKEN_RUN_RE.findall(text):
        if _HEX_RUN_RE.fullmatch(run):
            return True
        classes = sum(1 for pattern in (_LOWER_RE, _UPPER_RE, _DIGIT_RE) if pattern.search(run))
        if classes >= 3 or (classes == 2 and _DIGIT_RE.search(run)) or _entropy_bits(run) >= 4.0:
            return True
    return False


def public_url(value: str) -> Optional[str]:
    """``scheme://host[:port]/path`` for a public http(s) URL without secret-looking path segments, else None."""
    try:
        parts = urlsplit(value.strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    if (public_ip(host) if _is_ip_literal(host) else public_domain(host)) is None:
        return None
    if any(secret_like_segment(segment) for segment in parts.path.split("/") if segment):
        return None
    netloc = host if port is None else f"{host}:{port}"
    if ":" in host:
        netloc = f"[{host}]" if port is None else f"[{host}]:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", "", ""))


def normal_hash(value: str) -> Optional[str]:
    text = value.strip().lower()
    return text if _HASH_RE.match(text) else None


def _epoch_iso(value: Any) -> Optional[str]:
    seconds = as_int(value)
    if seconds is None or seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=UTC).date().isoformat()
    except (OverflowError, OSError, ValueError):
        return None


class _HttpProvider:
    name = "http"
    kinds: FrozenSet[str] = frozenset()
    external = True
    default_base_url = ""
    default_rpm = 60
    default_ttl_s = 3_600.0

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        production: bool = False,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        cfg = dict(config or {})
        self.base_url = validate_base_url(str(cfg.get("base_url") or self.default_base_url), production=production)
        self.requests_per_minute = int(cfg.get("requests_per_minute", self.default_rpm))
        self.cache_ttl_s = float(cfg.get("cache_ttl_s", self.default_ttl_s))
        ca_bundle = cfg.get("ca_bundle")
        self.http = JsonHttpClient(
            self.name,
            timeout_s=float(cfg.get("timeout_s", DEFAULT_TIMEOUT_S)),
            verify=str(ca_bundle) if ca_bundle else True,
            transport=transport,
        )
        self.config = cfg

    def requires_credentials(self) -> bool:
        return True

    async def aclose(self) -> None:
        await self.http.aclose()

    def _status_result(self, kind: str, status: int, retry_after: Optional[float]) -> Optional[EnrichmentResult]:
        """Common handling for non-200 statuses; None means "parse the body"."""
        if status == 200:
            return None
        if status == 404:
            return EnrichmentResult(self.name, kind, "not_found", "unknown")
        if status == 429:
            return EnrichmentResult.failed(
                self.name, kind, "rate_limited", "provider rate limit", retry_after or DEFAULT_RETRY_AFTER_S
            )
        if status in (401, 403):
            return EnrichmentResult.failed(self.name, kind, "error", f"authentication failed (HTTP {status})")
        if status >= 500:
            return EnrichmentResult.failed(self.name, kind, "error", f"provider unavailable (HTTP {status})", retry_after)
        return EnrichmentResult.failed(self.name, kind, "error", f"unexpected HTTP {status}")


class VirusTotalProvider(_HttpProvider):
    """VirusTotal API v3 lookups (``x-apikey`` header)."""

    name = "virustotal"
    kinds = frozenset({"ip", "domain", "url", "hash"})
    default_base_url = "https://www.virustotal.com/api/v3"
    default_rpm = 4  # public API quota; raise it for premium keys
    default_ttl_s = 3_600.0

    def __init__(self, config: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)
        self.malicious_threshold = int(self.config.get("malicious_threshold", 3))

    @staticmethod
    def resource(kind: str, value: str) -> Optional[str]:
        if kind == "hash":
            h = normal_hash(value)
            return f"files/{h}" if h else None
        if kind == "ip":
            ip = public_ip(value)
            return f"ip_addresses/{quote(ip, safe='')}" if ip else None
        if kind == "domain":
            d = public_domain(value)
            return f"domains/{d}" if d else None
        if kind == "url":
            u = public_url(value)
            if u is None:
                return None
            return "urls/" + base64.urlsafe_b64encode(u.encode("utf-8")).decode("ascii").rstrip("=")
        return None

    def verdict(self, malicious: int, suspicious: int, harmless: int) -> Verdict:
        if malicious >= self.malicious_threshold:
            return "malicious"
        if malicious >= 1 or suspicious >= 2:
            return "suspicious"
        if harmless > 0:
            return "harmless"
        return "unknown"

    async def lookup(self, request: LookupRequest) -> EnrichmentResult:
        if request.kind not in self.kinds:
            return EnrichmentResult.failed(self.name, request.kind, "unsupported")
        if request.credentials is None:
            return EnrichmentResult.failed(self.name, request.kind, "not_configured")
        path = self.resource(request.kind, request.value)
        if path is None:
            return EnrichmentResult.failed(self.name, request.kind, "skipped", "not a public indicator")
        try:
            response = await self.http.get_json(
                f"{self.base_url}/{path}", headers={"x-apikey": request.credentials.api_key}
            )
        except ProviderHTTPError as exc:
            return EnrichmentResult.failed(self.name, request.kind, "error", str(exc))
        failed = self._status_result(request.kind, response.status, response.retry_after_s)
        if failed is not None:
            return failed
        attributes = as_mapping(as_mapping(as_mapping(response.body).get("data")).get("attributes"))
        if not attributes:
            return EnrichmentResult.failed(self.name, request.kind, "error", "unexpected response shape")
        stats = as_mapping(attributes.get("last_analysis_stats"))
        malicious = as_int(stats.get("malicious")) or 0
        suspicious = as_int(stats.get("suspicious")) or 0
        harmless = as_int(stats.get("harmless")) or 0
        data: Dict[str, Any] = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": as_int(stats.get("undetected")) or 0,
            "reputation": as_int(attributes.get("reputation")),
            "last_analysis": _epoch_iso(attributes.get("last_analysis_date")),
        }
        if request.kind == "hash":
            classification = as_mapping(attributes.get("popular_threat_classification"))
            data["threat_label"] = classification.get("suggested_threat_label")
            data["type"] = attributes.get("type_description")
            data["first_seen"] = _epoch_iso(attributes.get("first_submission_date"))
        elif request.kind == "ip":
            data["country"] = attributes.get("country")
            data["asn"] = as_int(attributes.get("asn"))
            data["as_owner"] = attributes.get("as_owner")
        elif request.kind == "domain":
            data["registrar"] = attributes.get("registrar")
            data["created"] = _epoch_iso(attributes.get("creation_date"))
        tags = attributes.get("tags")
        if isinstance(tags, list):
            data["tags"] = [str(t) for t in tags[:5]]
        clean = {k: v for k, v in data.items() if v is not None}
        return EnrichmentResult.ok(self.name, request.kind, self.verdict(malicious, suspicious, harmless), clean)


class AbuseIPDBProvider(_HttpProvider):
    """AbuseIPDB API v2 ``/check`` (``Key`` header)."""

    name = "abuseipdb"
    kinds = frozenset({"ip"})
    default_base_url = "https://api.abuseipdb.com/api/v2"
    default_rpm = 60
    default_ttl_s = 1_800.0

    def __init__(self, config: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)
        self.max_age_days = max(1, min(365, int(self.config.get("max_age_days", 90))))
        self.malicious_threshold = int(self.config.get("malicious_threshold", 75))
        self.suspicious_threshold = int(self.config.get("suspicious_threshold", 25))

    def verdict(self, score: int, whitelisted: bool) -> Verdict:
        if whitelisted:
            return "harmless"
        if score >= self.malicious_threshold:
            return "malicious"
        if score >= self.suspicious_threshold:
            return "suspicious"
        return "unknown"

    async def lookup(self, request: LookupRequest) -> EnrichmentResult:
        if request.kind not in self.kinds:
            return EnrichmentResult.failed(self.name, request.kind, "unsupported")
        if request.credentials is None:
            return EnrichmentResult.failed(self.name, request.kind, "not_configured")
        ip = public_ip(request.value)
        if ip is None:
            return EnrichmentResult.failed(self.name, request.kind, "skipped", "not a public indicator")
        try:
            response = await self.http.get_json(
                f"{self.base_url}/check",
                headers={"Key": request.credentials.api_key},
                params={"ipAddress": ip, "maxAgeInDays": self.max_age_days},
            )
        except ProviderHTTPError as exc:
            return EnrichmentResult.failed(self.name, request.kind, "error", str(exc))
        failed = self._status_result(request.kind, response.status, response.retry_after_s)
        if failed is not None:
            return failed
        body = as_mapping(as_mapping(response.body).get("data"))
        score = as_int(body.get("abuseConfidenceScore"))
        if score is None:
            return EnrichmentResult.failed(self.name, request.kind, "error", "unexpected response shape")
        whitelisted = body.get("isWhitelisted") is True
        data = {
            "abuse_score": score,
            "reports": as_int(body.get("totalReports")) or 0,
            "distinct_reporters": as_int(body.get("numDistinctUsers")) or 0,
            "last_reported": str(body.get("lastReportedAt"))[:10] if body.get("lastReportedAt") else None,
            "country": body.get("countryCode"),
            "usage_type": body.get("usageType"),
            "is_tor": body.get("isTor") if isinstance(body.get("isTor"), bool) else None,
            "whitelisted": whitelisted,
        }
        clean = {k: v for k, v in data.items() if v is not None}
        return EnrichmentResult.ok(self.name, request.kind, self.verdict(score, whitelisted), clean)
