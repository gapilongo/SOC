"""App-only access tokens from the Microsoft identity platform (OAuth 2.0 client credentials).

``POST https://{login_host}/{directory_tenant_id}/oauth2/v2.0/token``
(form-encoded, ``grant_type=client_credentials``), one token per (cloud,
directory, client, API) with the scope ``<resource>/.default`` of
:class:`~lg_sotf.integrations.microsoft.clouds.CloudProfile`.

Credentials
    * ``client_secret``: sent as the ``client_secret`` form field.
    * certificate (recommended by Microsoft): ``client_assertion_type=
      urn:ietf:params:oauth:client-assertion-type:jwt-bearer`` and a
      ``client_assertion`` JWT signed with the private key: ``alg=PS256``,
      headers ``typ=JWT``, ``x5t`` (base64url SHA-1 of the certificate's
      DER) **and** ``x5t#S256`` (base64url SHA-256; RFC 7515 allows both and
      Microsoft sources disagree on which one Entra reads), claims ``aud`` =
      the exact token URL, ``iss`` = ``sub`` = the client id, a fresh
      ``jti``, ``nbf`` = ``iat`` = now and ``exp`` = now + 300 s.

Cache (in memory, one :class:`TokenProvider` per process)
    * keyed by (LG-SOTF tenant, integration id, credential fingerprint,
      cloud, directory, client id, API): a token is never reused for another
      tenant's integration, and rotating the credential changes the key;
    * refreshed ``min(300, expires_in / 4)`` seconds before it expires;
    * one fetch in flight per key; LRU of ``max_entries`` keys;
    * ``invalid_client``, ``unauthorized_client`` and ``invalid_grant``
      failures are remembered for 60 s, so a broken credential cannot
      hammer the token endpoint (Microsoft throttles that as AADSTS50196).

Errors branch on the OAuth ``error`` field only (Microsoft: never on
``error_description`` or AADSTS numbers); AADSTS codes only choose the
operator hint:

=========================================  ===============================
OAuth ``error``                            ledger error
=========================================  ===============================
``invalid_client``, ``invalid_grant``      ``credentials_invalid``
``unauthorized_client``,                   ``app_not_in_tenant``
``invalid_resource``
``invalid_scope``                          ``consent_missing``
``interaction_required``                   ``conditional_access_blocked``
``temporarily_unavailable``, 429, 5xx,     ``token_unavailable`` (retryable)
network errors
=========================================  ===============================

``trace_id`` and ``correlation_id`` are kept for Microsoft support;
``error_description`` and ``error_uri`` are never stored. Tokens, secrets
and assertions never appear in logs, errors or results.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Tuple
from uuid import UUID

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.sources.http import parse_retry_after
from lg_sotf.integrations.microsoft.clouds import Api, CloudProfile
from lg_sotf.integrations.microsoft.http import MicrosoftApiError, MicrosoftHttpFactory
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_LIFETIME_S = 300
NEGATIVE_CACHE_S = 60.0
MAX_REFRESH_MARGIN_S = 300.0
MIN_TOKEN_TTL_S = 30.0
NEGATIVE_CACHED_ERRORS = frozenset({"invalid_client", "unauthorized_client", "invalid_grant"})
LEDGER_ERRORS: Mapping[str, str] = {
    "invalid_client": "credentials_invalid",
    "invalid_grant": "credentials_invalid",
    "unauthorized_client": "app_not_in_tenant",
    "invalid_resource": "app_not_in_tenant",
    "invalid_scope": "consent_missing",
    "interaction_required": "conditional_access_blocked",
    "temporarily_unavailable": "token_unavailable",
}
# AADSTS numbers choose the operator hint only (Microsoft: never branch on them).
AADSTS_HINTS: Mapping[int, str] = {
    7000215: "the client secret is wrong: paste the secret's value (not its id) from the app registration",
    7000222: "the client secret has expired: add a new one, or better, switch to a certificate",
    700027: "the client assertion was rejected: upload this certificate to the app registration "
            "(Certificates & secrets) and check it is the one configured here",
    700024: "the client assertion is outside its valid time range: check this server's clock and the "
            "certificate's validity",
    50012: "authentication failed: the certificate or its thumbprint is not accepted for this app",
    700016: "the app is not found in this directory: check the directory (tenant) id and the cloud, and that an "
            "administrator consented to the app in this directory",
    7000229: "the app has no service principal in this directory: an administrator must consent to it",
    90002: "the directory was not found: check the directory (tenant) id and the cloud (tokens are not "
           "interchangeable between clouds)",
    65001: "admin consent is missing: an administrator must grant consent for the app's application permissions",
    90094: "admin consent is required: an administrator must grant consent for the app's application permissions",
    650056: "the app is misconfigured or admin consent is missing: grant admin consent after adding permissions",
    53003: "Conditional Access blocked the app: exclude this workload identity or allow its sign-in location",
    530032: "a security policy blocked the app's sign-in",
    50196: "Microsoft Entra ID is throttling token requests for this app (too many requests); retry later",
    90055: "Microsoft Entra ID is throttling this directory; retry later",
}
DEFAULT_HINTS: Mapping[str, str] = {
    "credentials_invalid": "the app's credential was rejected: check the client id, the secret or the certificate",
    "app_not_in_tenant": "the app is not registered or consented in this directory, or the cloud is wrong",
    "consent_missing": "admin consent is missing for the requested API",
    "conditional_access_blocked": "Conditional Access requires an interaction the app cannot perform",
    "token_unavailable": "Microsoft Entra ID did not issue a token right now; retry later",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, repr=False)
class AppCredentials:
    """One integration's app registration and credential. ``__repr__`` never shows the secret or the key.

    ``fingerprint`` is ``sha256(secret ciphertext)[:16]``: it changes when the
    credential is rotated, which invalidates cached tokens.
    """

    lg_tenant_id: str
    integration_id: UUID
    cloud: CloudProfile
    directory_tenant_id: str
    client_id: str
    fingerprint: str
    client_secret: Optional[str] = None
    private_key_pem: Optional[str] = None
    certificate_pem: Optional[str] = None
    defender_geo: Optional[str] = None

    def __repr__(self) -> str:
        return (
            f"AppCredentials(tenant={self.lg_tenant_id!r}, integration={self.integration_id}, cloud={self.cloud.name!r}, "
            f"client_id={self.client_id!r}, credential={self.credential!r})"
        )

    __str__ = __repr__

    @property
    def credential(self) -> str:
        return "certificate" if self.private_key_pem else "client_secret"

    @property
    def token_url(self) -> str:
        return self.cloud.token_url(self.directory_tenant_id)


def fingerprint_of(ciphertext: Optional[str]) -> str:
    """The credential fingerprint of a stored secret ciphertext."""
    return hashlib.sha256((ciphertext or "").encode("utf-8")).hexdigest()[:16]


def certificate_thumbprints(certificate_pem: str) -> Tuple[str, str]:
    """(``x5t``, ``x5t#S256``): base64url SHA-1 and SHA-256 of the certificate's DER encoding."""
    der = x509.load_pem_x509_certificate(certificate_pem.encode("ascii")).public_bytes(serialization.Encoding.DER)
    # x5t is SHA-1 by definition (RFC 7515); it identifies the certificate, it protects nothing.
    return _b64url(hashlib.sha1(der, usedforsecurity=False).digest()), _b64url(hashlib.sha256(der).digest())


def client_assertion(creds: AppCredentials, *, now: Optional[float] = None) -> str:
    """The signed ``client_assertion`` JWT (PS256) for a certificate credential."""
    if not creds.private_key_pem or not creds.certificate_pem:
        raise ValueError("a certificate credential needs the certificate and its private key")
    key = serialization.load_pem_private_key(creds.private_key_pem.encode("ascii"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("the private key must be an RSA key")
    sha1, sha256 = certificate_thumbprints(creds.certificate_pem)
    issued = int(time.time() if now is None else now)
    claims = {
        "aud": creds.token_url,
        "iss": creds.client_id,
        "sub": creds.client_id,
        "jti": str(uuid.uuid4()),
        "nbf": issued,
        "iat": issued,
        "exp": issued + ASSERTION_LIFETIME_S,
    }
    return jwt.encode(claims, key, algorithm="PS256", headers={"typ": "JWT", "x5t": sha1, "x5t#S256": sha256})


class MicrosoftAuthError(MicrosoftApiError):
    """A token could not be obtained. ``ledger_error`` is the ledger code; ``hint`` is for the operator."""

    def __init__(
        self,
        ledger_error: str,
        *,
        oauth_error: str = "",
        aadsts: Optional[int] = None,
        hint: str = "",
        trace_id: str = "",
        correlation_id: str = "",
        status: int = 0,
        retryable: bool = False,
        retry_after_s: Optional[float] = None,
    ) -> None:
        detail = f" ({oauth_error})" if oauth_error else ""
        suffix = f" AADSTS{aadsts}" if aadsts else ""
        super().__init__(
            "auth",
            f"Microsoft sign-in failed: {ledger_error}{detail}{suffix}",
            status=status,
            code=oauth_error,
            request_id=trace_id,
            retry_after_s=retry_after_s,
            retryable=retryable,
        )
        self.auth_error = ledger_error
        self.oauth_error = oauth_error
        self.aadsts = aadsts
        self.hint = (hint or AADSTS_HINTS.get(aadsts or 0) or DEFAULT_HINTS.get(ledger_error, ""))[:300]
        self.trace_id = trace_id[:64]
        self.correlation_id = correlation_id[:64]

    @property
    def ledger_error(self) -> str:
        return self.auth_error

    def copy(self) -> MicrosoftAuthError:
        return MicrosoftAuthError(
            self.auth_error, oauth_error=self.oauth_error, aadsts=self.aadsts, hint=self.hint, trace_id=self.trace_id,
            correlation_id=self.correlation_id, status=self.status, retryable=self.retryable,
            retry_after_s=self.retry_after_s,
        )


def _auth_error(status: int, body: Any, retry_after: Optional[float]) -> MicrosoftAuthError:
    data = body if isinstance(body, Mapping) else {}
    oauth_error = str(data.get("error") or "")[:64]
    codes = data.get("error_codes")
    aadsts = next((c for c in codes if isinstance(c, int)), None) if isinstance(codes, list) else None
    trace_id = str(data.get("trace_id") or "")[:64]
    correlation_id = str(data.get("correlation_id") or "")[:64]
    if status == 429 or status >= 500 or oauth_error == "temporarily_unavailable":
        return MicrosoftAuthError(
            "token_unavailable", oauth_error=oauth_error, aadsts=aadsts, trace_id=trace_id,
            correlation_id=correlation_id, status=status, retryable=True, retry_after_s=retry_after,
        )
    ledger = LEDGER_ERRORS.get(oauth_error, "credentials_invalid" if oauth_error else "token_unavailable")
    return MicrosoftAuthError(
        ledger, oauth_error=oauth_error, aadsts=aadsts, trace_id=trace_id, correlation_id=correlation_id,
        status=status, retryable=ledger == "token_unavailable",
    )


@dataclass
class _Token:
    value: str
    refresh_at: float
    expires_at: float


@dataclass
class _Failure:
    error: MicrosoftAuthError
    until: float


CacheKey = Tuple[str, str, str, str, str, str, str]


class TokenProvider:
    """In-memory app token cache and client (one per process). See the module docstring."""

    def __init__(
        self,
        http: MicrosoftHttpFactory,
        *,
        max_entries: int = 1024,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._http = http
        self._max = max(1, max_entries)
        self._clock = clock
        self._wall = wall_clock
        self._cache: OrderedDict[CacheKey, Any] = OrderedDict()
        self._inflight: Dict[CacheKey, asyncio.Task[str]] = {}

    @staticmethod
    def key(creds: AppCredentials, api: Api) -> CacheKey:
        return (
            creds.lg_tenant_id, str(creds.integration_id), creds.fingerprint, creds.cloud.name,
            creds.directory_tenant_id.lower(), creds.client_id.lower(), api,
        )

    def invalidate(self, creds: AppCredentials, api: Api) -> None:
        self._cache.pop(self.key(creds, api), None)

    def roles(self, token: str) -> Optional[FrozenSet[str]]:
        """The ``roles`` claim of an app token (diagnostics only: the token is not validated)."""
        try:
            payload = token.split(".")[1]
            data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (IndexError, ValueError, TypeError):
            return None
        roles = data.get("roles") if isinstance(data, dict) else None
        if roles is None:
            return frozenset()
        if not isinstance(roles, list):
            return None
        return frozenset(str(r) for r in roles if isinstance(r, str))

    async def token(self, creds: AppCredentials, api: Api, *, deadline: float) -> str:
        """A valid access token for ``api``; raises :class:`MicrosoftAuthError` (or ``deadline``)."""
        key = self.key(creds, api)
        now = self._clock()
        cached = self._cache.get(key)
        if isinstance(cached, _Token) and now < cached.refresh_at:
            self._cache.move_to_end(key)
            return cached.value
        if isinstance(cached, _Failure):
            if now < cached.until:
                raise cached.error.copy()
            self._cache.pop(key, None)
        task = self._inflight.get(key)
        if task is None:
            task = asyncio.create_task(self._fetch(key, creds, api, deadline))
            self._inflight[key] = task
            task.add_done_callback(self._fetched(key))
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(max(0.1, deadline - loop.time())):
                return await asyncio.shield(task)
        except TimeoutError:
            if isinstance(cached, _Token) and self._clock() < cached.expires_at - MIN_TOKEN_TTL_S:
                return cached.value  # the refresh is late; the current token is still valid
            raise MicrosoftAuthError(
                "token_unavailable", hint="no token before the deadline", retryable=True
            ) from None

    def _fetched(self, key: CacheKey) -> Callable[[asyncio.Task[str]], None]:
        def done(task: asyncio.Task[str]) -> None:
            self._inflight.pop(key, None)
            if not task.cancelled():
                task.exception()  # retrieved: a caller that gave up on its deadline must not leave it unobserved

        return done

    def _store(self, key: CacheKey, value: Any) -> None:
        self._cache[key] = value
        self._cache.move_to_end(key)
        while len(self._cache) > self._max:
            self._cache.popitem(last=False)

    async def _fetch(self, key: CacheKey, creds: AppCredentials, api: Api, deadline: float) -> str:
        form: Dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": creds.client_id,
            "scope": creds.cloud.scope(api),
        }
        loop = asyncio.get_running_loop()
        attempt = 0
        while True:
            if creds.private_key_pem:
                try:
                    form["client_assertion_type"] = ASSERTION_TYPE
                    form["client_assertion"] = client_assertion(creds, now=self._wall())
                except (ValueError, TypeError) as exc:
                    error = MicrosoftAuthError(
                        "credentials_invalid", hint="the stored certificate or private key cannot be used"
                    )
                    self._store(key, _Failure(error, self._clock() + NEGATIVE_CACHE_S))
                    raise error from exc
            elif creds.client_secret:
                form["client_secret"] = creds.client_secret
            else:
                raise MicrosoftAuthError("credentials_invalid", hint="no client secret or certificate is configured")
            remaining = deadline - loop.time()
            if remaining < 0.5:
                raise MicrosoftAuthError("token_unavailable", hint="no token before the deadline", retryable=True)
            try:
                status, body, headers = await self._http.post_form(
                    creds.token_url, form, timeout_s=max(0.1, min(self._http.timeout_s, remaining))
                )
            except SourceConfigError:
                raise MicrosoftAuthError(
                    "token_unavailable", hint="the sign-in host was refused by the network policy"
                ) from None
            except (httpx.TransportError, TimeoutError) as exc:
                wait = self._http.backoff(attempt)
                if attempt < self._http.retries and loop.time() + wait + 0.5 < deadline:
                    await self._http.sleep(wait)
                    attempt += 1
                    continue
                log.warning("microsoft.token_network_error", error_type=type(exc).__name__)
                raise MicrosoftAuthError(
                    "token_unavailable", hint="the sign-in endpoint could not be reached", retryable=True
                ) from None
            if status == 200 and isinstance(body, Mapping) and isinstance(body.get("access_token"), str):
                return self._accept(key, body)
            retry_after = parse_retry_after(headers.get("Retry-After"))
            error = _auth_error(status, body, retry_after)
            log.warning(
                "microsoft.token_failed", http_status=status, oauth_error=error.oauth_error, aadsts=error.aadsts,
                ledger_error=error.auth_error, trace_id=error.trace_id, api=api,
            )
            if error.retryable and attempt < self._http.retries:
                wait = retry_after if retry_after is not None else self._http.backoff(attempt)
                if loop.time() + wait + 0.5 < deadline:
                    await self._http.sleep(wait)
                    attempt += 1
                    continue
            if error.oauth_error in NEGATIVE_CACHED_ERRORS:
                self._store(key, _Failure(error, self._clock() + NEGATIVE_CACHE_S))
            raise error

    def _accept(self, key: CacheKey, body: Mapping[str, Any]) -> str:
        token = str(body["access_token"])
        try:
            expires_in = float(body.get("expires_in", 3599))
        except (TypeError, ValueError):
            expires_in = 3599.0
        expires_in = max(MIN_TOKEN_TTL_S, expires_in)
        now = self._clock()
        margin = min(MAX_REFRESH_MARGIN_S, expires_in / 4)
        self._store(key, _Token(token, now + expires_in - margin, now + expires_in))
        return token


__all__ = [
    "AADSTS_HINTS",
    "ASSERTION_TYPE",
    "AppCredentials",
    "MicrosoftAuthError",
    "TokenProvider",
    "certificate_thumbprints",
    "client_assertion",
    "fingerprint_of",
]
