"""Webhook connector: an HMAC-signed POST per approved action to the tenant's SOAR.

The receiver (Tracecat, Shuffle, Tines, n8n, or any HTTPS endpoint) performs
the actual containment with its own vendor integrations. LG-SOTF never calls
vendor EDR/firewall/IdP APIs directly.

Request
-------

``POST <webhook_url>`` with ``Content-Type: application/json`` and headers:

=========================  ==============================================================
``Idempotency-Key``        the ledger action id (UUID), the same value as the signed body
                           field ``action.id``. Identical on every retry and on every
                           re-execution of the same action.
``X-LGSOTF-Timestamp``     Unix time (seconds) when this attempt was signed (every retry is
                           signed afresh).
``X-LGSOTF-Signature``     ``v1=<hex>``: HMAC-SHA256 over ``"<timestamp>.<raw body>"``
                           with the shared webhook secret. Verify it with a constant-time
                           comparison and reject timestamps older than 5 minutes
                           (see :func:`verify_signature`).
``X-LGSOTF-Event``         ``response_action.execute``
``X-LGSOTF-Delivery``      a UUID per execution (for receiver-side logs).
=========================  ==============================================================

Deduplication: receivers must deduplicate on the **signed** body field
``action.id`` and treat a repeated id as the same request (answer it with the
original result, do not act twice). The ``Idempotency-Key`` header is a
convenience copy for SOAR platforms that deduplicate on headers; it is not
covered by the signature, so a receiver that uses it must reject a request
whose header differs from ``action.id`` (:func:`verify_request` does both
checks). Otherwise a captured request could be replayed within the timestamp
tolerance under a new key.

Body (``schema`` ``lg-sotf.response-action.v1``; keys are stable, new keys may
be added)::

    {
      "schema": "lg-sotf.response-action.v1",
      "event": "response_action.execute",
      "sent_at": "2026-09-29T12:00:00+00:00",      # first attempt of this execution
      "tenant_id": "acme",
      "action": {
        "id": "7b0c...-uuid",                      # same as Idempotency-Key
        "idempotency_key": "<sha256 hex>",          # (tenant, alert, type, target)
        "type": "block_ip",                        # see ACTION_TARGET_KINDS
        "target": "185.220.101.44",
        "target_type": "ip",                       # ip|domain|url|hash|user|host|process|alert
        "risk_level": "medium",                    # low|medium|high|critical
        "params": {"playbook": "malware", ...},
        "requested_by": "agent:workflow",
        "approved_by": "<user id>|policy:auto",
        "approved_at": "2026-09-29T11:59:00+00:00"
      },
      "alert": {"id": "<alert id>", "severity": "high", "title": "..."}
    }

Response
--------

* ``2xx``: the action was performed (or accepted). An optional JSON object
  body is recorded (capped, redacted); ``{"status": "failed", ...}`` (or
  ``"error"``/``"rejected"``) marks the action failed, anything else succeeded.
  Receivers should answer a repeated ``Idempotency-Key`` with the original
  ``2xx`` response.
* ``429`` / ``5xx`` / network errors: retried with exponential backoff and
  jitter (``Retry-After`` honoured up to ``max_retry_after_s``, 15 s by
  default), then the action fails.
* any other status, or a redirect (redirects are not followed): the action
  fails without retry.

Every execution has a total deadline (``deadline_s``; the registry derives it
from ``worker.node_timeout_s``): no attempt starts, and no retry waits, past
it, and the action then fails with ``error="deadline"``. Each attempt's
request timeout is also cut to the time left.

Transport security: TLS certificates are always verified (a tenant may add a
private CA with ``ca_cert_pem``); the destination is checked and pinned by the
ingestion :class:`~lg_sotf.ingestion.sources.netpolicy.DestinationPolicy`
(https only in staging/production; loopback, link-local and metadata
addresses always refused; private ranges only when the install allows them);
the response body is capped.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Mapping, Optional, Union

import httpx

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.sources.http import Verify, parse_retry_after
from lg_sotf.ingestion.sources.netpolicy import DestinationPolicy, GuardedTransport, Resolver, system_resolve
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.redaction import redact
from lg_sotf.services.connectors.base import ConnectorConfigError, ConnectorResult

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

log = get_logger(__name__)

SCHEMA = "lg-sotf.response-action.v1"
EVENT = "response_action.execute"
USER_AGENT = "lg-sotf-response/1"
SIGNATURE_HEADER = "X-LGSOTF-Signature"
TIMESTAMP_HEADER = "X-LGSOTF-Timestamp"
EVENT_HEADER = "X-LGSOTF-Event"
DELIVERY_HEADER = "X-LGSOTF-Delivery"
IDEMPOTENCY_HEADER = "Idempotency-Key"
SIGNATURE_VERSION = "v1"
DEFAULT_TOLERANCE_S = 300
MIN_SECRET_BYTES = 16
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024
MAX_RECORDED_RESPONSE_CHARS = 2_000
FAILED_BODY_STATUSES = frozenset({"failed", "error", "rejected"})
DEFAULT_DEADLINE_S = 60.0
DEFAULT_MAX_RETRY_AFTER_S = 15.0
# An attempt is only started (or waited for) when at least this much of the deadline is left.
MIN_ATTEMPT_S = 1.0

SleepFn = Callable[[float], Awaitable[None]]


def _secret_bytes(secret: Union[str, bytes]) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)


def sign(secret: Union[str, bytes], timestamp: str, body: bytes) -> str:
    """``v1=<hex>`` HMAC-SHA256 over ``"<timestamp>.<body>"``."""
    mac = hmac.new(_secret_bytes(secret), timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return f"{SIGNATURE_VERSION}={mac.hexdigest()}"


def verify_signature(
    secret: Union[str, bytes],
    timestamp: str,
    body: bytes,
    signature: str,
    *,
    now: Optional[float] = None,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> bool:
    """Receiver-side check (reference implementation): signature matches and the timestamp is fresh."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance_s:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


def verify_request(
    secret: Union[str, bytes],
    headers: Mapping[str, str],
    body: bytes,
    *,
    now: Optional[float] = None,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
) -> Optional[str]:
    """Receiver-side check of a whole request; returns the action id to deduplicate on, or ``None``.

    Verifies the signature and timestamp, and that the (unsigned)
    ``Idempotency-Key`` header, when present, equals the signed body's
    ``action.id``. ``headers`` lookups must be case-insensitive (as in
    ``httpx.Headers`` or most web frameworks).
    """
    timestamp = headers.get(TIMESTAMP_HEADER)
    signature = headers.get(SIGNATURE_HEADER)
    if not timestamp or not signature:
        return None
    if not verify_signature(secret, timestamp, body, signature, now=now, tolerance_s=tolerance_s):
        return None
    payload = _json_object(body)
    action = payload.get("action") if payload is not None else None
    action_id = action.get("id") if isinstance(action, Mapping) else None
    if not isinstance(action_id, str) or not action_id:
        return None
    key = headers.get(IDEMPOTENCY_HEADER)
    if key is not None and not hmac.compare_digest(key.encode("utf-8"), action_id.encode("utf-8")):
        return None
    return action_id


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def build_payload(action: ResponseAction, *, target_type: Optional[str], sent_at: datetime) -> Dict[str, Any]:
    params = {k: v for k, v in dict(action.params).items() if k != "alert"}
    raw_ctx = action.params.get("alert")
    alert_ctx: Mapping[str, Any] = raw_ctx if isinstance(raw_ctx, Mapping) else {}
    return {
        "schema": SCHEMA,
        "event": EVENT,
        "sent_at": sent_at.isoformat(),
        "tenant_id": action.tenant_id,
        "action": {
            "id": str(action.id),
            "idempotency_key": action.idempotency_key,
            "type": action.action_type,
            "target": action.target,
            "target_type": target_type,
            "risk_level": action.risk_level,
            "params": params,
            "requested_by": action.requested_by,
            "approved_by": action.approved_by,
            "approved_at": _iso(action.approved_at),
        },
        "alert": {
            "id": action.alert_id,
            "severity": alert_ctx.get("severity"),
            "title": alert_ctx.get("title"),
        },
    }


def encode_body(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes (what the signature covers)."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")


@dataclass(frozen=True)
class WebhookTarget:
    """Where and how to deliver. ``origin`` is ``tenant`` or ``install`` (for logs and the ledger)."""

    url: str
    secret: bytes = field(repr=False)
    verify: Verify = True
    origin: str = "tenant"

    def __post_init__(self) -> None:
        if len(self.secret) < MIN_SECRET_BYTES:
            raise ConnectorConfigError(f"webhook secret must be at least {MIN_SECRET_BYTES} bytes")


class _ResponseTooLarge(Exception):
    pass


class WebhookConnector:
    """Delivers each action once per execution with retries; see the module docstring for the wire format."""

    name = "webhook"

    def __init__(
        self,
        target: WebhookTarget,
        *,
        policy: DestinationPolicy,
        target_kinds: Optional[Mapping[str, str]] = None,
        timeout_s: float = 15.0,
        connect_timeout_s: float = 5.0,
        max_retries: int = 3,
        backoff_base_s: float = 0.5,
        backoff_max_s: float = 10.0,
        max_retry_after_s: float = DEFAULT_MAX_RETRY_AFTER_S,
        deadline_s: float = DEFAULT_DEADLINE_S,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        resolver: Optional[Resolver] = None,
        sleep: SleepFn = asyncio.sleep,
        rand: Callable[[], float] = random.random,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """``transport`` is a test hook: it is wrapped by the destination policy but not pinned.

        ``deadline_s`` bounds one :meth:`execute` call (all attempts and
        waits); ``clock`` signs the timestamps, ``monotonic`` measures the
        deadline (both test hooks, like ``sleep`` and ``rand``).
        """
        try:
            policy.check_url(target.url)
        except SourceConfigError as exc:
            raise ConnectorConfigError(f"webhook URL rejected: {exc}") from exc
        self._target = target
        self._policy = policy
        self._target_kinds = dict(target_kinds or {})
        self._timeout_s = timeout_s
        self._connect_timeout_s = min(connect_timeout_s, timeout_s)
        self._max_retries = max(0, max_retries)
        self._backoff_base_s = backoff_base_s
        self._backoff_max_s = backoff_max_s
        self._max_retry_after_s = max_retry_after_s
        self._deadline_s = max(MIN_ATTEMPT_S, deadline_s)
        self._max_response_bytes = max_response_bytes
        self._transport = transport
        self._resolver = resolver or system_resolve
        self._sleep = sleep
        self._rand = rand
        self._clock = clock
        self._monotonic = monotonic

    @property
    def origin(self) -> str:
        return self._target.origin

    @property
    def deadline_s(self) -> float:
        return self._deadline_s

    def _client(self) -> httpx.AsyncClient:
        inner = self._transport or httpx.AsyncHTTPTransport(verify=self._target.verify)
        guarded = GuardedTransport(inner, self._policy, self._resolver, pin=self._transport is None)
        return httpx.AsyncClient(
            verify=self._target.verify,
            timeout=httpx.Timeout(self._timeout_s, connect=self._connect_timeout_s),
            transport=guarded,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )

    def _backoff(self, attempt: int) -> float:
        delay = min(self._backoff_max_s, self._backoff_base_s * (2**attempt))
        return delay * (0.5 + self._rand() / 2)

    def _headers(self, action: ResponseAction, body: bytes, delivery: str) -> Dict[str, str]:
        """Headers for one attempt, signed with the current time (a retry is never sent with a stale signature)."""
        timestamp = str(int(self._clock()))
        return {
            "Content-Type": "application/json",
            IDEMPOTENCY_HEADER: str(action.id),
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: sign(self._target.secret, timestamp, body),
            EVENT_HEADER: EVENT,
            DELIVERY_HEADER: delivery,
        }

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        ends_at = self._monotonic() + self._deadline_s
        sent_at = datetime.fromtimestamp(self._clock(), UTC)
        body = encode_body(build_payload(action, target_type=self._target_kinds.get(action.action_type), sent_at=sent_at))
        delivery = str(uuid.uuid4())
        base: Dict[str, Any] = {"connector": self.name, "delivery_id": delivery, "destination": self._target.origin}
        attempt = 0
        async with self._client() as client:
            while True:
                remaining = ends_at - self._monotonic()
                if remaining < MIN_ATTEMPT_S:
                    return self._deadline(action, base, attempt)
                try:
                    status, content = await self._post(
                        client, body, self._headers(action, body, delivery), min(self._timeout_s, remaining)
                    )
                except SourceConfigError:
                    log.warning("response.webhook_destination_refused", action_type=action.action_type)
                    return ConnectorResult("failed", {**base, "error": "destination_refused", "attempts": attempt + 1})
                except _ResponseTooLarge:
                    return ConnectorResult("failed", {**base, "error": "response_too_large", "attempts": attempt + 1})
                except (httpx.TransportError, TimeoutError) as exc:
                    if attempt >= self._max_retries:
                        log.warning(
                            "response.webhook_unreachable", action_type=action.action_type, attempts=attempt + 1,
                            error_type=type(exc).__name__,
                        )
                        return ConnectorResult(
                            "failed", {**base, "error": "network_error", "error_type": type(exc).__name__,
                                       "attempts": attempt + 1},
                        )
                    delay = self._backoff(attempt)
                    if self._monotonic() + delay + MIN_ATTEMPT_S > ends_at:
                        return self._deadline(action, base, attempt + 1, error_type=type(exc).__name__)
                    await self._sleep(delay)
                    attempt += 1
                    continue
                if status == 429 or status >= 500:
                    retry_after = parse_retry_after(content.headers.get("Retry-After"))
                    too_long = retry_after is not None and retry_after > self._max_retry_after_s
                    if attempt >= self._max_retries or too_long:
                        log.warning(
                            "response.webhook_gave_up", action_type=action.action_type, http_status=status,
                            attempts=attempt + 1,
                        )
                        return ConnectorResult(
                            "failed", {**base, "error": "http_status", "http_status": status, "attempts": attempt + 1}
                        )
                    delay = retry_after if retry_after is not None else self._backoff(attempt)
                    if self._monotonic() + delay + MIN_ATTEMPT_S > ends_at:
                        return self._deadline(action, base, attempt + 1, http_status=status)
                    await self._sleep(delay)
                    attempt += 1
                    continue
                return self._outcome(action, base, status, content.body, attempt + 1)

    def _deadline(self, action: ResponseAction, base: Mapping[str, Any], attempts: int, **last: Any) -> ConnectorResult:
        log.warning("response.webhook_deadline", action_type=action.action_type, attempts=attempts)
        return ConnectorResult(
            "failed", {**base, "error": "deadline", "deadline_s": self._deadline_s, "attempts": attempts, **last}
        )

    async def _post(
        self, client: httpx.AsyncClient, body: bytes, headers: Mapping[str, str], timeout_s: float
    ) -> tuple[int, _Received]:
        request = client.build_request("POST", self._target.url, content=body, headers=dict(headers))
        async with asyncio.timeout(timeout_s):
            response = await client.send(request, stream=True)
            try:
                chunks = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self._max_response_bytes:
                        raise _ResponseTooLarge()
                    chunks.append(chunk)
            finally:
                await response.aclose()
        return response.status_code, _Received(response.headers, b"".join(chunks))

    def _outcome(
        self, action: ResponseAction, base: Dict[str, Any], status: int, body: bytes, attempts: int
    ) -> ConnectorResult:
        detail: Dict[str, Any] = {**base, "http_status": status, "attempts": attempts}
        if not 200 <= status < 300:
            log.warning("response.webhook_rejected", action_type=action.action_type, http_status=status)
            detail["error"] = "unexpected_redirect" if 300 <= status < 400 else "http_status"
            return ConnectorResult("failed", detail)
        parsed = _json_object(body)
        if parsed is not None:
            safe, _ = redact(parsed)
            text = json.dumps(safe, separators=(",", ":"), default=str)
            detail["response"] = safe if len(text) <= MAX_RECORDED_RESPONSE_CHARS else {"_truncated": True}
            reported = str(parsed.get("status", "")).lower()
            if reported in FAILED_BODY_STATUSES:
                detail["error"] = "receiver_reported_failure"
                return ConnectorResult("failed", detail)
        return ConnectorResult("succeeded", detail)


@dataclass(frozen=True)
class _Received:
    headers: httpx.Headers
    body: bytes = field(repr=False)


def _json_object(body: bytes) -> Optional[Dict[str, Any]]:
    if not body:
        return None
    try:
        value = json.loads(body)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
