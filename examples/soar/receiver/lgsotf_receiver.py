#!/usr/bin/env python3
"""Reference receiver for LG-SOTF response actions (schema ``lg-sotf.response-action.v1``).

Standard library only, Python 3.10 or later. It does what every receiver of the
LG-SOTF webhook connector must do (docs/soar-playbooks.md):

1. verify the request exactly as the connector signs it: ``X-LGSOTF-Signature``
   is ``v1=`` + hex HMAC-SHA256 of ``"<X-LGSOTF-Timestamp>.<raw body>"`` with the
   shared secret, the timestamp is at most five minutes away from now, and the
   unsigned ``Idempotency-Key`` header, when present, equals the signed
   ``action.id``;
2. deduplicate on ``action.id``: a repeated id is answered with the original
   result and never acted on twice (LG-SOTF re-signs every retry, and re-sends
   an action whose execution was interrupted);
3. run the handler for ``action.type`` (``lgsotf_handlers.py``, or forward the
   verified action to another SOAR with ``LGSOTF_FORWARD_URL``);
4. answer ``200`` with ``{"status": "succeeded" | "failed" | "rejected", ...}``,
   which LG-SOTF records on the action ledger; ``401`` when the request is not
   authentic; ``503`` with ``Retry-After`` while the same action is still running.

Run it (secrets only ever come from the environment)::

    export LGSOTF_WEBHOOK_SECRET=...        # the tenant's webhook secret in LG-SOTF
    python3 lgsotf_receiver.py serve --host 0.0.0.0 --port 8443 \\
        --tls-cert server.crt --tls-key server.key --db /var/lib/lgsotf/receiver.sqlite3

and set the tenant's webhook URL to ``https://<host>:8443/lgsotf/actions``.
``python3 lgsotf_receiver.py send-test --url <url>`` posts one signed
``send_alert`` test action, to check a receiver (this one, or an n8n, Tines or
Shuffle flow) before LG-SOTF is pointed at it.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

SCHEMA = "lg-sotf.response-action.v1"
EVENT = "response_action.execute"
SIGNATURE_HEADER = "X-LGSOTF-Signature"
TIMESTAMP_HEADER = "X-LGSOTF-Timestamp"
IDEMPOTENCY_HEADER = "Idempotency-Key"
EVENT_HEADER = "X-LGSOTF-Event"
DELIVERY_HEADER = "X-LGSOTF-Delivery"
REPLAYED_HEADER = "Idempotent-Replayed"
SIGNATURE_VERSION = "v1"
TOLERANCE_S = 300
MIN_SECRET_BYTES = 16
MAX_BODY_BYTES = 256 * 1024
# The webhook connector gives up at once on a Retry-After above 15 s (its max_retry_after_s).
RETRY_AFTER_S = 5
MAX_RETRY_AFTER_S = 15
# A claim older than this belongs to a request that never finished (crash): its outcome is unknown.
STALE_CLAIM_S = 600
RETENTION_S = 30 * 86400
MAX_MESSAGE_CHARS = 300
MAX_REFERENCE_CHARS = 200
MAX_DETAIL_CHARS = 1_000
DEFAULT_PATH = "/lgsotf/actions"
USER_AGENT = "lgsotf-reference-receiver/1"
OUTCOME_STATUSES = ("succeeded", "failed", "rejected")
FAILED_STATUSES = frozenset({"failed", "error", "rejected"})
# Names of the environment variables that hold the secrets (never the secrets themselves).
SECRET_ENV = "LGSOTF_WEBHOOK_SECRET"  # noqa: S105  # nosec B105
PREVIOUS_SECRET_ENV = "LGSOTF_WEBHOOK_SECRET_PREVIOUS"  # noqa: S105  # nosec B105

_SECURITY_HEADERS = frozenset(h.lower() for h in (SIGNATURE_HEADER, TIMESTAMP_HEADER, IDEMPOTENCY_HEADER))
_TIMESTAMP_RE = re.compile(r"^[0-9]{1,15}$")
_SIGNATURE_RE = re.compile(r"^v1=[0-9a-f]{64}$")
_LENGTH_RE = re.compile(r"^[0-9]{1,9}$")

log = logging.getLogger("lgsotf_receiver")

Headers = Union[Mapping[str, str], Iterable[Tuple[str, str]]]


def sign(secret: bytes, timestamp: str, body: bytes) -> str:
    """``v1=<hex>``: HMAC-SHA256 over ``"<timestamp>.<raw body>"`` (what LG-SOTF sends)."""
    mac = hmac.new(secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return f"{SIGNATURE_VERSION}={mac.hexdigest()}"


@dataclass(frozen=True)
class Action:
    """A verified action: the signed body's ``action`` object and its context."""

    id: str
    type: str
    target: str
    target_type: Optional[str]
    risk_level: Optional[str]
    params: Mapping[str, Any]
    tenant_id: str
    alert: Mapping[str, Any]
    payload: Mapping[str, Any] = field(repr=False)

    @property
    def scope_hosts(self) -> Tuple[str, ...]:
        """Hosts a host-local action (``terminate_process``, ``quarantine_file``) is limited to."""
        scope = self.params.get("scope")
        hosts = scope.get("hosts") if isinstance(scope, Mapping) else None
        return tuple(h for h in hosts if isinstance(h, str)) if isinstance(hosts, list) else ()

    @property
    def rollback_of(self) -> Optional[str]:
        """For a rollback (``release_host``, ``unblock_ip``, ...): the id of the action it undoes, else ``None``."""
        value = self.payload.get("rollback_of")
        return value if isinstance(value, str) and value else None

    @property
    def message_match(self) -> Mapping[str, str]:
        """``purge_message``: Message-ID, sender and subject, all of which a purge must match."""
        match = self.params.get("match")
        return {k: v for k, v in match.items() if isinstance(v, str)} if isinstance(match, Mapping) else {}


@dataclass(frozen=True)
class Outcome:
    """What a handler did; becomes the JSON body LG-SOTF records on the action ledger.

    ``succeeded``: the change was made (or was already in place). ``failed``:
    it was attempted and did not happen. ``rejected``: it was not attempted
    (not implemented, not allowed here). Keep ``detail`` small and free of
    secrets: LG-SOTF stores at most 2,000 characters of the response.
    """

    status: str
    error: Optional[str] = None
    message: Optional[str] = None
    reference: Optional[str] = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in OUTCOME_STATUSES:
            raise ValueError(f"status must be one of {OUTCOME_STATUSES}")

    @classmethod
    def succeeded(cls, reference: Optional[str] = None, **detail: Any) -> Outcome:
        return cls("succeeded", reference=reference, detail=detail)

    @classmethod
    def failed(cls, error: str, message: Optional[str] = None, **detail: Any) -> Outcome:
        return cls("failed", error=error, message=message, detail=detail)

    @classmethod
    def rejected(cls, error: str, message: Optional[str] = None, **detail: Any) -> Outcome:
        return cls("rejected", error=error, message=message, detail=detail)


class RetryLater(Exception):
    """Raise from a handler when the change certainly did not happen (vendor 429/503, connection refused).

    The receiver forgets the action and answers ``503`` with ``Retry-After``,
    so LG-SOTF sends it again. Never raise it after a call that may have
    reached the vendor (a timeout): return ``Outcome.failed`` instead.
    """

    def __init__(self, retry_after_s: int = RETRY_AFTER_S) -> None:
        super().__init__("retry later")
        self.retry_after_s = max(1, min(MAX_RETRY_AFTER_S, int(retry_after_s)))


Handler = Callable[[Action], Outcome]


@dataclass(frozen=True)
class Reply:
    status: int
    body: Dict[str, Any]
    headers: Dict[str, str] = field(default_factory=dict)

    def encoded(self) -> bytes:
        return json.dumps(self.body, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass(frozen=True)
class Claim:
    """Result of :meth:`IdempotencyStore.claim`: ``new``, ``done`` (with the stored reply), ``busy``, ``stale`` or ``conflict``."""

    state: str
    reply: Optional[Dict[str, Any]] = None


class IdempotencyStore:
    """Action ids already seen, in SQLite: a file several receiver processes may share, or ``:memory:``."""

    def __init__(
        self,
        path: str = ":memory:",
        *,
        clock: Callable[[], float] = time.time,
        stale_after_s: float = STALE_CLAIM_S,
        retention_s: float = RETENTION_S,
    ) -> None:
        self._clock = clock
        self._stale_after_s = stale_after_s
        self._retention_s = retention_s
        self._lock = threading.Lock()
        self._last_purge = 0.0
        self._db = sqlite3.connect(path, timeout=10.0, isolation_level=None, check_same_thread=False)
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS lgsotf_actions ("
            " action_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,"
            " state TEXT NOT NULL CHECK (state IN ('in_progress', 'done')),"
            " reply TEXT, updated_at REAL NOT NULL)"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS lgsotf_actions_updated ON lgsotf_actions (updated_at)")

    def claim(self, action_id: str, fingerprint: str) -> Claim:
        """Atomically take ownership of ``action_id``, or report why not (across processes too)."""
        now = self._clock()
        with self._lock:
            self._maybe_purge(now)
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT fingerprint, state, reply, updated_at FROM lgsotf_actions WHERE action_id = ?", (action_id,)
                ).fetchone()
                if row is None:
                    self._db.execute(
                        "INSERT INTO lgsotf_actions (action_id, fingerprint, state, updated_at)"
                        " VALUES (?, ?, 'in_progress', ?)",
                        (action_id, fingerprint, now),
                    )
                    claim = Claim("new")
                elif row[0] != fingerprint:
                    claim = Claim("conflict")
                elif row[1] == "done":
                    claim = Claim("done", json.loads(row[2]))
                elif now - row[3] > self._stale_after_s:
                    # Refreshed so a concurrent duplicate sees "busy" while the caller settles it.
                    self._db.execute("UPDATE lgsotf_actions SET updated_at = ? WHERE action_id = ?", (now, action_id))
                    claim = Claim("stale")
                else:
                    claim = Claim("busy")
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return claim

    def finish(self, action_id: str, reply: Mapping[str, Any]) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE lgsotf_actions SET state = 'done', reply = ?, updated_at = ? WHERE action_id = ?",
                (json.dumps(dict(reply), sort_keys=True), self._clock(), action_id),
            )

    def release(self, action_id: str) -> None:
        """Forget an unfinished claim (the handler asked for a retry: nothing was done)."""
        with self._lock:
            self._db.execute("DELETE FROM lgsotf_actions WHERE action_id = ? AND state = 'in_progress'", (action_id,))

    def purge(self) -> int:
        """Delete entries older than the retention; returns how many."""
        with self._lock:
            return self._purge(self._clock())

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _maybe_purge(self, now: float) -> None:
        if now - self._last_purge >= 3600:
            self._purge(now)

    def _purge(self, now: float) -> int:
        self._last_purge = now
        cursor = self._db.execute("DELETE FROM lgsotf_actions WHERE updated_at < ?", (now - self._retention_s,))
        return int(cursor.rowcount)


def _fingerprint(action: Action) -> str:
    """What must not change between deliveries of one action id."""
    material = json.dumps([action.tenant_id, action.type, action.target], ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _json_object(body: bytes) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(body)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _security_headers(headers: Headers) -> Optional[Dict[str, str]]:
    """The signature, timestamp and Idempotency-Key headers by lower-case name; ``None`` when one is repeated."""
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    found: Dict[str, str] = {}
    for name, value in pairs:
        key = str(name).lower()
        if key in _SECURITY_HEADERS:
            if key in found:
                return None
            found[key] = str(value)
    return found


def _text(value: Any, limit: int) -> Optional[str]:
    return None if value is None else str(value)[:limit]


def _outcome_body(outcome: Outcome, base: Mapping[str, Any]) -> Dict[str, Any]:
    body: Dict[str, Any] = {"status": outcome.status, **base}
    for key, value, limit in (
        ("error", outcome.error, 64),
        ("message", outcome.message, MAX_MESSAGE_CHARS),
        ("reference", outcome.reference, MAX_REFERENCE_CHARS),
    ):
        if value is not None:
            body[key] = _text(value, limit)
    if outcome.detail:
        detail = json.loads(json.dumps(dict(outcome.detail), default=str))
        body["detail"] = detail if len(json.dumps(detail)) <= MAX_DETAIL_CHARS else {"_truncated": True}
    return body


def _parse_action(payload: Mapping[str, Any]) -> Optional[Action]:
    raw = payload.get("action")
    alert = payload.get("alert")
    if not isinstance(raw, Mapping):
        return None
    action_id, action_type, target = raw.get("id"), raw.get("type"), raw.get("target")
    tenant_id = payload.get("tenant_id")
    if not all(isinstance(v, str) and v for v in (action_id, action_type, target, tenant_id)):
        return None
    params = raw.get("params")
    return Action(
        id=str(action_id),
        type=str(action_type),
        target=str(target),
        target_type=_text(raw.get("target_type"), 32),
        risk_level=_text(raw.get("risk_level"), 32),
        params=params if isinstance(params, Mapping) else {},
        tenant_id=str(tenant_id),
        alert=alert if isinstance(alert, Mapping) else {},
        payload=payload,
    )


def _unauthorized() -> Reply:
    # One answer for every authentication failure: the sender learns nothing about which check failed.
    return Reply(401, {"status": "rejected", "error": "unauthorized"})


class Receiver:
    """Verifies, deduplicates and dispatches one request at a time (thread-safe); no I/O of its own."""

    def __init__(
        self,
        secrets: Sequence[bytes],
        handlers: Mapping[str, Handler],
        store: IdempotencyStore,
        *,
        tenants: Optional[Iterable[str]] = None,
        tolerance_s: float = TOLERANCE_S,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """``secrets``: the current secret first, then (while rotating) the previous one.

        ``tenants``: when given, actions of any other LG-SOTF tenant are
        rejected (useful on an install-wide webhook shared by several tenants).
        """
        if not secrets or any(len(s) < MIN_SECRET_BYTES for s in secrets):
            raise ValueError(f"every webhook secret must be at least {MIN_SECRET_BYTES} bytes")
        self._secrets = tuple(bytes(s) for s in secrets)
        self._handlers = dict(handlers)
        self._store = store
        self._tenants: Optional[FrozenSet[str]] = frozenset(tenants) if tenants is not None else None
        self._tolerance_s = tolerance_s
        self._clock = clock

    def _authentic(self, headers: Mapping[str, str], body: bytes) -> bool:
        """Signed with one of the secrets, over this body and a timestamp at most ``tolerance_s`` away.

        ``headers`` are the security headers by lower-case name (:func:`_security_headers`).
        """
        timestamp = headers.get(TIMESTAMP_HEADER.lower(), "")
        signature = headers.get(SIGNATURE_HEADER.lower(), "")
        if not _TIMESTAMP_RE.match(timestamp) or not _SIGNATURE_RE.match(signature):
            return False
        if abs(self._clock() - int(timestamp)) > self._tolerance_s:
            return False
        matched = False
        for secret in self._secrets:  # every secret is tried, so timing does not reveal which one matched
            matched |= hmac.compare_digest(sign(secret, timestamp, body), signature)
        return matched

    def handle(self, headers: Headers, body: bytes) -> Reply:
        if len(body) > MAX_BODY_BYTES:
            return Reply(413, {"status": "rejected", "error": "body_too_large"})
        security = _security_headers(headers)
        if security is None or not self._authentic(security, body):
            log.warning("request refused: missing, invalid or stale signature")
            return _unauthorized()
        payload = _json_object(body) or {}
        raw = payload.get("action")
        raw_action: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
        action_id = raw_action.get("id")
        if not isinstance(action_id, str) or not action_id:
            return Reply(400, {"status": "rejected", "error": "malformed_payload"})
        key = security.get(IDEMPOTENCY_HEADER.lower())
        if key is not None and not hmac.compare_digest(key.encode("utf-8"), action_id.encode("utf-8")):
            log.warning("request refused: Idempotency-Key does not match the signed action id")
            return _unauthorized()
        base = {"action_id": action_id[:64], "action_type": str(raw_action.get("type") or "")[:64]}
        if payload.get("schema") != SCHEMA or payload.get("event") != EVENT:
            return Reply(200, {"status": "rejected", "error": "unsupported_schema", **base})
        if self._tenants is not None and payload.get("tenant_id") not in self._tenants:
            return Reply(200, {"status": "rejected", "error": "tenant_not_allowed", **base})
        action = _parse_action(payload)
        if action is None:
            return Reply(400, {"status": "rejected", "error": "malformed_payload", **base})
        return self._dispatch(action, base)

    def _dispatch(self, action: Action, base: Mapping[str, Any]) -> Reply:
        claim = self._store.claim(action.id, _fingerprint(action))
        if claim.state == "done" and claim.reply is not None:
            log.info("action %s answered again with its original result", action.id)
            return Reply(200, claim.reply, {REPLAYED_HEADER: "true"})
        if claim.state == "busy":
            return Reply(503, {"status": "in_progress", **base}, {"Retry-After": str(RETRY_AFTER_S)})
        if claim.state == "conflict":
            log.warning("action %s was seen before with another tenant, type or target", action.id)
            return Reply(409, {"status": "rejected", "error": "idempotency_conflict", **base})
        if claim.state == "stale":
            outcome = Outcome.failed(
                "interrupted", "an earlier attempt stopped before it finished: check the target before acting again"
            )
        else:
            handler = self._handlers.get(action.type)
            if handler is None:
                outcome = Outcome.rejected("unsupported_action_type", f"no handler for {action.type[:64]}")
            else:
                try:
                    outcome = handler(action)
                except RetryLater as exc:
                    self._store.release(action.id)
                    return Reply(503, {"status": "retry_later", **base}, {"Retry-After": str(exc.retry_after_s)})
                except Exception:  # a bug or an unexpected vendor answer: the outcome is failed, never retried
                    log.exception("handler for %s raised", action.type)
                    outcome = Outcome.failed("handler_error", "the handler raised an exception: see the receiver log")
                if not isinstance(outcome, Outcome):
                    outcome = Outcome.failed("handler_error", "the handler did not return an Outcome")
        body = _outcome_body(outcome, base)
        self._store.finish(action.id, body)
        log.info("action %s (%s) %s", action.id, action.type, outcome.status)
        return Reply(200, body)


# --------------------------------------------------------------------------- gateway mode


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Forwarder:
    """A handler that sends the verified action to your SOAR's own webhook (gateway mode).

    For SOARs that cannot check an HMAC over the raw body: this receiver
    verifies and deduplicates, then POSTs the payload (plus
    ``Idempotency-Key``) to ``url`` with ``headers`` (the SOAR's own webhook
    authentication). A ``2xx`` answer means succeeded (accepted), a JSON body
    with ``status`` ``failed``/``error``/``rejected`` means failed, ``429`` and
    ``503`` are retried, anything else fails. Redirects are not followed.
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        *,
        timeout_s: float = 10.0,
        allow_http: bool = False,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        parts = urlsplit(url)
        schemes = ("https", "http") if allow_http else ("https",)
        if parts.scheme not in schemes or not parts.hostname:
            raise ValueError(f"forward URL must be {' or '.join(schemes)} with a host")
        self._url = url
        self._headers = dict(headers or {})
        self._timeout_s = timeout_s
        self._opener = opener or urllib.request.build_opener(_NoRedirect())

    def __call__(self, action: Action) -> Outcome:
        body = json.dumps(action.payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - https (or explicitly allowed http) only, checked above
            self._url,
            data=body,
            method="POST",
            headers={
                **self._headers,
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                IDEMPOTENCY_HEADER: action.id,
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout_s) as response:
                status, content, retry_after = response.status, response.read(64 * 1024), None
        except urllib.error.HTTPError as exc:
            status, content, retry_after = exc.code, exc.read(64 * 1024), exc.headers.get("Retry-After")
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (ConnectionRefusedError, socket.gaierror)):
                raise RetryLater() from exc  # nothing reached the SOAR
            if isinstance(exc.reason, TimeoutError):
                return Outcome.failed("forward_timeout", "the SOAR did not answer in time: check whether it acted")
            return Outcome.failed("forward_failed", type(exc.reason).__name__)
        except TimeoutError:
            return Outcome.failed("forward_timeout", "the SOAR did not answer in time: check whether it acted")
        except OSError as exc:  # the connection broke after the request was sent: the outcome is unknown
            return Outcome.failed("forward_failed", type(exc).__name__)
        if status in (429, 503):
            raise RetryLater(int(retry_after) if retry_after and retry_after.isdigit() else RETRY_AFTER_S)
        if not 200 <= status < 300:
            return Outcome.failed("forward_rejected", f"the SOAR answered HTTP {status}", http_status=status)
        parsed = _json_object(content) or {}
        if str(parsed.get("status", "")).lower() in FAILED_STATUSES:
            return Outcome.failed("soar_reported_failure", _text(parsed.get("error") or parsed.get("message"), 200))
        reference = next((parsed[k] for k in ("execution_id", "wf_exec_id", "id") if parsed.get(k)), None)
        return Outcome.succeeded(reference=_text(reference, MAX_REFERENCE_CHARS), forwarded=True, http_status=status)


# --------------------------------------------------------------------------- HTTP server


class ReceiverHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: Tuple[str, int], receiver: Receiver, path: str = DEFAULT_PATH) -> None:
        super().__init__(address, _RequestHandler)
        self.receiver = receiver
        self.path = path

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A client that drops the connection or fails the TLS handshake is not worth a traceback.
        log.warning("connection from %s failed: %s", client_address[0], type(sys.exc_info()[1]).__name__)


class _RequestHandler(BaseHTTPRequestHandler):
    server: ReceiverHTTPServer
    server_version = "lgsotf-receiver/1"
    sys_version = ""
    timeout = 20  # seconds per socket read: a slow client cannot hold a thread forever

    def setup(self) -> None:
        super().setup()
        if isinstance(self.connection, ssl.SSLSocket):
            # In this thread and under the socket timeout, not in the accept loop.
            self.connection.do_handshake()

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        if urlsplit(self.path).path != self.server.path:
            self._send(Reply(404, {"status": "rejected", "error": "not_found"}))
            return
        length = self.headers.get("Content-Length", "")
        if self.headers.get("Transfer-Encoding") or not _LENGTH_RE.match(length):
            self._send(Reply(411, {"status": "rejected", "error": "length_required"}))
            return
        if int(length) > MAX_BODY_BYTES:
            self._send(Reply(413, {"status": "rejected", "error": "body_too_large"}))
            return
        if self.headers.get_content_type() != "application/json":
            self._send(Reply(415, {"status": "rejected", "error": "unsupported_media_type"}))
            return
        body = self.rfile.read(int(length))
        if len(body) != int(length):
            self._send(Reply(400, {"status": "rejected", "error": "incomplete_body"}))
            return
        self._send(self.server.receiver.handle(self.headers.items(), body))

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if urlsplit(self.path).path == "/healthz":
            self._send(Reply(200, {"status": "ok"}))
        else:
            self._send(Reply(404, {"status": "rejected", "error": "not_found"}))

    def _send(self, reply: Reply) -> None:
        content = reply.encoded()
        self.send_response(reply.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        for name, value in reply.headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - http.server signature
        log.debug("%s %s", self.address_string(), format % args)


# --------------------------------------------------------------------------- test sender


def sample_request(
    secret: bytes, *, action_type: str = "send_alert", tenant_id: str = "lgsotf-test", now: Optional[float] = None
) -> Tuple[Dict[str, str], bytes]:
    """Headers and body of a signed test action, encoded and signed the way LG-SOTF does it."""
    moment = time.time() if now is None else now
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(moment))
    action_id = str(uuid.uuid4())
    payload = {
        "schema": SCHEMA,
        "event": EVENT,
        "sent_at": stamp,
        "tenant_id": tenant_id,
        "action": {
            "id": action_id,
            "idempotency_key": hashlib.sha256(action_id.encode("ascii")).hexdigest(),
            "type": action_type,
            "target": f"alert:lgsotf-test-{action_id[:8]}",
            "target_type": "alert",
            "risk_level": "low",
            "params": {"playbook": "test", "evidence": "rules", "explanation": "receiver test sent by lgsotf_receiver.py"},
            "requested_by": "receiver-test",
            "approved_by": "receiver-test",
            "approved_at": stamp,
        },
        "alert": {"id": f"lgsotf-test-{action_id[:8]}", "severity": "low", "title": "LG-SOTF receiver test"},
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    timestamp = str(int(moment))
    headers = {
        "Content-Type": "application/json",
        IDEMPOTENCY_HEADER: action_id,
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: sign(secret, timestamp, body),
        EVENT_HEADER: EVENT,
        DELIVERY_HEADER: str(uuid.uuid4()),
    }
    return headers, body


def send_test(url: str, secret: bytes, *, action_type: str, tenant_id: str, timeout_s: float = 20.0) -> int:
    if urlsplit(url).scheme not in ("https", "http"):
        print("--url must be an http(s) URL", file=sys.stderr)
        return 2
    headers, body = sample_request(secret, action_type=action_type, tenant_id=tenant_id)
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)  # noqa: S310 - checked above
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout_s) as response:
            status, content = response.status, response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        status, content = exc.code, exc.read(64 * 1024)
    except (urllib.error.URLError, OSError) as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        return 1
    print(f"HTTP {status} {content.decode('utf-8', 'replace')}")
    parsed = _json_object(content) or {}
    return 0 if 200 <= status < 300 and str(parsed.get("status", "")).lower() not in FAILED_STATUSES else 1


# --------------------------------------------------------------------------- command line


def _secrets_from_env() -> List[bytes]:
    secrets = [os.environ.get(name, "").encode("utf-8") for name in (SECRET_ENV, PREVIOUS_SECRET_ENV)]
    return [s for s in secrets if s]


def _forward_handlers(catalog: Iterable[str]) -> Optional[Dict[str, Handler]]:
    url = os.environ.get("LGSOTF_FORWARD_URL")
    if not url:
        return None
    raw_headers = os.environ.get("LGSOTF_FORWARD_HEADERS", "{}")
    headers = json.loads(raw_headers)
    if not isinstance(headers, dict) or not all(isinstance(v, str) for v in headers.values()):
        raise ValueError("LGSOTF_FORWARD_HEADERS must be a JSON object of header names to string values")
    forwarder = Forwarder(url, headers, allow_http=os.environ.get("LGSOTF_FORWARD_ALLOW_HTTP") == "1")
    return {action_type: forwarder for action_type in catalog}


def _serve(args: argparse.Namespace) -> int:
    import lgsotf_handlers  # the stubs you edit; imported here so tests can build a Receiver without them

    secrets = _secrets_from_env()
    if not secrets:
        print(f"set {SECRET_ENV} (the tenant's webhook secret in LG-SOTF)", file=sys.stderr)
        return 2
    try:
        handlers = _forward_handlers(lgsotf_handlers.HANDLERS) or lgsotf_handlers.HANDLERS
        tenants = [t.strip() for t in args.tenants.split(",") if t.strip()] if args.tenants else None
        receiver = Receiver(secrets, handlers, IdempotencyStore(args.db), tenants=tenants)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    server = ReceiverHTTPServer((args.host, args.port), receiver, args.path)
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    scheme = "https" if args.tls_cert else "http"
    log.info("listening on %s://%s:%s%s", scheme, args.host, server.server_address[1], args.path)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="LG-SOTF response-action receiver (reference implementation)")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="receive signed actions from LG-SOTF")
    serve.add_argument("--host", default="127.0.0.1", help="address to bind (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--path", default=DEFAULT_PATH, help=f"URL path to accept (default: {DEFAULT_PATH})")
    serve.add_argument("--db", default="lgsotf-receiver.sqlite3", help="SQLite file for deduplication")
    serve.add_argument("--tenants", default="", help="comma-separated LG-SOTF tenant ids to accept (default: any)")
    serve.add_argument("--tls-cert", default="", help="PEM certificate chain (serve HTTPS directly)")
    serve.add_argument("--tls-key", default="", help="PEM private key for --tls-cert")
    test = sub.add_parser("send-test", help="post one signed test action to a receiver")
    test.add_argument("--url", required=True)
    test.add_argument("--action-type", default="send_alert")
    test.add_argument("--tenant", default="lgsotf-test")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if args.command == "send-test":
        secrets = _secrets_from_env()
        if not secrets or len(secrets[0]) < MIN_SECRET_BYTES:
            print(f"set {SECRET_ENV} (at least {MIN_SECRET_BYTES} bytes)", file=sys.stderr)
            return 2
        return send_test(args.url, secrets[0], action_type=args.action_type, tenant_id=args.tenant)
    if bool(args.tls_cert) != bool(args.tls_key):
        print("--tls-cert and --tls-key go together", file=sys.stderr)
        return 2
    return _serve(args)


if __name__ == "__main__":
    # Run through the importable module, so lgsotf_handlers (which imports it) and the
    # server share one copy of Outcome, Action and RetryLater.
    import lgsotf_receiver

    sys.exit(lgsotf_receiver.main())
