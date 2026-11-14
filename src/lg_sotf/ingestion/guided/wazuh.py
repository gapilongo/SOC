"""Guided setup checks for Wazuh (PRD-13.2a).

**Pull** (the platform reads the Wazuh indexer): :func:`check_wazuh_pull`
builds the real connector from the entered URL and credentials, applies the
install's destination policy and sends one read-only search
(:meth:`~lg_sotf.ingestion.sources.wazuh.WazuhConnector.probe`). The answer
is read as seven checks, in the order a connection is made:

=================== ==========================================================
``settings``         the URL, index pattern, time field and CA are well formed
``reachable``        the install may connect there and the indexer answers
``tls``              the certificate is trusted and names the host
``credentials``      the indexer accepts the user (HTTP 401 otherwise)
``index_permission`` the user's role may search the index (HTTP 403 otherwise)
``index``            the pattern matches an index and the time field sorts
``clock``            the indexer's clock and the newest alert agree with ours
=================== ==========================================================

Nothing is stored and one attempt is made (no retries): a guided check
answers in seconds. Only a certificate that fails verification is told
apart from other network failures; a refused destination keeps the single
message of :mod:`lg_sotf.net.egress`.

**Push** (the Wazuh manager posts alerts to the ingest webhook):
:func:`check_wazuh_push` checks the push source and the API key the manager
sends. An unknown key, a mistyped one and another tenant's key get the same
answer.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

import httpx

from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import ApiKey, Repositories, Source
from lg_sotf.ingestion.errors import SourceConfigError, SourceError, SourceUnavailable
from lg_sotf.ingestion.guided import CheckStatus, Failure, SetupCheck, ordered_checks
from lg_sotf.ingestion.normalizers import resolve_format
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources.base import ConnectorDeps
from lg_sotf.ingestion.sources.http import HttpResponse
from lg_sotf.ingestion.sources.wazuh import CLOCK_AGG, WazuhConnector
from lg_sotf.models.vocabulary import PUSH_SOURCE_TYPES
from lg_sotf.net.egress import DestinationRefused
from lg_sotf.security.hashing import InvalidApiKey, parse_api_key, verify_api_key
from lg_sotf.security.redaction import redact_text
from lg_sotf.settings import Settings

PULL_CHECKS: Tuple[Tuple[str, str], ...] = (
    ("settings", "Connection settings"),
    ("reachable", "Indexer reachable"),
    ("tls", "TLS certificate"),
    ("credentials", "Sign-in"),
    ("index_permission", "Permission to read the alerts index"),
    ("index", "Alerts index"),
    ("clock", "Clocks agree"),
)
PUSH_CHECKS: Tuple[Tuple[str, str], ...] = (("push_source", "Push source"), ("push_key", "Webhook API key"))

READ_PERMISSION = "indices:data/read/search"
INGEST_SCOPE = "ingest"
WAZUH_FORMAT = "wazuh"
# Clocks further apart than this fail the check (NTP keeps hosts within a second).
CLOCK_TOLERANCE_S = 120
MAX_MESSAGE_CHARS = 300
DRAFT_SOURCE_ID = "guided-setup"

_DENIED_ACTION = re.compile(r"no permissions for \[([a-z][a-z0-9:/_*-]{2,80})\]")
_DUMMY_KEY_HASH = "0" * 64
# OpenSSL verify codes (X509_V_ERR_*): untrusted issuer, validity dates, host name.
_UNTRUSTED_CA = frozenset({18, 19, 20, 21})
_BAD_DATES = frozenset({9, 10})
_HOSTNAME_MISMATCH = 62

SETTINGS_OK = "The URL, index pattern and credentials are well formed."
SETTINGS_FIX = (
    "Use an https URL to the indexer such as https://wazuh-indexer.example.com:9200, an index pattern such as "
    "wazuh-alerts-*, a date field such as timestamp, and a CA certificate in PEM format."
)
DESTINATION_FIX = (
    "Ask whoever runs this install to allow the indexer: add its host to ingestion.allowed_destination_hosts "
    "(PoV install: scripts/pov.sh --allow-host HOST), and set ingestion.allow_private_destinations "
    "(PoV install: --allow-private) when the indexer has a private address."
)
WRONG_SERVER_FIX = (
    "Point the URL at the Wazuh indexer's REST API (port 9200 by default), not the Wazuh dashboard (443) or the "
    "Wazuh manager API (55000)."
)
CLOCK_FIX = (
    "Synchronise the indexer, the Wazuh manager and this server with NTP (chrony or systemd-timesyncd), then run "
    "the checks again. Alerts are read by time window on this server's clock: with clocks apart they arrive late "
    "or are skipped."
)
KEY_FIX = (
    "Create an API key with the ingest scope (Users and API keys > Create API key), copy it when it is shown, "
    "and send it as the X-API-Key header from the Wazuh manager's integration."
)


@dataclass(frozen=True)
class _Target:
    """What the checks talk about: where the indexer is and what is read from it (no credentials)."""

    host: str
    port: int
    https: bool
    index: str
    time_field: str

    @property
    def where(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def not_applicable(self) -> Dict[str, str]:
        if self.https:
            return {}
        return {"tls": "The URL uses http: the connection is not encrypted and no certificate is checked."}

    def passed(self) -> Dict[str, str]:
        return {
            "settings": SETTINGS_OK,
            "reachable": f"{self.where} answered.",
            "tls": f"The certificate is trusted and names {self.host}.",
            "credentials": "The indexer accepted the user name and password.",
            "index_permission": f"The user's role may read {self.index} ({READ_PERMISSION}).",
        }


def _target(connector: WazuhConnector, base_url: str) -> _Target:
    url = httpx.URL(base_url)
    https = url.scheme.lower() == "https"
    return _Target(url.host, url.port or (443 if https else 80), https, connector.index, connector.time_field)


def _safe(exc: BaseException) -> str:
    text, _ = redact_text(str(exc))
    return text[:MAX_MESSAGE_CHARS] or type(exc).__name__


# -- pull --------------------------------------------------------------------------


def draft_source(tenant_id: str, config: Mapping[str, Any], now: datetime) -> Source:
    """The unsaved Wazuh source the checks run for."""
    return Source(
        id=DRAFT_SOURCE_ID,
        tenant_id=tenant_id,
        type="wazuh",
        name="Wazuh",
        enabled=True,
        config=dict(config),
        secret_ciphertext=None,
        poll_interval_s=60,
        cursor=None,
        cursor_watermark=None,
        last_polled_at=None,
        next_poll_at=None,
        consecutive_failures=0,
        last_error=None,
        health="unknown",
        created_at=now,
        updated_at=now,
    )


async def check_wazuh_pull(
    tenant_id: str,
    config: Mapping[str, Any],
    credentials: Mapping[str, Any],
    *,
    settings: Settings,
    options: IngestionOptions,
    deps: Optional[ConnectorDeps] = None,
) -> List[SetupCheck]:
    """Run the pull checks for an unsaved source (see the module docstring); never raises for a failing source."""
    source = draft_source(tenant_id, config, datetime.now(UTC))
    quick = options.model_copy(update={"http_max_retries": 0})
    try:
        connector = WazuhConnector(source, credentials, settings=settings, options=quick, deps=deps)
    except SourceConfigError as exc:
        return ordered_checks(PULL_CHECKS, {"settings": SETTINGS_OK}, _connect_failure(exc, None))
    target = _target(connector, str(source.config.get("base_url", "")))
    try:
        await connector.check_destinations()
        before = connector.deps.now()
        response = await connector.probe()
        # The middle of the request: the indexer read its clock somewhere between the two.
        now = before + (connector.deps.now() - before) / 2
    except (SourceConfigError, SourceError, httpx.TransportError) as exc:
        return ordered_checks(PULL_CHECKS, target.passed(), _connect_failure(exc, target), target.not_applicable)
    finally:
        await connector.aclose()
    return _evaluate(response, target, now)


def _connect_failure(exc: BaseException, target: Optional[_Target]) -> Failure:
    """The check a connection error fails. ``target`` is None while the settings themselves are refused."""
    where = target.where if target is not None else "that address"
    host = target.host if target is not None else "that host"
    if isinstance(exc, DestinationRefused):
        return Failure("reachable", f"This install is not allowed to connect to {host}.", DESTINATION_FIX)
    if isinstance(exc, SourceConfigError):
        return Failure("settings", _safe(exc), SETTINGS_FIX)
    if isinstance(exc, httpx.TransportError):
        return Failure(
            "reachable",
            f"The name {host} does not resolve from this server.",
            "Check the host name in the URL, or add it to the DNS (or the hosts file) this server uses.",
        )
    certificate = _certificate_error(exc)
    if certificate is not None:
        return _tls_failure(certificate, host)
    if isinstance(exc, SourceUnavailable) and exc.__cause__ is None:
        return Failure(
            "reachable",
            f"{where} answered with a server error.",
            "Check the indexer's health (GET _cluster/health) and its logs; it may still be starting.",
        )
    if isinstance(exc, SourceUnavailable):
        return Failure(
            "reachable",
            f"No answer from {where}.",
            "Check the host and port in the URL (the Wazuh indexer listens on 9200), and that a firewall lets "
            "this server reach it.",
        )
    return Failure("reachable", f"{where} did not give a usable answer.", WRONG_SERVER_FIX)


def _certificate_error(exc: BaseException) -> Optional[ssl.SSLCertVerificationError]:
    """The certificate verification failure behind ``exc``, if that is what stopped the connection."""
    seen: Optional[BaseException] = exc
    for _ in range(8):
        if seen is None:
            return None
        if isinstance(seen, ssl.SSLCertVerificationError):
            return seen
        seen = seen.__cause__ or seen.__context__
    return None


def _tls_failure(error: ssl.SSLCertVerificationError, host: str) -> Failure:
    code = getattr(error, "verify_code", None)
    if code in _UNTRUSTED_CA:
        return Failure(
            "tls",
            "The indexer's certificate is signed by a certificate authority this server does not trust "
            "(a private or self-signed CA).",
            "Paste the indexer's root CA certificate in PEM format (root-ca.pem; on a Wazuh node in "
            "/etc/wazuh-indexer/certs/) into the CA certificate field. Do not turn verification off.",
        )
    if code == _HOSTNAME_MISMATCH:
        return Failure(
            "tls",
            f"The indexer's certificate is not issued for {host}.",
            f"Use a host name the certificate lists (its subject alternative names) in the URL, or reissue the "
            f"indexer certificate with {host} among its names.",
        )
    if code in _BAD_DATES:
        return Failure(
            "tls",
            "The indexer's certificate has expired or is not valid yet.",
            "Renew the indexer certificate. If its dates are right, correct this server's clock.",
        )
    return Failure(
        "tls",
        f"The certificate of {host} could not be verified.",
        "Check that the CA certificate field holds the root CA that signed the indexer certificate, and that the "
        "certificate names the host in the URL.",
    )


def _evaluate(response: HttpResponse, target: _Target, now: datetime) -> List[SetupCheck]:
    """The checks an HTTP answer from the indexer settles."""
    passed = target.passed()
    skipped = dict(target.not_applicable)
    failure = _status_failure(response, target)
    body = _search_body(response) if failure is None else None
    if failure is None and body is None:
        failure = _wrong_server(response.status_code, target)
    if failure is None and body is not None:
        failure = _index_failure(body, target)
    if failure is None and body is not None:
        passed["index"] = _index_summary(body, target)
        clock = _clock_finding(body, target, now)
        if isinstance(clock, Failure):
            failure = clock
        elif clock is None:
            skipped["clock"] = "Not checked: the index holds no alert to compare clocks with."
        else:
            passed["clock"] = clock
    return ordered_checks(PULL_CHECKS, passed, failure, skipped)


def _status_failure(response: HttpResponse, target: _Target) -> Optional[Failure]:
    status = response.status_code
    if status == 200:
        return None
    if status == 401:
        return Failure(
            "credentials",
            "The indexer rejected the user name or password (HTTP 401).",
            "Enter the name and password of a Wazuh indexer user (an internal user of the indexer's security "
            "plugin). Wazuh dashboard and Wazuh manager API accounts, such as wazuh-wui, are different accounts.",
        )
    if status == 403:
        action = _denied_action(response)
        return Failure(
            "index_permission",
            f"The user signed in, but its role may not read {target.index}: the permission {action} is missing.",
            f"In the Wazuh indexer, give the user a role with the index permission read (it includes "
            f"{READ_PERMISSION}) on the index pattern {target.index}, and map the user to that role (Wazuh "
            f"dashboard: Indexer management > Security > Roles).",
        )
    if status == 404 and _error_type(response) == "index_not_found_exception":
        return _no_index(target)
    if status == 400 and _error_type(response) is not None:
        return Failure(
            "index",
            f"The indexer cannot sort {target.index} on the time field {target.time_field} (HTTP 400): the "
            f"field is not mapped as a date there.",
            f"Use a date field the alerts have: timestamp (the default, set by the Wazuh manager) or an ingest "
            f"timestamp you added. GET {target.index}/_mapping/field/{target.time_field} shows the mapping.",
        )
    return _wrong_server(status, target)


def _wrong_server(status: int, target: _Target) -> Failure:
    return Failure("reachable", f"{target.where} answered (HTTP {status}), but not like a Wazuh indexer.", WRONG_SERVER_FIX)


def _no_index(target: _Target) -> Failure:
    return Failure(
        "index",
        f"No index matches {target.index}.",
        "Check the index pattern: Wazuh stores alerts in daily indices named wazuh-alerts-4.x-YYYY.MM.DD, which "
        "wazuh-alerts-* matches. If the pattern is right, check that the Wazuh manager ships alerts to this "
        "indexer (filebeat test output, run on the manager).",
    )


def _json_object(response: HttpResponse) -> Optional[Mapping[str, Any]]:
    try:
        body = response.json()
    except SourceError:
        return None
    return body if isinstance(body, Mapping) else None


def _error(response: HttpResponse) -> Mapping[str, Any]:
    body = _json_object(response)
    error = body.get("error") if body is not None else None
    return error if isinstance(error, Mapping) else {}


def _error_type(response: HttpResponse) -> Optional[str]:
    kind = _error(response).get("type")
    return kind if isinstance(kind, str) else None


def _denied_action(response: HttpResponse) -> str:
    """The action the indexer's security plugin names in a 403; only the action name is read from the body."""
    reason = _error(response).get("reason")
    match = _DENIED_ACTION.search(reason) if isinstance(reason, str) else None
    return match.group(1) if match else READ_PERMISSION


def _search_body(response: HttpResponse) -> Optional[Mapping[str, Any]]:
    """The body of a search answer, or None when this is not what an indexer sends."""
    body = _json_object(response)
    if body is None or not isinstance(body.get("_shards"), Mapping) or not isinstance(body.get("hits"), Mapping):
        return None
    return body


def _index_failure(body: Mapping[str, Any], target: _Target) -> Optional[Failure]:
    shards = body["_shards"]
    if not shards.get("total"):
        # A wildcard that matches nothing is not an error for the indexer: it searches zero shards.
        return _no_index(target)
    if shards.get("failed"):
        return Failure(
            "index",
            f"{shards.get('failed')} of {shards.get('total')} shards of {target.index} did not answer.",
            "Bring the indexer cluster back to green or yellow health (GET _cluster/health), then run the checks again.",
        )
    return None


def _from_millis(value: Any) -> Optional[datetime]:
    """An indexer date (epoch milliseconds, as sort values and bucket bounds are) as a time, unclamped."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value / 1000, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _newest(body: Mapping[str, Any]) -> Optional[datetime]:
    hits = body["hits"].get("hits")
    first = hits[0] if isinstance(hits, list) and hits else None
    sort = first.get("sort") if isinstance(first, Mapping) else None
    # Not parse_timestamp: it clamps a time in the future to now, which is what the clock check looks for.
    return _from_millis(sort[0]) if isinstance(sort, list) and sort else None


def _index_summary(body: Mapping[str, Any], target: _Target) -> str:
    newest = _newest(body)
    if newest is None:
        return f"{target.index} exists and holds no alert yet; alerts appear once the Wazuh manager ships them."
    total = body["hits"].get("total")
    count = total.get("value") if isinstance(total, Mapping) else None
    more = isinstance(total, Mapping) and total.get("relation") == "gte"
    amount = f"{count:,}{' or more' if more else ''} alerts" if isinstance(count, int) else "alerts"
    return f"{target.index} holds {amount}; the newest is dated {newest:%Y-%m-%d %H:%M} UTC."


def _indexer_now(body: Mapping[str, Any]) -> Optional[datetime]:
    """The time the indexer resolved ``now`` to (the ``from`` of the probe's date_range bucket)."""
    aggregations = body.get("aggregations")
    clock = aggregations.get(CLOCK_AGG) if isinstance(aggregations, Mapping) else None
    buckets = clock.get("buckets") if isinstance(clock, Mapping) else None
    first = buckets[0] if isinstance(buckets, list) and buckets else None
    return _from_millis(first.get("from")) if isinstance(first, Mapping) else None


def _span(seconds: float) -> str:
    """A clock difference in words; it is only ever shown above the tolerance, so minutes are the smallest unit."""
    whole = int(abs(seconds))
    if whole < 2 * 3600:
        return f"{whole // 60} minutes"
    if whole < 2 * 86_400:
        return f"{whole // 3600} hours"
    return f"{whole // 86_400} days"


def _clock_finding(body: Mapping[str, Any], target: _Target, now: datetime) -> Union[Failure, str, None]:
    """A failure, the text of a pass, or None when there is nothing to compare."""
    indexer = _indexer_now(body)
    newest = _newest(body)
    if indexer is not None:
        skew = (indexer - now).total_seconds()
        if abs(skew) > CLOCK_TOLERANCE_S:
            direction = "ahead of" if skew > 0 else "behind"
            return Failure("clock", f"The indexer's clock is {_span(skew)} {direction} this server's clock.", CLOCK_FIX)
    if newest is not None:
        ahead = (newest - now).total_seconds()
        if ahead > CLOCK_TOLERANCE_S:
            return Failure(
                "clock",
                f"The newest alert in {target.index} is dated {_span(ahead)} in the future: the Wazuh manager's "
                f"clock is ahead of this server's.",
                CLOCK_FIX,
            )
    if indexer is not None:
        return f"The indexer's clock is within {CLOCK_TOLERANCE_S} seconds of this server's."
    if newest is not None:
        return "The newest alert is not dated in the future."
    return None


# -- push --------------------------------------------------------------------------


async def check_wazuh_push(
    repos: Repositories, tenant_id: str, source_id: str, api_key: Optional[str]
) -> List[SetupCheck]:
    """Check the push source and the API key the Wazuh manager sends (both are always checked)."""
    titles = dict(PUSH_CHECKS)
    source = await _push_source(repos, tenant_id, source_id)
    key = await _push_key(repos, tenant_id, (api_key or "").strip())
    return [
        SetupCheck("push_source", titles["push_source"], *source),
        SetupCheck("push_key", titles["push_key"], *key),
    ]


_Finding = Tuple[CheckStatus, str, Optional[str]]  # (status, message, fix)


def _failed(message: str, fix: str) -> _Finding:
    return ("failed", message, fix)


async def _push_source(repos: Repositories, tenant_id: str, source_id: str) -> _Finding:
    create = (
        f"Create a source of type webhook with the id {source_id} and config.format set to {WAZUH_FORMAT} "
        f"(Sources > Add source)."
    )
    try:
        source = await repos.sources.get(tenant_id, source_id)
    except NotFound:
        return _failed(f"This tenant has no source with the id {source_id}.", create)
    if source.type not in PUSH_SOURCE_TYPES:
        return _failed(f"{source_id} is a {source.type} pull source: alerts cannot be pushed to it.", create)
    try:
        fmt = resolve_format(source.type, source.config)
    except SourceConfigError as exc:
        return _failed(_safe(exc), f"Set config.format of the source {source_id} to {WAZUH_FORMAT}.")
    if fmt != WAZUH_FORMAT:
        return _failed(
            f"The source {source_id} expects the {fmt} format, not Wazuh alerts.",
            f"Set config.format of the source {source_id} to {WAZUH_FORMAT}.",
        )
    if not source.enabled:
        return _failed(
            f"The source {source_id} is disabled: pushed alerts are refused.", f"Enable the source {source_id}."
        )
    return ("passed", f"{source_id} accepts Wazuh alerts at POST /api/v1/ingest/webhook/{source_id}.", None)


def _has_ingest(key: ApiKey) -> bool:
    return INGEST_SCOPE in key.scopes


async def _push_key(repos: Repositories, tenant_id: str, presented: str) -> _Finding:
    if not presented:
        usable = [k for k in await repos.api_keys.list(tenant_id) if _has_ingest(k)]
        if not usable:
            return _failed(
                f"This tenant has no active API key with the {INGEST_SCOPE} scope: the Wazuh manager has nothing "
                f"to authenticate with.",
                KEY_FIX,
            )
        return ("skipped", f"Not checked: paste the key the Wazuh manager sends ({len(usable)} active key(s) "
                           f"have the {INGEST_SCOPE} scope).", None)
    try:
        parsed = parse_api_key(presented)
    except InvalidApiKey:
        return _failed(
            "This is not an LG-SOTF API key: a key starts with lgk_ and is shown once, when it is created.", KEY_FIX
        )
    key = await repos.api_keys.get_by_id(tenant_id, parsed.key_id)
    # Compare against a dummy hash when there is no such key, so the time taken does not tell the two apart.
    matches = verify_api_key(presented, key.key_hash if key is not None else _DUMMY_KEY_HASH)
    if key is None or not matches:
        return _failed(
            "This key is not an API key of this tenant: it is mistyped, deleted or belongs to another tenant.", KEY_FIX
        )
    if key.is_revoked:
        return _failed(f"The key {key.prefix} was revoked: the ingest endpoint refuses it (HTTP 401).", KEY_FIX)
    if not _has_ingest(key):
        return _failed(
            f"The key {key.prefix} lacks the {INGEST_SCOPE} scope (it has: {', '.join(sorted(key.scopes))}): the "
            f"ingest endpoint refuses it (HTTP 403).",
            KEY_FIX,
        )
    return ("passed", f"The key {key.prefix} is active and has the {INGEST_SCOPE} scope.", None)


__all__ = ["CLOCK_TOLERANCE_S", "PULL_CHECKS", "PUSH_CHECKS", "READ_PERMISSION", "check_wazuh_pull", "check_wazuh_push"]
