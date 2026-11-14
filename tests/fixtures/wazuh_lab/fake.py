"""A fake Wazuh indexer for tests that cannot start the lab (an ``httpx.MockTransport`` handler).

It answers ``POST /<index>/_search`` and ``GET /<index>/_count`` the way the
Wazuh 4.14 indexer of the lab does (``docker/docker-compose.wazuh-test.yml``):
every status, header and body below was copied from that indexer, and
``tests/live/wazuh/test_guided_setup.py`` asks the real one the same
questions, so the two cannot drift apart unnoticed.

* a user the indexer does not know, or the wrong secret for a known one, is
  answered ``401`` with the plain text ``Unauthorized``;
* a user whose roles cover none of the indices the pattern resolves to:
  ``403`` ``security_exception`` naming the denied action;
* a wildcard that resolves to no index: ``200`` over zero shards (and no
  aggregations), whatever the user's roles;
* a concrete index that does not exist: ``404`` ``index_not_found_exception``
  when a role covers the name, ``403`` otherwise;
* a sort on a field no index maps: ``400`` ``search_phase_execution_exception``;
* otherwise the newest hit's sort value and, for a ``date_range`` aggregation
  from ``now``, the indexer's own clock in the bucket's ``from``.

Network faults are switched on by attribute: ``down`` (nothing listens) and
``certificate`` (the TLS handshake fails verification with that OpenSSL
``verify_code``), raised the way ``httpx`` raises them.
"""

from __future__ import annotations

import base64
import json
import ssl
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import httpx

SEARCH_ACTION = "indices:data/read/search"
UNTRUSTED_ISSUER = (20, "unable to get local issuer certificate")
HOSTNAME_MISMATCH = (62, "Hostname mismatch, certificate is not valid for 'wazuh.example.com'.")
EXPIRED = (10, "certificate has expired")


def certificate_failure(code: int, message: str) -> httpx.ConnectError:
    """What ``httpx`` raises when the server certificate fails verification."""
    text = f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message} (_ssl.c:1010)"
    cause = ssl.SSLCertVerificationError(1, text)
    cause.verify_code = code
    cause.verify_message = message
    error = httpx.ConnectError(text)
    error.__cause__ = cause
    return error


def _millis(when: datetime) -> int:
    return int(when.timestamp() * 1000)


class FakeWazuhIndexer:
    def __init__(self, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.clock = clock
        self.down = False
        self.certificate: Optional[Tuple[int, str]] = None
        self.failed_shards = 0
        # index name -> {field: [values of each document]}; every index maps the fields its documents hold
        self.indices: Dict[str, Dict[str, List[datetime]]] = {}
        self.users: Dict[str, Tuple[str, List[str]]] = {}
        self.requests: List[httpx.Request] = []

    # -- setup -------------------------------------------------------------------

    def add_alerts(self, index: str, timestamps: Sequence[datetime], field: str = "timestamp") -> None:
        self.indices.setdefault(index, {}).setdefault(field, []).extend(timestamps)

    def put_user(self, username: str, password: str, patterns: Sequence[str] = ()) -> None:
        """A user whose role may read ``patterns`` (none: the user signs in and may read nothing)."""
        self.users[username] = (password, list(patterns))

    # -- transport ---------------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError("All connection attempts failed")
        if self.certificate is not None:
            raise certificate_failure(*self.certificate)
        user = self._authenticate(request)
        if user is None:
            return httpx.Response(
                401, text="Unauthorized", headers={"WWW-Authenticate": 'Basic realm="OpenSearch Security"'}
            )
        target, _, operation = request.url.path.lstrip("/").partition("/")
        if operation not in ("_search", "_count"):
            return _error(404, "invalid_index_name_exception", "no such endpoint in the fake")
        return self._search(target, operation, self.users[user][1], user, json.loads(request.content or b"{}"))

    def _authenticate(self, request: httpx.Request) -> Optional[str]:
        """The user name, when the Basic credentials are those of a known user."""
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        if scheme != "Basic":
            return None
        username, _, password = base64.b64decode(token).decode().partition(":")
        known = self.users.get(username)
        return username if known is not None and known[0] == password else None

    def _search(self, target: str, operation: str, allowed: List[str], user: str, query: Dict[str, Any]) -> httpx.Response:
        wanted = target.split(",")
        wildcard = any("*" in name for name in wanted)
        resolved = [name for name in self.indices if any(fnmatchcase(name, w) for w in wanted)]
        readable = [name for name in resolved if any(fnmatchcase(name, a) for a in allowed)]
        denied = _error(
            403, "security_exception",
            f"no permissions for [{SEARCH_ACTION}] and User [name={user}, backend_roles=[], requestedTenant=null]",
        )
        if not resolved and not wildcard:
            if any(fnmatchcase(target, a) for a in allowed):
                return _error(404, "index_not_found_exception", f"no such index [{target}]", index=target)
            return denied
        if resolved and not readable:
            return denied
        if not readable:
            body: Dict[str, Any] = {"_shards": _shards(0, 0)}
            if operation == "_count":
                return httpx.Response(200, json={"count": 0, **body})
            return httpx.Response(200, json={
                "took": 0, "timed_out": False, **body,
                "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": 0.0, "hits": []},
            })
        return self._hits(readable, operation, query)

    def _hits(self, readable: List[str], operation: str, query: Dict[str, Any]) -> httpx.Response:
        sort = query.get("sort") or []
        field = next(iter(sort[0])) if sort else "timestamp"
        if sort and not any(field in self.indices[name] for name in readable):
            cause = {"type": "query_shard_exception", "reason": f"No mapping found for [{field}] in order to sort on"}
            return httpx.Response(400, json={"status": 400, "error": {
                "root_cause": [cause], "type": "search_phase_execution_exception", "reason": "all shards failed",
                "phase": "can_match", "grouped": True, "caused_by": cause,
            }})
        values = sorted(
            ((value, name) for name in readable for value in self.indices[name].get(field, [])), reverse=True
        )
        total = sum(len(v) for name in readable for v in self.indices[name].values())
        shards = {"_shards": _shards(len(readable), self.failed_shards)}
        if operation == "_count":
            return httpx.Response(200, json={"count": total, **shards})
        hits = [
            {"_index": name, "_id": f"doc-{i}", "_score": None, "sort": [_millis(value)]}
            for i, (value, name) in enumerate(values[: int(query.get("size", 10))])
        ]
        body: Dict[str, Any] = {
            "took": 3, "timed_out": False, **shards,
            "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": hits},
        }
        aggregations = {
            name: _date_range_from_now(self.clock())
            for name, spec in (query.get("aggs") or {}).items()
            if "date_range" in spec
        }
        if aggregations:
            body["aggregations"] = aggregations
        return httpx.Response(200, json=body)


def _shards(total: int, failed: int) -> Dict[str, int]:
    return {"total": total, "successful": total - failed, "skipped": 0, "failed": failed}


def _date_range_from_now(now: datetime) -> Dict[str, Any]:
    stamp = now.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"buckets": [{"key": f"{stamp}-*", "from": float(_millis(now)), "from_as_string": stamp, "doc_count": 0}]}


def _error(status: int, kind: str, reason: str, **extra: Any) -> httpx.Response:
    cause = {"type": kind, "reason": reason, **extra}
    return httpx.Response(status, json={"error": {"root_cause": [cause], **cause}, "status": status})
