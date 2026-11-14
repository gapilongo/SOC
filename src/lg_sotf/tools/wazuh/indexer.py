"""Where the evidence templates are answered: a backend, and the client for a tenant's Wazuh indexer (INT3.4).

A :class:`Backend` answers a search body. Two exist: :class:`IndexerClient` here, for a tenant's own Wazuh
indexer (OpenSearch), and the evaluation harness's event store (``lg_sotf.eval.wazuh_events``), which
answers the same bodies from a dataset's telemetry. Both refuse a body that fails
:func:`lg_sotf.tools.wazuh.dsl.check_search`.

:class:`IndexerClient` can do one thing: ``POST /<index>/_search``. The base URL, the index pattern and
the credentials are the tenant's source configuration, given when the client is built; no parameter of a
tool reaches the URL. Every request goes through the install's destination policy
(:class:`lg_sotf.net.egress.PolicyTransport`: https outside development, every resolved address checked,
the connection pinned to it), redirects are never followed, the response body is capped, and at most two
searches run at once. A failed search is not retried: it is a missing fact, never a retry storm.

:meth:`IndexerClient.search` is the ``wazuh_indexer`` egress boundary. It also runs in a shadow run: it
reads the tenant's own system, tells no third party anything and changes nothing, and a candidate
investigated without evidence could not be compared with production (ADR 0014 section 3.2).
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

import httpx

from lg_sotf.errors import SourceConfigError
from lg_sotf.net.egress import DestinationPolicy, PolicyTransport, Resolver, system_resolve
from lg_sotf.net.http import ResponseTooLarge, read_capped
from lg_sotf.net.tls import Verify
from lg_sotf.security.shadow import allow, egress
from lg_sotf.tools.wazuh.dsl import Clause, all_of, check_search

EGRESS_BOUNDARY = "wazuh_indexer"
READS_IN_SHADOW = allow(
    "reads the tenant's own Wazuh indexer with POST _search only: no third party is told anything, nothing is changed"
)
INDEX = re.compile(r"^[a-z0-9*][a-z0-9*_.,-]{0,254}$")
"""An index name or pattern: the rule of the Wazuh pull source (``lg_sotf.ingestion.sources.wazuh``)."""
USER_AGENT = "lg-sotf-evidence/1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CONCURRENT_SEARCHES = 2
DEFAULT_TIMEOUT_S = 10.0
_SCOPE_FIELD = re.compile(r"^agent\.[A-Za-z0-9_.]{1,64}$")
_STATUS_REASONS = {401: "credentials_refused", 403: "credentials_refused", 404: "index_not_found", 429: "rate_limited"}


class IndexerUnavailable(Exception):
    """A backend gave no answer. ``reason`` is a short fixed code: never a URL, a credential or a response body."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Backend(Protocol):
    """What answers the templates: the tenant's indexer, or a dataset's telemetry."""

    @property
    def lag(self) -> timedelta:
        """How long after an alert's time the backend may still receive it: a window is closed once this has passed."""
        ...

    def now(self) -> datetime: ...

    async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """The search response for an allow-listed ``body``; raises :class:`IndexerUnavailable` without one."""
        ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _scope(clauses: Sequence[Clause]) -> List[Clause]:
    """The tenant's fixed filters: ``term`` or ``terms`` on an ``agent.*`` field, from configuration only."""
    for clause in clauses:
        spec = clause.get("term", clause.get("terms"))
        field, value = next(iter(spec.items())) if isinstance(spec, dict) and len(spec) == 1 else ("", None)
        listed = value if isinstance(value, list) and "terms" in clause else [value]
        if len(clause) != 1 or not _SCOPE_FIELD.fullmatch(field) or not listed or not all(isinstance(v, str) for v in listed):
            raise SourceConfigError("a Wazuh evidence scope filters on an agent field")
    return [dict(clause) for clause in clauses]


class IndexerClient:
    def __init__(
        self,
        *,
        base_url: str,
        index: str,
        username: str,
        password: str,
        policy: DestinationPolicy,
        verify: Verify = True,
        lag: timedelta = timedelta(0),
        scope: Sequence[Clause] = (),
        timeout_s: float = DEFAULT_TIMEOUT_S,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        resolver: Optional[Resolver] = None,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        """``scope`` is added to every search (a tenant on a shared cluster; no source setting provides one
        yet, INT3.2). ``transport`` is a test hook: it still goes through ``policy``, only unpinned."""
        policy.check_url(base_url)
        if not INDEX.fullmatch(index):
            raise SourceConfigError("wazuh config.index must be an index name or pattern")
        if not username or not password:
            raise SourceConfigError("wazuh source requires the 'username' and 'password' credentials")
        self._base_url = base_url
        self._path = f"/{index}/_search"
        self._authorization = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        self._policy = policy
        self._verify = verify
        self._lag = lag
        self._scope = _scope(scope)
        self._timeout_s = timeout_s
        self._transport = transport
        self._resolver = resolver or system_resolve
        self._now = now
        self._http: Optional[httpx.AsyncClient] = None
        self._slots = asyncio.Semaphore(MAX_CONCURRENT_SEARCHES)

    def __repr__(self) -> str:
        return f"IndexerClient(path={self._path!r})"

    @property
    def lag(self) -> timedelta:
        return self._lag

    def now(self) -> datetime:
        return self._now()

    @egress(EGRESS_BOUNDARY, READS_IN_SHADOW)
    async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """One read-only search on the tenant's index pattern, with the tenant's scope in front of its filters."""
        check_search(body)
        scoped = {**body, "query": all_of(*self._scope, *body["query"]["bool"]["filter"])}
        if self._http is None:
            # The one client built outside guarded_client: it is behind this boundary and the same policy.
            inner = self._transport or httpx.AsyncHTTPTransport(verify=self._verify)  # noqa: TID251
            self._http = httpx.AsyncClient(
                base_url=self._base_url,
                transport=PolicyTransport(inner, self._policy, self._resolver, pin=self._transport is None),
                follow_redirects=False,
                timeout=httpx.Timeout(self._timeout_s, connect=min(5.0, self._timeout_s)),
                headers={"User-Agent": USER_AGENT, "Accept": "application/json", "Authorization": self._authorization},
            )
        async with self._slots:
            status, raw = await self._post(self._http, scoped)
        if status >= 400:
            raise IndexerUnavailable(_STATUS_REASONS.get(status, "indexer_error" if status >= 500 else "request_refused"))
        try:
            answer = json.loads(raw)
        except ValueError:
            answer = None
        if not isinstance(answer, dict):
            raise IndexerUnavailable("bad_response")
        shards = answer.get("_shards")
        if isinstance(shards, dict) and shards.get("total") == 0:  # the pattern matches no index: nothing was searched
            raise IndexerUnavailable("index_not_found")
        return answer

    async def _post(self, http: httpx.AsyncClient, body: Dict[str, Any]) -> Tuple[int, bytes]:
        try:
            async with asyncio.timeout(self._timeout_s * 2):
                async with http.stream("POST", self._path, json=body) as response:
                    return response.status_code, await read_capped(response, MAX_RESPONSE_BYTES)
        except SourceConfigError:  # the destination policy refused the address the host resolved to
            raise IndexerUnavailable("destination_refused") from None
        except ResponseTooLarge:
            raise IndexerUnavailable("response_too_large") from None
        except (httpx.TimeoutException, TimeoutError):
            raise IndexerUnavailable("timeout") from None
        except httpx.HTTPError:
            raise IndexerUnavailable("unreachable") from None

    async def aclose(self) -> None:
        http, self._http = self._http, None
        if http is not None:
            await http.aclose()
