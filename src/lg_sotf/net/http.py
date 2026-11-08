"""The two pieces every outbound HTTP stack shares: the guarded client builder and the capped body read.

* :func:`guarded_client` builds the ``httpx.AsyncClient`` of the stacks whose
  destinations are tenant-controlled (pull sources, integrations, response
  webhooks, Microsoft Graph and Defender): every request goes through
  :class:`~lg_sotf.net.egress.GuardedTransport`, redirects are never
  followed, and the timeout and ``User-Agent`` are always set.
* :func:`read_capped` reads a streamed response body up to a byte limit and
  raises :class:`ResponseTooLarge` beyond it, so a hostile or broken server
  cannot make the process buffer an unbounded body. Every stack uses it, the
  MCP client, the enrichment providers and the OIDC key fetch included.

Each stack keeps its own retry, idempotency and ``Retry-After`` rules and maps
:class:`ResponseTooLarge` to its own error (``docs/architecture.md`` §12 has
the table).
"""

from __future__ import annotations

from typing import List, Mapping, Optional

import httpx

from lg_sotf.net.egress import DestinationPolicy, GuardedTransport, Resolver, system_resolve
from lg_sotf.net.tls import Verify
from lg_sotf.security.shadow import REFUSE, egress


class ResponseTooLarge(Exception):
    """A response body is larger than the caller's limit (its text carries the limit only)."""

    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"response body exceeds {max_bytes} bytes")
        self.max_bytes = max_bytes


async def read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    """The body of a streamed ``response``, at most ``max_bytes`` long; raises :class:`ResponseTooLarge` beyond.

    When the body is not content-encoded, a ``Content-Length`` above the limit
    is refused before any byte is read (the declared length is then exactly
    what would be read). Otherwise the decoded bytes are counted as they
    arrive and reading stops at the first chunk past the limit. The caller
    owns the response and closes it (``async with client.stream(...)``, or
    ``aclose()`` in a ``finally``).
    """
    if response.headers.get("Content-Encoding", "identity").strip().lower() in ("", "identity"):
        declared = response.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            raise ResponseTooLarge(max_bytes)
    chunks: List[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise ResponseTooLarge(max_bytes)
        chunks.append(chunk)
    return b"".join(chunks)


@egress("http", REFUSE)
def guarded_client(
    *,
    policy: Optional[DestinationPolicy],
    verify: Verify,
    user_agent: str,
    timeout: httpx.Timeout,
    base_url: Optional[str] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    resolver: Optional[Resolver] = None,
    pin: bool,
    headers: Optional[Mapping[str, str]] = None,
) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` that sends every request through ``policy`` and never follows a redirect.

    ``verify`` is used as given: callers that open a client per request pass
    a cached context (:class:`~lg_sotf.net.tls.TlsContexts`). Without a
    ``transport`` the client gets a real ``httpx.AsyncHTTPTransport``; an
    injected one is a test hook, and its callers pass ``pin=False`` so it sees
    the original host. ``pin=True`` connects to the address the policy
    checked (see :class:`~lg_sotf.net.egress.GuardedTransport`).

    ``policy=None`` skips the destination check. Only the pull-source client
    accepts that, for its retry-loop unit tests; every runtime caller passes
    the install's policy.
    """
    inner = transport if transport is not None else httpx.AsyncHTTPTransport(verify=verify)  # noqa: TID251
    routed: httpx.AsyncBaseTransport = (
        inner if policy is None else GuardedTransport(inner, policy, resolver or system_resolve, pin=pin)
    )
    return httpx.AsyncClient(
        base_url=base_url if base_url is not None else "",
        verify=verify,
        timeout=timeout,
        transport=routed,
        follow_redirects=False,
        headers={"User-Agent": user_agent, **(headers or {})},
    )
