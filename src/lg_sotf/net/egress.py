"""Where outbound connections may go (SSRF egress policy).

Source, integration and webhook URLs are tenant-controlled, so every outbound request is checked
before it is sent:

* the scheme must be ``https`` in staging/production (``http`` is allowed in
  development only);
* the host is resolved and **every** address it resolves to must be
  allowed. Loopback, link-local (which includes the cloud metadata endpoint
  169.254.169.254), multicast, unspecified and reserved addresses, and the
  known metadata addresses, are always refused. Other non-global addresses
  (RFC 1918, CGNAT, unique-local IPv6) are refused unless the install sets
  ``ingestion.allow_private_destinations`` (on-prem installs whose SIEM sits
  on a private network);
* the connection is made to the address that was checked (the request is
  pinned to it, with the original name kept for the ``Host`` header, SNI
  and certificate verification), so a DNS answer that changes between the
  check and the connect cannot redirect the request.

Refusals carry one generic message so they cannot be used to map the
internal network.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Awaitable, Callable, List, Optional, Sequence, Tuple, Union

import httpx

from lg_sotf.errors import SourceConfigError
from lg_sotf.settings import IngestionSection, Settings

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Resolver = Callable[[str, int], Awaitable[Sequence[str]]]

REFUSED_MESSAGE = "source destination is not allowed"
_METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a)
    for a in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "192.0.0.192")
)
_DEFAULT_PORTS = {"https": 443, "http": 80}


class DestinationRefused(SourceConfigError):
    """The source URL points somewhere connectors may not go."""

    def __init__(self, message: str = REFUSED_MESSAGE):
        super().__init__(message)


async def system_resolve(host: str, port: int) -> List[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise httpx.ConnectError(f"could not resolve host ({type(exc).__name__})") from exc
    return [str(info[4][0]) for info in infos]


@dataclass(frozen=True)
class DestinationPolicy:
    require_https: bool
    allow_private: bool = False

    def check_url(self, url: Union[str, httpx.URL]) -> Tuple[str, int]:
        """Scheme and shape checks; returns (host, port)."""
        try:
            parsed = httpx.URL(url) if isinstance(url, str) else url
        except httpx.InvalidURL as exc:
            raise SourceConfigError("source URL is not a valid URL") from exc
        scheme = parsed.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            raise SourceConfigError("source URL must be http(s)")
        if scheme != "https" and self.require_https:
            raise SourceConfigError("source URLs must use https in staging and production")
        if parsed.userinfo:
            raise SourceConfigError("source URL must not contain credentials")
        host = parsed.host
        if not host:
            raise SourceConfigError("source URL has no host")
        return host, parsed.port or _DEFAULT_PORTS[scheme]

    def address_allowed(self, address: IPAddress) -> bool:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if address in _METADATA_ADDRESSES:
            return False
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            return False
        if not address.is_global:
            return self.allow_private
        return True

    async def resolve_allowed(self, host: str, port: int, resolver: Resolver) -> str:
        """The address to connect to; raises :class:`DestinationRefused` if any resolved address is refused."""
        literal = _ip_literal(host)
        candidates = [str(literal)] if literal is not None else list(await resolver(host, port))
        if not candidates:
            raise httpx.ConnectError("host resolved to no addresses")
        chosen: Optional[str] = None
        for candidate in candidates:
            address = _ip_literal(candidate)
            if address is None or not self.address_allowed(address):
                raise DestinationRefused()
            chosen = chosen or str(address)
        assert chosen is not None
        return chosen

    async def check(self, url: Union[str, httpx.URL], resolver: Resolver) -> None:
        host, port = self.check_url(url)
        await self.resolve_allowed(host, port, resolver)


def egress_policy(settings: Settings, *, require_https: Optional[bool] = None) -> DestinationPolicy:
    """The install's destination policy for integrations, webhooks and Microsoft Graph.

    ``require_https`` defaults to ``settings.is_production``. Private
    destinations follow ``ingestion.allow_private_destinations``, read
    leniently: if the ``ingestion`` section is invalid (any key, not only this
    one) they are refused, and no error is raised, so a typo in an unrelated
    ingestion limit fails closed instead of stopping the API or the scheduler.
    Pull sources read the section strictly through
    :class:`~lg_sotf.ingestion.options.IngestionOptions` instead (ADR-0007).
    """
    try:
        allow_private = IngestionSection.model_validate(settings.ingestion or {}).allow_private_destinations
    except ValueError:  # pydantic's ValidationError; net does not import pydantic itself
        allow_private = False
    return DestinationPolicy(
        require_https=settings.is_production if require_https is None else require_https,
        allow_private=allow_private,
    )


def ip_literal(value: str) -> Optional[IPAddress]:
    """The address ``value`` spells (``[::1]`` and zone ids accepted), or None when it is a name."""
    return _ip_literal(value)


def _ip_literal(value: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


class GuardedTransport(httpx.AsyncBaseTransport):
    """Applies a :class:`DestinationPolicy` to every request before handing it on.

    With ``pin=True`` the request URL's host is replaced by the checked
    address; the ``Host`` header (set when the request was built) and the
    ``sni_hostname`` extension keep the original name for routing and TLS.
    Injected test transports are wrapped with ``pin=False`` so they still see
    the original host.
    """

    def __init__(
        self, inner: httpx.AsyncBaseTransport, policy: DestinationPolicy, resolver: Resolver, *, pin: bool
    ):
        self._inner = inner
        self._policy = policy
        self._resolver = resolver
        self._pin = pin

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host, port = self._policy.check_url(request.url)
        address = await self._policy.resolve_allowed(host, port, self._resolver)
        if self._pin and _ip_literal(host) is None:
            request.extensions = {**request.extensions, "sni_hostname": host}
            request.url = request.url.copy_with(host=address)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
