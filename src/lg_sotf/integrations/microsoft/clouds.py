"""Microsoft clouds: the fixed sign-in, Graph and Defender hosts of each cloud.

Hosts are constants of this module and nothing else: no tenant setting and
no integration config ever holds a URL, so stored credentials can only ever
be sent to Microsoft (a tenant able to choose the token endpoint could
exfiltrate the client secret or a signed assertion).

=================  =========================  =========================  =========================================
cloud              sign-in                    Microsoft Graph            Defender for Endpoint API
=================  =========================  =========================  =========================================
``global``         login.microsoftonline.com  graph.microsoft.com        api.security.microsoft.com, or the geo
                                                                         host ``{geo}.api.security.microsoft.com``
``usgov_gcc_high`` login.microsoftonline.us   graph.microsoft.us         not supported in 1.1
``usgov_dod``      login.microsoftonline.us   dod-graph.microsoft.us     not supported in 1.1
=================  =========================  =========================  =========================================

``global`` also covers GCC tenants: Microsoft 365 GCC uses the worldwide
sign-in and Graph endpoints. GCC tenants whose Defender for Endpoint runs on
``api-gcc`` are out of scope, as is the China cloud: no Microsoft Learn page
documents a token scope for the US Government Defender hosts, so LG-SOTF does
not guess one.

The Defender token is requested for the legacy resource
``https://api.securitycenter.microsoft.com`` (Microsoft: some Defender for
Endpoint APIs still require that audience even when called on
``api.security.microsoft.com``; a wrong audience answers 403).
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import FrozenSet, Literal, Mapping, Optional, Tuple

Cloud = Literal["global", "usgov_gcc_high", "usgov_dod"]
Api = Literal["graph", "defender"]
APIS: Tuple[Api, ...] = ("graph", "defender")
DEFENDER_GEOS: Tuple[str, ...] = ("us", "eu", "uk", "au", "swa", "ina", "aea")
DEFENDER_HOST = "api.security.microsoft.com"
DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default"


@dataclass(frozen=True)
class CloudProfile:
    """The fixed endpoints of one Microsoft cloud."""

    name: Cloud
    login_host: str
    graph_host: str
    graph_scope: str
    defender_supported: bool
    defender_scope: Optional[str]

    def defender_host(self, geo: Optional[str]) -> str:
        """``api.security.microsoft.com``, or ``{geo}.api.security.microsoft.com`` for a geo in :data:`DEFENDER_GEOS`.

        Raises ``ValueError`` for a cloud without Defender support or an unknown geo.
        """
        if not self.defender_supported:
            raise ValueError(f"the Defender for Endpoint API is not supported in the {self.name} cloud")
        if geo is None:
            return DEFENDER_HOST
        if geo not in DEFENDER_GEOS:
            raise ValueError(f"unknown Defender geo {str(geo)[:16]!r}")
        return f"{geo}.{DEFENDER_HOST}"

    def host(self, api: Api, geo: Optional[str] = None) -> str:
        """The API host for ``api`` (``geo`` only applies to Defender)."""
        if api == "graph":
            return self.graph_host
        if api == "defender":
            return self.defender_host(geo)
        raise ValueError(f"unknown Microsoft API {str(api)[:16]!r}")

    def scope(self, api: Api) -> str:
        """The client-credentials ``scope`` for one API (one token per resource)."""
        if api == "graph":
            return self.graph_scope
        if api == "defender" and self.defender_scope:
            return self.defender_scope
        raise ValueError(f"no token scope for {str(api)[:16]!r} in the {self.name} cloud")

    def token_url(self, directory_tenant_id: str) -> str:
        """The tenant-specific v2.0 token endpoint (never ``common`` or ``organizations``)."""
        return f"https://{self.login_host}/{directory_tenant_id}/oauth2/v2.0/token"


def _profile(name: Cloud, login: str, graph: str, *, defender: bool) -> CloudProfile:
    return CloudProfile(
        name=name,
        login_host=login,
        graph_host=graph,
        graph_scope=f"https://{graph}/.default",
        defender_supported=defender,
        defender_scope=DEFENDER_SCOPE if defender else None,
    )


CLOUDS: Mapping[Cloud, CloudProfile] = MappingProxyType(
    {
        "global": _profile("global", "login.microsoftonline.com", "graph.microsoft.com", defender=True),
        "usgov_gcc_high": _profile("usgov_gcc_high", "login.microsoftonline.us", "graph.microsoft.us", defender=False),
        "usgov_dod": _profile("usgov_dod", "login.microsoftonline.us", "dod-graph.microsoft.us", defender=False),
    }
)
ALL_CLOUDS: FrozenSet[Cloud] = frozenset(CLOUDS)
GLOBAL_ONLY: FrozenSet[Cloud] = frozenset({"global"})


def cloud_profile(name: str) -> CloudProfile:
    """The profile of a cloud name; ``ValueError`` for an unknown one."""
    for key, profile in CLOUDS.items():
        if key == name:
            return profile
    raise ValueError(f"unknown Microsoft cloud {str(name)[:32]!r}")


def fixed_hosts() -> FrozenSet[str]:
    """Every host the Microsoft connector may ever contact (for tests and the security docs)."""
    hosts: set[str] = set()
    for profile in CLOUDS.values():
        hosts.update((profile.login_host, profile.graph_host))
        if profile.defender_supported:
            hosts.add(DEFENDER_HOST)
            hosts.update(f"{geo}.{DEFENDER_HOST}" for geo in DEFENDER_GEOS)
    return frozenset(hosts)


__all__ = [
    "ALL_CLOUDS",
    "APIS",
    "CLOUDS",
    "DEFENDER_GEOS",
    "DEFENDER_HOST",
    "DEFENDER_SCOPE",
    "GLOBAL_ONLY",
    "Api",
    "Cloud",
    "CloudProfile",
    "cloud_profile",
    "fixed_hosts",
]
