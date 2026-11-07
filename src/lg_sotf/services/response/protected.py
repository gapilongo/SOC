"""Protected assets: the tenant's hosts, users, domains, networks, processes and hashes no action may touch.

:class:`ProtectedAssetsSettings` is the schema of ``tenants.settings["protected_assets"]``
(the legacy flat list and ``protected_cidrs`` are still honoured).
:class:`ProtectedAssets` matches a target in every spelling it may take
(:mod:`lg_sotf.services.response.targets`); a malformed or oversized setting
fails closed (``problems``). :func:`protected_lookup` gives connectors the
same check for the identities they resolve a target to.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Annotated, Any, Callable, FrozenSet, Iterable, List, Mapping, Optional, Tuple, Union

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    StringConstraints,
    TypeAdapter,
    ValidationError,
)

from lg_sotf.domain.actions import PROTECTED_INVALID_REASON
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.response.targets import (
    IPAddress,
    clean,
    critical_process,
    domain_key,
    embedded_ipv4,
    host_forms,
    parse_address,
    process_forms,
    url_hosts,
    user_forms,
)

log = get_logger(__name__)


IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Per list (hosts, users, domains, cidrs). Larger inventories belong in the SOAR, not in tenant settings.
MAX_PROTECTED_ENTRIES = 10_000
MAX_PROTECTED_ENTRY_CHARS = 256

MAX_POLICY_PROBLEMS = 5

_WILDCARDS = frozenset("*?[")


class _Names:
    """Exact names in a set (constant-time lookup), wildcard patterns matched with fnmatch."""

    __slots__ = ("exact", "patterns")

    def __init__(self, entries: Iterable[str]) -> None:
        exact: set[str] = set()
        patterns: List[str] = []
        for entry in entries:
            if not entry or set(entry) <= {"*", "?"}:
                continue  # a bare wildcard (e.g. the short form of "*.corp.local") would match everything
            if _WILDCARDS & set(entry):
                patterns.append(entry)
            else:
                exact.add(entry)
        self.exact = frozenset(exact)
        self.patterns = tuple(dict.fromkeys(patterns))

    def matches(self, forms: Iterable[str]) -> bool:
        for form in forms:
            if form in self.exact or any(fnmatch.fnmatchcase(form, p) for p in self.patterns):
                return True
        return False


def problem_list(prefix: str, exc: ValidationError) -> List[str]:
    out: List[str] = []
    for error in exc.errors()[:MAX_POLICY_PROBLEMS]:
        loc = ".".join(str(p) for p in error["loc"])
        out.append(f"{prefix}{'.' + loc if loc else ''}: {error['msg']}"[:200])
    return out


def _check_cidr(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("not an IP network in CIDR notation") from exc
    return value


ProtectedName = Annotated[
    StrictStr, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_PROTECTED_ENTRY_CHARS)
]
ProtectedCidr = Annotated[
    StrictStr, StringConstraints(strip_whitespace=True, min_length=1, max_length=64), AfterValidator(_check_cidr)
]


class ProtectedAssetsSettings(BaseModel):
    """Schema of ``tenants.settings["protected_assets"]``. Host and user entries may use ``*``/``?`` wildcards."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hosts: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    users: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    domains: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    cidrs: List[ProtectedCidr] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    # Process names (or wildcards) never terminated, and file hashes never quarantined, on top of
    # the built-in CRITICAL_PROCESSES (e.g. line-of-business agents, known-good binaries).
    processes: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)
    hashes: List[ProtectedName] = Field(default_factory=list, max_length=MAX_PROTECTED_ENTRIES)


LEGACY_ASSETS: TypeAdapter[List[str]] = TypeAdapter(
    Annotated[List[ProtectedName], Field(max_length=MAX_PROTECTED_ENTRIES)]
)
LEGACY_CIDRS: TypeAdapter[List[str]] = TypeAdapter(
    Annotated[List[ProtectedCidr], Field(max_length=MAX_PROTECTED_ENTRIES)]
)


@dataclass(frozen=True)
class ProtectedAssets:
    """Tenant assets no action may touch. ``problems`` non-empty means the setting is malformed (fail closed)."""

    hosts: Tuple[str, ...] = ()
    users: Tuple[str, ...] = ()
    domains: Tuple[str, ...] = ()
    networks: Tuple[IPNetwork, ...] = ()
    problems: Tuple[str, ...] = ()
    processes: Tuple[str, ...] = ()
    hashes: Tuple[str, ...] = ()
    _hosts: _Names = field(init=False, repr=False, compare=False)
    _users: _Names = field(init=False, repr=False, compare=False)
    _domains: FrozenSet[str] = field(init=False, repr=False, compare=False)
    _processes: _Names = field(init=False, repr=False, compare=False)
    _hashes: FrozenSet[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        host_entries: List[str] = []
        for host in self.hosts:
            host_entries.extend(host_forms(host))
        user_entries: List[str] = []
        for user in self.users:
            user_entries.extend(user_forms(user))
        object.__setattr__(self, "_hosts", _Names(host_entries))
        object.__setattr__(self, "_users", _Names(user_entries))
        # "*.example.com" means example.com and its subdomains, which is what every domain entry covers.
        domains = (domain_key(d[2:] if d.startswith("*.") else d) for d in self.domains)
        object.__setattr__(self, "_domains", frozenset(d for d in domains if d))
        process_entries: List[str] = []
        for process in self.processes:
            process_entries.extend(process_forms(process))
        object.__setattr__(self, "_processes", _Names(process_entries))
        object.__setattr__(self, "_hashes", frozenset(clean(h) for h in self.hashes if clean(h)))

    @property
    def invalid(self) -> bool:
        return bool(self.problems)

    @classmethod
    def from_tenant_settings(cls, tenant_settings: Mapping[str, Any]) -> ProtectedAssets:
        raw = tenant_settings.get("protected_assets")
        hosts: List[str] = []
        users: List[str] = []
        domains: List[str] = []
        cidrs: List[str] = []
        processes: List[str] = []
        hashes: List[str] = []
        problems: List[str] = []
        if isinstance(raw, Mapping):
            try:
                parsed = ProtectedAssetsSettings.model_validate(dict(raw))
            except ValidationError as exc:
                problems += problem_list("protected_assets", exc)
            else:
                hosts, users, domains, cidrs = list(parsed.hosts), list(parsed.users), list(parsed.domains), list(parsed.cidrs)
                processes, hashes = list(parsed.processes), list(parsed.hashes)
        elif raw is not None:
            # Legacy flat list: networks become CIDRs, anything else protects that exact name everywhere.
            try:
                entries = LEGACY_ASSETS.validate_python(raw)
            except ValidationError as exc:
                problems += problem_list("protected_assets", exc)
            else:
                for entry in entries:
                    if any(ch.isdigit() for ch in entry) and ("." in entry or ":" in entry) and _is_network(entry):
                        cidrs.append(entry)
                    else:
                        hosts.append(entry)
                        users.append(entry)
                        domains.append(entry)
        legacy_cidrs = tenant_settings.get("protected_cidrs")
        if legacy_cidrs is not None:
            try:
                cidrs += LEGACY_CIDRS.validate_python(legacy_cidrs)
            except ValidationError as exc:
                problems += problem_list("protected_cidrs", exc)
        if problems:
            log.warning("response.protected_assets_invalid", problems=problems[:MAX_POLICY_PROBLEMS])
        return cls(
            hosts=tuple(hosts),
            users=tuple(users),
            domains=tuple(domains),
            networks=tuple(ipaddress.ip_network(c, strict=False) for c in cidrs),
            problems=tuple(problems[:MAX_POLICY_PROBLEMS]),
            processes=tuple(processes),
            hashes=tuple(hashes),
        )

    def _host_protected(self, host: str) -> bool:
        return self._hosts.matches(host_forms(host))

    def _user_protected(self, user: str) -> bool:
        return self._users.matches(user_forms(user))

    def _domain_protected(self, domain: str) -> bool:
        labels = domain_key(domain).split(".")
        return any(".".join(labels[i:]) in self._domains for i in range(len(labels)))

    def _ip_protected(self, address: IPAddress) -> bool:
        forms: List[IPAddress] = [address]
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            forms.append(address.ipv4_mapped)
        forms += embedded_ipv4(address)
        return any(form.version == net.version and form in net for form in forms for net in self.networks)

    def _address_match(self, value: str, *, as_domain: bool) -> Optional[str]:
        address = parse_address(value)
        if address is not None and self._ip_protected(address):
            return "cidr"
        if self._host_protected(value):
            return "host"
        if as_domain and self._domain_protected(value):
            return "domain"
        return None

    def match(self, kind: str, target: str) -> Optional[str]:
        """Which protected category the target falls in, else ``None``.

        Categories: ``host``/``user``/``domain``/``cidr``/``process``/``hash``
        and ``critical_process`` (the built-in never-terminate list). IP and
        host targets are checked against CIDRs and host names; domain targets
        and URL hosts (canonicalised) also against protected domains; sender
        addresses by their domain (and subdomains) and as a whole address
        against protected users (a bare account name such as ``admin`` does
        not protect ``admin@`` every domain).
        """
        if kind == "process":
            if critical_process(target):
                return "critical_process"
            return "process" if self._processes.matches(process_forms(target)) else None
        if kind == "hash":
            return "hash" if clean(target) in self._hashes else None
        if kind == "user":
            return "user" if self._user_protected(target) else None
        if kind in ("ip", "host"):
            return self._address_match(target, as_domain=False)
        if kind == "domain":
            return self._address_match(target, as_domain=True)
        if kind == "url":
            for host in url_hosts(target):
                category = self._address_match(host, as_domain=True)
                if category is not None:
                    return category
            return None
        if kind == "email":
            address = clean(target)
            if address in self._users.exact or any(fnmatch.fnmatchcase(address, p) for p in self._users.patterns):
                return "user"
            domain = address.rsplit("@", 1)[-1]
            return self._address_match(domain, as_domain=True)
        return None


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return False
    return True


def protected_lookup(tenant_settings: Mapping[str, Any]) -> Callable[[str, str], Optional[str]]:
    """The tenant's protected assets as a connector lookup: ``lookup(kind, value)`` -> the category matched.

    A direct connector checks the identity it resolved a target to (an alias
    or object id resolved to a user) with it, because the guardrails only
    saw the literal target. A malformed list matches everything (fail closed).
    """
    assets = ProtectedAssets.from_tenant_settings(tenant_settings)

    def lookup(kind: str, value: str) -> Optional[str]:
        if assets.invalid:
            return PROTECTED_INVALID_REASON
        return assets.match(kind, value)

    return lookup
