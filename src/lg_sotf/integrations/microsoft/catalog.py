"""The capability catalog: the mail, Entra and Defender packages' ``CAPABILITIES``, merged and checked.

Invariants (checked on first load, and by a unit test):

* keys are unique and look like ``<package>.<name>`` for the spec's package;
* every action type a capability lists is in
  :data:`~lg_sotf.services.response.ACTION_CATALOG`, and every *reversible*
  type's inverse is listed by the same capability;
* among capabilities that do not exclude each other, an action type is
  executed by at most one (so the enabled capabilities of an integration
  always name one executor per type); ``excludes`` must name existing
  capabilities and is read both ways;
* option models only use the allowed field types
  (:func:`~lg_sotf.integrations.microsoft.capability.option_problems`);
* permissions are Graph or Defender; clouds are known, and a Defender
  capability only lists clouds with Defender support.

A broken package fails loudly at import of the catalog (``CatalogError``),
never by silently dropping a capability.
"""

from __future__ import annotations

from contextlib import contextmanager
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Mapping, Optional, Sequence

from lg_sotf.integrations.microsoft.capability import CapabilitySpec, option_problems
from lg_sotf.integrations.microsoft.clouds import ALL_CLOUDS, APIS, CLOUDS, DEFENDER_GEOS

if TYPE_CHECKING:
    from lg_sotf.integrations.config import MicrosoftConfig

PACKAGES = ("mail", "entra", "defender")

_loaded: Optional[Mapping[str, CapabilitySpec]] = None
_override: Optional[Mapping[str, CapabilitySpec]] = None


class CatalogError(RuntimeError):
    """The merged capabilities break an invariant (a packaging bug)."""


def _package_specs() -> List[CapabilitySpec]:
    from lg_sotf.integrations.microsoft.defender import CAPABILITIES as DEFENDER
    from lg_sotf.integrations.microsoft.entra import CAPABILITIES as ENTRA
    from lg_sotf.integrations.microsoft.mail import CAPABILITIES as MAIL

    return [*MAIL, *ENTRA, *DEFENDER]


def _excluded(a: CapabilitySpec, b: CapabilitySpec) -> bool:
    return b.key in a.excludes or a.key in b.excludes


def check_invariants(specs: Sequence[CapabilitySpec]) -> Dict[str, CapabilitySpec]:
    """The specs by key; raises :class:`CatalogError` listing every broken invariant."""
    from lg_sotf.services.response import ACTION_CATALOG

    problems: List[str] = []
    by_key: Dict[str, CapabilitySpec] = {}
    for spec in specs:
        if not isinstance(spec, CapabilitySpec):
            problems.append(f"{spec!r} is not a CapabilitySpec")
            continue
        if spec.key in by_key:
            problems.append(f"duplicate capability key {spec.key}")
        by_key[spec.key] = spec
        package, _, name = spec.key.partition(".")
        if spec.package not in PACKAGES or package != spec.package or not name:
            problems.append(f"{spec.key}: key must be '<package>.<name>' of package {spec.package}")
        if spec.api not in APIS:
            problems.append(f"{spec.key}: unknown api {spec.api!r}")
        if not spec.actions:
            problems.append(f"{spec.key}: executes no action type")
        for action_type, support in spec.actions.items():
            catalog_spec = ACTION_CATALOG.get(action_type)
            if catalog_spec is None:
                problems.append(f"{spec.key}: {action_type} is not in ACTION_CATALOG")
                continue
            if support.reversible:
                inverse = catalog_spec.inverse
                if inverse is None:
                    problems.append(f"{spec.key}: {action_type} is marked reversible but has no inverse type")
                elif inverse not in spec.actions:
                    problems.append(f"{spec.key}: {action_type} is reversible but {inverse} is not listed")
        for permission in spec.permissions:
            if permission.api not in APIS:
                problems.append(f"{spec.key}: permission {permission.role} has unknown api {permission.api!r}")
            if not permission.role:
                problems.append(f"{spec.key}: a permission has no role")
        problems.extend(f"{spec.key}: {p}" for p in option_problems(spec.options))
        unknown_clouds = set(spec.clouds) - set(ALL_CLOUDS)
        if not spec.clouds or unknown_clouds:
            problems.append(f"{spec.key}: clouds must be a non-empty subset of {sorted(ALL_CLOUDS)}")
        uses_defender = spec.api == "defender" or any(p.api == "defender" for p in spec.permissions)
        if uses_defender and any(not CLOUDS[c].defender_supported for c in spec.clouds if c in CLOUDS):
            problems.append(f"{spec.key}: the Defender API is not supported in every cloud it lists")
    for spec in by_key.values():
        for other in spec.excludes:
            if other not in by_key:
                problems.append(f"{spec.key}: excludes unknown capability {other}")
    specs_list = list(by_key.values())
    for i, first in enumerate(specs_list):
        for second in specs_list[i + 1:]:
            if _excluded(first, second):
                continue
            shared = sorted(set(first.actions) & set(second.actions))
            if shared:
                problems.append(f"{first.key} and {second.key} both execute {', '.join(shared)} without excluding each other")
    if problems:
        raise CatalogError("; ".join(problems[:20]))
    return by_key


def capabilities() -> Mapping[str, CapabilitySpec]:
    """Every capability of the mail, Entra and Defender packages by key (invariants checked once)."""
    global _loaded
    if _override is not None:
        return _override
    if _loaded is None:
        _loaded = MappingProxyType(check_invariants(_package_specs()))
    return _loaded


def _capability_config(config: Any, key: str) -> Any:
    caps = config.get("capabilities") if isinstance(config, Mapping) else getattr(config, "capabilities", None)
    if not isinstance(caps, Mapping):
        return None
    return caps.get(key)


def _flag(entry: Any, name: str) -> bool:
    if entry is None:
        return False
    value = entry.get(name) if isinstance(entry, Mapping) else getattr(entry, name, False)
    return value is True


def is_enabled(config: Any, key: str) -> bool:
    return _flag(_capability_config(config, key), "enabled")


def is_live(config: Any, key: str) -> bool:
    entry = _capability_config(config, key)
    return _flag(entry, "enabled") and _flag(entry, "live")


def executor(
    config: MicrosoftConfig, action_type: str, *, pinned: bool = False, prefer: Optional[str] = None
) -> Optional[CapabilitySpec]:
    """The capability that executes ``action_type`` for this integration config, or ``None``.

    ``pinned=False``: the *enabled* capability executing the type (at most
    one, by the catalog invariants). ``pinned=True`` (rollbacks, retries,
    re-runs): any catalog capability executing it, preferring ``prefer``
    (the capability recorded on the row), then an enabled one.
    """
    catalog = capabilities()
    candidates = [spec for spec in catalog.values() if action_type in spec.actions]
    enabled = [spec for spec in candidates if is_enabled(config, spec.key)]
    if not pinned:
        return enabled[0] if enabled else None
    if prefer is not None and prefer in catalog and action_type in catalog[prefer].actions:
        return catalog[prefer]
    if enabled:
        return enabled[0]
    return candidates[0] if candidates else None


def executes(action_type: str) -> bool:
    """Whether any catalog capability executes ``action_type`` (``response.routes`` validation)."""
    return any(action_type in spec.actions for spec in capabilities().values())


def _action_out(action_type: str, spec: CapabilitySpec) -> Dict[str, Any]:
    from lg_sotf.services.response import ACTION_CATALOG

    support = spec.actions[action_type]
    catalog_spec = ACTION_CATALOG.get(action_type)
    return {
        "reversible": support.reversible,
        "rollback_window_s": support.rollback_window_s,
        "note": support.note,
        "inverse": catalog_spec.inverse if catalog_spec is not None else None,
        "risk": catalog_spec.risk if catalog_spec is not None else None,
        "restorative": catalog_spec.restorative if catalog_spec is not None else False,
        "irreversible_note": catalog_spec.irreversible_note if catalog_spec is not None else "",
    }


def spec_out(spec: CapabilitySpec) -> Dict[str, Any]:
    """One capability as JSON (the catalog endpoint, docs and the UI)."""
    return {
        "key": spec.key,
        "package": spec.package,
        "api": spec.api,
        "title": spec.title,
        "description": spec.description,
        "actions": {t: _action_out(t, spec) for t in spec.actions},
        "permissions": [
            {
                "api": p.api,
                "role": p.role,
                "purpose": p.purpose,
                "required": p.required,
                "when": p.when,
                "directory_role": p.directory_role,
                "exchange_rbac": p.exchange_rbac,
            }
            for p in spec.permissions
        ],
        "options_schema": spec.options.model_json_schema(),
        "options_defaults": spec.options().model_dump(mode="json"),
        "clouds": sorted(spec.clouds),
        "licence": spec.licence,
        "live_confirmation": spec.live_confirmation,
        "excludes": list(spec.excludes),
    }


def catalog_out() -> Dict[str, Any]:
    """JSON for ``GET /integrations/microsoft/catalog``: the capabilities, the clouds and the Defender geos."""
    return {
        "capabilities": [spec_out(spec) for spec in sorted(capabilities().values(), key=lambda s: s.key)],
        "clouds": [
            {"name": p.name, "login_host": p.login_host, "graph_host": p.graph_host,
             "defender_supported": p.defender_supported}
            for p in CLOUDS.values()
        ],
        "defender_geos": list(DEFENDER_GEOS),
    }


@contextmanager
def override_for_tests(specs: Sequence[CapabilitySpec]) -> Iterator[None]:
    """Replace the catalog with ``specs`` (checked) for the duration of a test."""
    global _override
    previous = _override
    _override = MappingProxyType(check_invariants(specs))
    try:
        yield
    finally:
        _override = previous


__all__ = [
    "CatalogError",
    "capabilities",
    "catalog_out",
    "check_invariants",
    "executes",
    "executor",
    "is_enabled",
    "is_live",
    "override_for_tests",
    "spec_out",
]
