"""The capability catalog: invariants, executor selection, JSON for the UI."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List

import pytest
from pydantic import Field

from lg_sotf.integrations.microsoft import catalog
from lg_sotf.integrations.microsoft.capability import (
    ActionSupport,
    CapabilityOptions,
    CapabilitySpec,
    Permission,
    action_marker,
    option_problems,
)
from lg_sotf.integrations.microsoft.catalog import CatalogError, check_invariants, override_for_tests
from lg_sotf.integrations.microsoft.clouds import ALL_CLOUDS
from tests.unit.integrations.microsoft._support import ACCOUNT, FAKE_SPECS, ISOLATION


def variant(spec: CapabilitySpec, **changes: Any) -> CapabilitySpec:
    return dataclasses.replace(spec, **changes)


def test_the_real_packages_load_the_fixed_capability_keys() -> None:
    # The other framework tests run on FAKE_SPECS; this one pins the merged packages to the shared spec's key table.
    reversible = {
        key: sorted(t for t, support in spec.actions.items() if support.reversible)
        for key, spec in catalog.capabilities().items()
    }
    assert reversible == {
        "mail.remediate": ["purge_message"],
        "mail.notify": [],
        "entra.account": ["disable_user"],
        "entra.sessions": [],
        "entra.password": [],
        "entra.risk": ["confirm_compromised"],
        "defender.isolation": ["isolate_host"],
        "defender.indicators": ["block_domain", "block_ip", "block_url"],
        "defender.file_indicators": ["quarantine_file"],
        "defender.stop_quarantine": [],
        "defender.forensics": [],
    }
    assert catalog.capabilities()["defender.file_indicators"].excludes == ("defender.stop_quarantine",)
    assert catalog.capabilities()["defender.stop_quarantine"].excludes == ("defender.file_indicators",)


def test_fake_catalog_is_valid() -> None:
    assert set(check_invariants(FAKE_SPECS)) == {"defender.fake_isolation", "entra.fake_account"}


@pytest.mark.parametrize(
    ("specs", "message"),
    [
        ((ISOLATION, ISOLATION), "duplicate capability key"),
        ((variant(ISOLATION, key="mail.fake_isolation"),), "key must be"),
        ((variant(ISOLATION, key="defender"),), "key must be"),
        ((variant(ISOLATION, actions={"isolate_host": ActionSupport(reversible=True)}),), "release_host is not listed"),
        ((variant(ISOLATION, actions={"launch_missiles": ActionSupport()}),), "not in ACTION_CATALOG"),
        ((variant(ACCOUNT, actions={"reset_password": ActionSupport(reversible=True)}),), "has no inverse"),
        ((variant(ISOLATION, permissions=(Permission("exchange", "X", "y"),)),), "unknown api"),  # type: ignore[arg-type]
        ((variant(ISOLATION, clouds=ALL_CLOUDS),), "not supported in every cloud"),
        ((variant(ISOLATION, clouds=frozenset()),), "non-empty subset"),
        ((variant(ISOLATION, excludes=("defender.nope",)),), "excludes unknown capability"),
        ((ISOLATION, variant(ACCOUNT, key="entra.second", actions=dict(ISOLATION.actions))), "without excluding each other"),
    ],
)
def test_invariants(specs: Any, message: str) -> None:
    with pytest.raises(CatalogError) as exc:
        check_invariants(specs)
    assert message in str(exc.value)


def test_mutually_excluding_capabilities_may_share_a_type() -> None:
    second = variant(ISOLATION, key="defender.fake_other", excludes=("defender.fake_isolation",),
                     actions={"isolate_host": ActionSupport()})
    assert set(check_invariants((ISOLATION, second))) == {"defender.fake_isolation", "defender.fake_other"}


def test_option_types_are_restricted() -> None:
    class Good(CapabilityOptions):
        flag: bool = False
        count: int = Field(default=1, ge=0, le=9)
        name: str = Field(default="", max_length=10)
        items: List[str] = Field(default_factory=list, max_length=5)

    class Bad(CapabilityOptions):
        count: int = 1
        ratio: float = 0.5
        required: str = Field(max_length=5)
        mapping: Dict[str, str] = Field(default_factory=dict)

    assert option_problems(Good) == []
    problems = option_problems(Bad)
    assert any("ge and le" in p for p in problems) and any("float" in p for p in problems)
    assert any("no default" in p for p in problems) and any("mapping" in p for p in problems)
    with pytest.raises(CatalogError):
        check_invariants((variant(ISOLATION, options=Bad),))


def test_executor_selection() -> None:
    config = {"capabilities": {"defender.fake_isolation": {"enabled": True, "live": False}}}
    with override_for_tests(FAKE_SPECS):
        assert catalog.executor(config, "isolate_host") is ISOLATION
        assert catalog.executor(config, "disable_user") is None  # not enabled
        assert catalog.executor(config, "disable_user", pinned=True) is ACCOUNT
        assert catalog.executor(config, "release_host", pinned=True, prefer="entra.fake_account") is ISOLATION
        assert catalog.is_enabled(config, "defender.fake_isolation") and not catalog.is_live(config, "defender.fake_isolation")
        assert catalog.executes("enable_user") and not catalog.executes("block_sender")
    assert catalog.capabilities().get("defender.fake_isolation") is None  # restored


def test_catalog_json() -> None:
    with override_for_tests(FAKE_SPECS):
        out = catalog.catalog_out()
    by_key = {c["key"]: c for c in out["capabilities"]}
    iso = by_key["defender.fake_isolation"]
    assert iso["actions"]["isolate_host"] == {
        "reversible": True, "rollback_window_s": 86_400, "note": "", "inverse": "release_host", "risk": "high",
        "restorative": False, "irreversible_note": "",
    }
    assert iso["actions"]["release_host"]["restorative"] is True
    assert iso["options_defaults"] == {"mode": "normal", "limit": 5, "note": "", "tags": []}
    assert iso["options_schema"]["properties"]["mode"]["enum"] == ["normal", "strict"]
    assert iso["clouds"] == ["global"] and iso["live_confirmation"]
    assert by_key["entra.fake_account"]["permissions"][0]["directory_role"] == "User Administrator"
    assert {c["name"] for c in out["clouds"]} == set(ALL_CLOUDS) and "eu" in out["defender_geos"]


def test_marker() -> None:
    assert action_marker("abc") == "LG-SOTF action abc"
