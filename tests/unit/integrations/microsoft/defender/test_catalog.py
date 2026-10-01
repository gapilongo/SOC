"""The Defender package's capabilities: catalog invariants, declared actions, excludes, options, docs, hygiene."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.integrations.config import IntegrationConfigError, validate_config
from lg_sotf.integrations.microsoft import catalog
from lg_sotf.integrations.microsoft.catalog import check_invariants
from lg_sotf.integrations.microsoft.clouds import GLOBAL_ONLY
from lg_sotf.integrations.microsoft.defender import CAPABILITIES
from lg_sotf.services.response import ACTION_CATALOG
from tests.fixtures.microsoft import fake_config

ROOT = Path(__file__).resolve().parents[5]
DOC = ROOT / "docs" / "microsoft-defender.md"
PACKAGE = ROOT / "src" / "lg_sotf" / "integrations" / "microsoft" / "defender"
TESTS = Path(__file__).resolve().parent
FLOW = ROOT / "tests" / "integration" / "integrations" / "microsoft" / "test_defender_flow.py"

EXPECTED = {
    "defender.isolation": ({"isolate_host": True, "release_host": False}, {"Machine.Isolate", "Machine.ReadWrite.All"}),
    "defender.indicators": (
        {"block_ip": True, "block_domain": True, "block_url": True, "unblock_ip": False, "unblock_domain": False,
         "unblock_url": False},
        {"Ti.ReadWrite.All"},
    ),
    "defender.file_indicators": ({"quarantine_file": True, "unblock_file": False}, {"Ti.ReadWrite.All"}),
    "defender.stop_quarantine": ({"quarantine_file": False}, {"Machine.StopAndQuarantine", "Machine.ReadWrite.All"}),
    "defender.forensics": ({"collect_forensics": False}, {"Machine.CollectForensics", "Machine.ReadWrite.All"}),
}


def test_the_package_exports_its_five_capabilities_and_they_pass_the_invariants() -> None:
    assert [spec.key for spec in CAPABILITIES] == list(EXPECTED)
    assert set(check_invariants(CAPABILITIES)) == set(EXPECTED)
    merged = catalog.capabilities()
    assert all(merged[key] is spec for key, spec in ((s.key, s) for s in CAPABILITIES))


@pytest.mark.parametrize("spec", CAPABILITIES, ids=lambda s: s.key)
def test_declarations(spec: Any) -> None:
    actions, roles = EXPECTED[spec.key]
    assert spec.package == "defender" and spec.api == "defender" and spec.clouds == GLOBAL_ONLY
    assert {t: s.reversible for t, s in spec.actions.items()} == actions
    assert {p.role for p in spec.permissions} == roles
    assert all(p.api == "defender" and p.required and p.purpose for p in spec.permissions)
    assert all(t in ACTION_CATALOG for t in spec.actions)
    assert spec.title and spec.description and spec.licence
    catalog.spec_out(spec)  # renders for the catalog endpoint


def test_file_indicators_and_stop_quarantine_exclude_each_other() -> None:
    specs = {s.key: s for s in CAPABILITIES}
    assert specs["defender.file_indicators"].excludes == ("defender.stop_quarantine",)
    assert specs["defender.stop_quarantine"].excludes == ("defender.file_indicators",)
    both = {key: {"enabled": True, "live": False, "options": {}}
            for key in ("defender.file_indicators", "defender.stop_quarantine")}
    config, _ = fake_config(capabilities=both)
    with pytest.raises(IntegrationConfigError):
        validate_config("microsoft", config, require_https=True)
    one = dict(both)
    one["defender.stop_quarantine"] = {"enabled": False, "live": False, "options": {}}
    config, _ = fake_config(capabilities=one)
    assert validate_config("microsoft", config, require_https=True)["capabilities"]["defender.file_indicators"]["enabled"]


def check(capabilities: Dict[str, Any], **overrides: Any) -> Dict[str, Any]:
    config, _ = fake_config(capabilities=capabilities, **overrides)
    return validate_config("microsoft", config, require_https=True)


def test_options_are_validated_and_normalised() -> None:
    normalised = check({"defender.indicators": {"enabled": True, "live": True,
                                                "options": {"expiration_days": 7, "rbac_group_names": [" A ", "A"]}}})
    assert normalised["capabilities"]["defender.indicators"]["options"] == {
        "expiration_days": 7, "severity": "High", "generate_alert": True, "rbac_group_names": ["A"],
    }
    for options in ({"expiration_days": 0}, {"expiration_days": 366}, {"severity": "Critical"},
                    {"rbac_group_names": ["x"] * 51}, {"rbac_group_names": ["bad\nname"]}, {"unknown": 1}):
        with pytest.raises(IntegrationConfigError):
            check({"defender.indicators": {"enabled": True, "options": options}})
    for options in ({"isolation_type": "UnManagedDevice"}, {"isolation_type": "full"}):
        with pytest.raises(IntegrationConfigError):
            check({"defender.isolation": {"enabled": True, "options": options}})
    with pytest.raises(IntegrationConfigError):
        check({"defender.stop_quarantine": {"enabled": True, "options": {"max_machines": 51}}})


def test_defender_capabilities_are_refused_outside_the_global_cloud() -> None:
    with pytest.raises(IntegrationConfigError):
        check({"defender.isolation": {"enabled": True}}, cloud="usgov_gcc_high")


def test_every_permission_is_documented() -> None:
    text = DOC.read_text(encoding="utf-8")
    for spec in CAPABILITIES:
        assert f"`{spec.key}`" in text
        for permission in spec.permissions:
            assert f"`{permission.role}`" in text, permission.role
    for section in ("Overview", "Actions and Microsoft calls", "Permissions and setup", "Verification", "Rollback",
                    "Limits and licensing", "Troubleshooting"):
        assert re.search(rf"^## \d+\. {section}$", text, re.MULTILINE), section


GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.")
ASSIGNED = re.compile(r"(client_secret|password|private_key_pem|access_token)\s*[=:]\s*[\"'][^\"']{4,}[\"']", re.I)


def test_no_credential_shaped_literals() -> None:
    files = sorted(PACKAGE.glob("*.py")) + sorted(TESTS.glob("*.py")) + [DOC, FLOW]
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not GUID.search(text), path
        assert not JWT.search(text), path
        assert not ASSIGNED.search(text), path
        assert "-" * 5 + "BEGIN" not in text, path  # no PEM material: certificates and keys are generated
