"""Response guardrails: one row per rule, plus policy resolution and validation of tenant settings."""

from __future__ import annotations

import ipaddress
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from lg_sotf.services import response as response_module
from lg_sotf.services.response import (
    ACTION_CATALOG,
    DEFAULT_BLAST_RADIUS,
    GUARDRAIL_REASONS,
    MAX_PROTECTED_ENTRIES,
    ProtectedAssets,
    ResponsePolicy,
    ResponsePolicyError,
    approval_allowed,
    check_guardrails,
    ip_block_class,
    loose_ipv4,
    resolve_autonomy,
    validate_response_settings,
    validate_target,
)
from lg_sotf.settings import Settings

PROTECTED: Dict[str, Any] = {
    "protected_assets": {
        "hosts": ["dc-*", "WS-CEO.corp.example", "dc01.corp.local", "*.vault.internal"],
        "users": ["Administrator", "svc-*"],
        "cidrs": ["8.8.8.0/24", "2606:4700::/32", "10.1.1.0/24", "203.0.113.0/24"],
        "domains": ["example.com"],
    }
}
ALLOW_INTERNAL: Dict[str, Any] = {**PROTECTED, "response": {"allow_internal_ip_blocks": True}}
ALL_APPROVABLE: Dict[str, Any] = {**PROTECTED, "autonomy": {"critical": "approval"}}


def policy_for(make_settings: Callable[..., Settings], tenant: Optional[Dict[str, Any]] = None, **settings: Any) -> ResponsePolicy:
    return ResponsePolicy.resolve(tenant or {}, make_settings(**settings))


@pytest.mark.parametrize(
    ("action_type", "target", "tenant", "code"),
    [
        # 1. catalog and tenant allowlist
        ("launch_missiles", "x", {}, "unknown_action"),
        ("block_ip", "8.8.8.8", {"response": {"allowed_actions": ["create_ticket"]}}, "action_not_allowed"),
        ("create_ticket", "alert:a1", {"response": {"allowed_actions": ["create_ticket"]}}, None),
        # 3. syntax
        ("block_ip", "not-an-ip", {}, "invalid_ip"),
        ("block_ip", "3405803781", {}, "invalid_ip"),  # IP blocks need a canonical address
        ("block_domain", "bad domain", {}, "invalid_domain"),
        ("block_url", "javascript:alert(1)", {}, "invalid_url"),
        ("quarantine_file", "xyz", {}, "invalid_hash"),
        ("isolate_host", "ws 042; rm -rf", {}, "invalid_host"),
        ("disable_user", "jdoe\x00", {}, "invalid_user"),
        ("create_ticket", "", {}, "invalid_target"),
        # 4. IP classes
        ("block_ip", "185.220.101.44", {}, None),
        ("block_ip", "10.0.0.5", {}, "non_public_ip"),
        ("block_ip", "100.64.1.1", {}, "non_public_ip"),
        ("block_ip", "fd00::1", {}, "non_public_ip"),
        ("block_ip", "10.0.0.5", {"response": {"allow_internal_ip_blocks": True}}, None),
        ("block_ip", "127.0.0.1", {"response": {"allow_internal_ip_blocks": True}}, "unroutable_ip"),
        ("block_ip", "169.254.169.254", {"response": {"allow_internal_ip_blocks": True}}, "unroutable_ip"),
        ("block_ip", "fe80::1", {"response": {"allow_internal_ip_blocks": True}}, "unroutable_ip"),
        ("block_ip", "0.0.0.0", {"response": {"allow_internal_ip_blocks": True}}, "unroutable_ip"),  # noqa: S104
        ("block_ip", "224.0.0.1", {"response": {"allow_internal_ip_blocks": True}}, "unroutable_ip"),
        ("block_ip", "::ffff:127.0.0.1", {"response": {"allow_internal_ip_blocks": True}}, "unroutable_ip"),
        ("block_ip", "2002:a00:1::1", {}, "non_public_ip"),  # 6to4 of 10.0.0.1
        ("block_ip", "64:ff9b::cb00:7105", {"response": {"allow_internal_ip_blocks": True}}, "unroutable_ip"),
        # 5. protected assets
        ("block_ip", "8.8.8.9", PROTECTED, "protected_asset"),
        ("block_ip", "2606:4700::1111", PROTECTED, "protected_asset"),
        ("block_ip", "198.51.100.7", PROTECTED, "non_public_ip"),  # documentation range, not protected
        ("block_ip", "::ffff:8.8.8.9", PROTECTED, "protected_asset"),
        ("block_ip", "10.1.1.9", ALLOW_INTERNAL, "protected_asset"),
        ("block_ip", "2002:a01:109::1", ALLOW_INTERNAL, "protected_asset"),  # 6to4 embedding 10.1.1.9
        ("isolate_host", "DC-01", PROTECTED, "protected_asset"),
        ("isolate_host", "dc-01.corp.example", PROTECTED, "protected_asset"),
        ("isolate_host", "ws-ceo", PROTECTED, "protected_asset"),
        ("isolate_host", "ws-042", PROTECTED, None),
        ("isolate_host", "key01.vault.internal", PROTECTED, "protected_asset"),
        ("isolate_host", "vault", PROTECTED, None),  # "*.vault.internal" has no meaningful short form
        ("isolate_host", "WS⁠-CEO", PROTECTED, "invalid_host"),  # invisible characters never reach matching
        # host targets that are IP literals are checked against protected CIDRs (RR-3)
        ("isolate_host", "10.1.1.5", PROTECTED, "protected_asset"),
        ("collect_forensics", "10.1.1.5", PROTECTED, "protected_asset"),
        ("isolate_host", "10.2.1.5", PROTECTED, None),
        ("isolate_host", "3405803781", PROTECTED, "protected_asset"),  # 203.0.113.5
        # domain targets are checked against protected hosts and CIDRs too (RR-3)
        ("block_domain", "dc01.corp.local", PROTECTED, "protected_asset"),
        ("block_domain", "ws-ceo.corp.local", PROTECTED, "protected_asset"),
        ("block_domain", "203.0.113.5", PROTECTED, "protected_asset"),
        ("block_domain", "mail.example.com", PROTECTED, "protected_asset"),
        ("block_domain", "EXAMPLE.com.", PROTECTED, "protected_asset"),
        ("block_domain", "notexample.com", PROTECTED, None),
        ("block_domain", "cdn.partner.example.org", {"protected_assets": {"domains": ["*.partner.example.org"]}}, "protected_asset"),
        ("block_domain", "evil.test", PROTECTED, None),
        # URL hosts: names, IPs in every spelling a browser accepts (RR-3)
        ("block_url", "https://login.example.com/x", PROTECTED, "protected_asset"),
        ("block_url", "http://dc01.corp.local/x", PROTECTED, "protected_asset"),
        ("block_url", "http://8.8.8.5/payload", PROTECTED, "protected_asset"),
        ("block_url", "http://3405803781/", PROTECTED, "protected_asset"),
        ("block_url", "http://0xcb.0.113.5/", PROTECTED, "protected_asset"),
        ("block_url", "http://0313.0.0161.05/", PROTECTED, "protected_asset"),
        ("block_url", "http://203.28933/", PROTECTED, "protected_asset"),
        ("block_url", "http://[::ffff:203.0.113.5]/", PROTECTED, "protected_asset"),
        ("block_url", "http://%64c01.corp.local/", PROTECTED, "protected_asset"),
        ("block_url", "https://evil.test/payload", PROTECTED, None),
        ("block_url", "https://dc01.corp.local@evil.test/", PROTECTED, None),  # the real host is evil.test
        # user names in every account notation (RR-3)
        ("disable_user", "CORP\\administrator", ALL_APPROVABLE, "protected_asset"),
        ("disable_user", "administrator@corp.com", ALL_APPROVABLE, "protected_asset"),
        ("disable_user", "CN=Administrator,CN=Users,DC=corp,DC=com", ALL_APPROVABLE, "protected_asset"),
        ("disable_user", "uid=administrator,ou=people,dc=corp,dc=com", ALL_APPROVABLE, "protected_asset"),
        ("reset_password", "corp.com/Administrator", ALL_APPROVABLE, "protected_asset"),
        ("disable_user", "administrator​", ALL_APPROVABLE, "protected_asset"),
        ("disable_user", "Ａdministrator", ALL_APPROVABLE, "protected_asset"),  # fullwidth A (NFKC)
        ("reset_password", "svc-backup@corp.example", ALL_APPROVABLE, "protected_asset"),
        ("disable_user", "CN=Doe\\, John,OU=Staff,DC=corp,DC=com", ALL_APPROVABLE, None),
        ("disable_user", "jdoe", ALL_APPROVABLE, None),
        # legacy flat list and protected_cidrs
        ("isolate_host", "ws-042", {"protected_assets": ["WS-042"]}, "protected_asset"),
        ("block_ip", "185.220.101.44", {"protected_assets": ["185.220.0.0/16"]}, "protected_asset"),
        ("block_ip", "185.220.101.44", {"protected_cidrs": ["185.220.101.0/24"]}, "protected_asset"),
        # 0. malformed protected assets fail closed for every non-alert target (RR-5, RR-6)
        ("isolate_host", "ws-042", {"protected_assets": {"hosts": "dc01,dc02"}}, "protected_assets_invalid"),
        ("isolate_host", "ws-042", {"protected_assets": {"hosts": {"dc01": True}}}, "protected_assets_invalid"),
        ("isolate_host", "ws-042", {"protected_assets": {"hosts": ["dc01", 7]}}, "protected_assets_invalid"),
        ("block_ip", "185.220.101.44", {"protected_assets": {"cidrs": ["10.0.0.0/33"]}}, "protected_assets_invalid"),
        ("block_ip", "185.220.101.44", {"protected_assets": {"ips": ["185.220.101.44"]}}, "protected_assets_invalid"),
        ("block_ip", "185.220.101.44", {"protected_assets": "dc01"}, "protected_assets_invalid"),
        ("block_ip", "185.220.101.44", {"protected_cidrs": "185.220.101.0/24"}, "protected_assets_invalid"),
        ("create_ticket", "alert:a1", {"protected_assets": {"hosts": "dc01"}}, None),
        # 0. malformed guardrail settings fail closed for every action (RR-6)
        ("create_ticket", "alert:a1", {"response": {"allowed_actions": "create_ticket"}}, "response_policy_invalid"),
        ("block_ip", "8.8.8.8", {"response": {"allowed_actions": ["block-ip"]}}, "response_policy_invalid"),
        ("block_ip", "8.8.8.8", {"response": {"max_actions_per_hour": "5"}}, "response_policy_invalid"),
        ("block_ip", "8.8.8.8", {"response": {"blast_radius": {"isolate-host": 1}}}, "response_policy_invalid"),
        ("block_ip", "10.0.0.5", {"response": {"allow_internal_ip_blocks": "true"}}, "response_policy_invalid"),
        ("block_ip", "8.8.8.8", {"autonomy": {"medium": "Auto"}}, "response_policy_invalid"),
        # 6. autonomy disabled (critical is disabled by default)
        ("disable_user", "jdoe", {}, "autonomy_disabled"),
        ("disable_user", "jdoe", {"autonomy": {"critical": "approval"}}, None),
        ("block_ip", "8.8.8.8", {"autonomy": {"medium": "disabled"}}, "autonomy_disabled"),
    ],
)
def test_guardrail_table(
    make_settings: Callable[..., Settings], action_type: str, target: str, tenant: Dict[str, Any], code: Optional[str]
) -> None:
    block = check_guardrails(action_type, target, policy_for(make_settings, tenant))
    assert (block.code if block else None) == code
    if block is not None:
        assert block.code in GUARDRAIL_REASONS and block.explanation


def test_target_kind_must_match_the_action(make_settings: Callable[..., Settings]) -> None:
    policy = policy_for(make_settings)
    block = check_guardrails("block_ip", "ws-042", policy, target_kind="host")
    assert block is not None and block.code == "target_type_not_allowed"
    assert check_guardrails("isolate_host", "ws-042", policy, target_kind="host") is None


def test_every_catalog_action_has_a_target_kind_and_known_risk() -> None:
    for name, spec in ACTION_CATALOG.items():
        assert spec.risk in ("low", "medium", "high", "critical"), name
    assert set(DEFAULT_BLAST_RADIUS) <= set(ACTION_CATALOG)


def test_validate_target_is_syntax_only() -> None:
    assert validate_target("ip", "10.0.0.5") is None
    assert validate_target("ip", "nope") == "invalid_ip"
    assert ip_block_class(ipaddress.ip_address("8.8.8.8")) == "public"


@pytest.mark.parametrize(
    ("host", "address"),
    [
        ("3405803781", "203.0.113.5"),
        ("0xcb.0.113.5", "203.0.113.5"),
        ("0313.0.0161.05", "203.0.113.5"),
        ("203.28933", "203.0.113.5"),
        ("203.0.113.5.", "203.0.113.5"),
        ("0x", "0.0.0.0"),  # noqa: S104
        ("1.2.3.4.5", None),
        ("256.1.1.1", None),
        ("1_0", None),
        ("+1", None),
        ("example.com", None),
        ("12ab", None),
    ],
)
def test_loose_ipv4_follows_the_url_standard(host: str, address: Optional[str]) -> None:
    parsed = loose_ipv4(host)
    assert (str(parsed) if parsed else None) == address


def test_policy_resolution(make_settings: Callable[..., Settings]) -> None:
    tenant = {
        "autonomy": {"low": "auto"},
        "response": {"max_actions_per_hour": 500, "blast_radius": {"isolate_host": 2, "block_ip": 0}},
    }
    policy = policy_for(make_settings, tenant, response={"max_actions_per_hour_per_tenant": 40})
    assert policy.problems == ()
    assert policy.autonomy == {"low": "auto", "medium": "approval", "high": "approval", "critical": "disabled"}
    assert policy.max_actions_per_hour == 40  # a tenant can lower the install cap, never raise it
    assert policy.blast_radius["isolate_host"] == 2 and policy.blast_radius["block_ip"] == 0
    assert policy.blast_radius["disable_user"] == DEFAULT_BLAST_RADIUS["disable_user"]
    lowered = policy_for(make_settings, {"response": {"max_actions_per_hour": 5}})
    assert lowered.max_actions_per_hour == 5


class RecordingLog:
    def __init__(self) -> None:
        self.warnings: List[Tuple[str, Dict[str, Any]]] = []

    def warning(self, event: str, **kw: Any) -> None:
        self.warnings.append((event, kw))

    def info(self, event: str, **kw: Any) -> None:  # pragma: no cover - not expected here
        pass


def test_malformed_guardrail_settings_fail_closed_and_are_logged(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = RecordingLog()
    monkeypatch.setattr(response_module, "log", recorder)
    policy = policy_for(make_settings, {"response": {"allowed_actions": "create_ticket", "blast_radius": []}})
    assert policy.problems and any("allowed_actions" in p for p in policy.problems)
    logged = dict(recorder.warnings)
    assert "response.policy_invalid" in logged and logged["response.policy_invalid"]["problems"] == list(policy.problems)
    # The log carries field paths and schema messages only, never the offending values.
    assert "create_ticket" not in str(logged)
    for action_type, target in (("create_ticket", "alert:a1"), ("block_ip", "8.8.8.8"), ("isolate_host", "ws-1")):
        block = check_guardrails(action_type, target, policy)
        assert block is not None and block.code == "response_policy_invalid" and "allowed_actions" in block.detail


def test_protected_lists_are_never_truncated(make_settings: Callable[..., Settings]) -> None:
    """RR-5: the 1001st entry protects like the first; an oversized list fails closed instead of being cut."""
    filler = [f"h{i}" for i in range(5_000)]
    large = policy_for(make_settings, {"protected_assets": {"hosts": [*filler, "crown-jewel"]}})
    block = check_guardrails("isolate_host", "crown-jewel", large)
    assert block is not None and block.code == "protected_asset"
    assert check_guardrails("isolate_host", "ws-042", large) is None

    too_many = [f"h{i}" for i in range(MAX_PROTECTED_ENTRIES)] + ["crown-jewel"]
    oversized = policy_for(make_settings, {"protected_assets": {"hosts": too_many}})
    assert oversized.protected.invalid
    for target in ("crown-jewel", "ws-042"):
        block = check_guardrails("isolate_host", target, oversized)
        assert block is not None and block.code == "protected_assets_invalid" and "at most" in block.detail


def test_invalid_protected_entries_fail_closed() -> None:
    assets = ProtectedAssets.from_tenant_settings({"protected_assets": {"cidrs": ["8.8.8.0/24", "not-a-cidr"]}})
    assert assets.invalid and "cidrs.1" in assets.problems[0]
    assert ProtectedAssets.from_tenant_settings(PROTECTED).problems == ()


def test_invalid_autonomy_value_never_loosens(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    assert resolve_autonomy("critical", {"autonomy": {"critical": "disable"}}, settings) == "disabled"
    assert resolve_autonomy("low", {"autonomy": {"low": "yolo"}}, settings) == "disabled"


def test_validate_response_settings_for_the_settings_api() -> None:
    ok = validate_response_settings(
        {
            "response": {"connector": "webhook", "webhook_url": "https://soar.example.com/h", "dry_run": False,
                         "allowed_actions": ["block_ip"], "blast_radius": {"isolate_host": 1},
                         "autonomy": {"low": "auto"}},
            "protected_assets": {"hosts": [" dc01 "], "cidrs": ["10.0.0.0/8"]},
            "autonomy": {"critical": "disabled"},
            "unrelated": {"kept": "out of scope"},
        }
    )
    assert ok["response"]["connector"] == "webhook" and ok["protected_assets"]["hosts"] == ["dc01"]
    assert "unrelated" not in ok

    with pytest.raises(ResponsePolicyError) as err:
        validate_response_settings(
            {
                "response": {"connector": "crowdstrike", "tls_verify": False, "webhook_url": "https://u:p@x.example/",
                             "allowed_actions": "block_ip", "typo_key": 1},
                "protected_assets": {"hosts": "dc01,dc02"},
                "protected_cidrs": ["10.0.0.0/33"],
                "autonomy": {"low": "sometimes"},
            }
        )
    text = str(err.value)
    for fragment in ("connector", "tls_verify", "webhook_url", "allowed_actions", "typo_key",
                     "protected_assets.hosts", "protected_cidrs", "autonomy"):
        assert fragment in text, fragment
    with pytest.raises(ResponsePolicyError):
        validate_response_settings({"protected_assets": {"users": ["u"] * (MAX_PROTECTED_ENTRIES + 1)}})


@pytest.mark.parametrize(
    ("role", "risk", "autonomy", "allowed"),
    [
        ("viewer", "low", "approval", False),
        ("analyst", "low", "approval", True),
        ("analyst", "medium", "auto", True),
        ("analyst", "high", "approval", False),
        ("analyst", "critical", "approval", False),
        ("admin", "high", "approval", True),
        ("admin", "critical", "approval", True),
        ("admin", "critical", "disabled", False),
        ("admin", "low", "disabled", False),
        (None, "low", "approval", False),
    ],
)
def test_role_versus_risk(role: Optional[str], risk: str, autonomy: str, allowed: bool) -> None:
    assert approval_allowed(risk, role, autonomy) is allowed
