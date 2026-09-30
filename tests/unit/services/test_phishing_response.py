"""Phishing response actions: catalogue, playbook, targets, guardrails and blast radius."""

from __future__ import annotations

from typing import Any, Callable, Dict

from lg_sotf.services.response import (
    ACTION_CATALOG,
    DEFAULT_BLAST_RADIUS,
    PlanContext,
    ResponsePolicy,
    ResponseService,
    actions_from_recommendations,
    build_candidates,
    check_guardrails,
    detect_threat_type,
    plan_entities,
    validate_target,
)
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeRepos, FakeTenants

EMAIL_ALERT: Dict[str, Any] = {
    "title": "Reported email: Verify your account",
    "category": "phishing",
    "entities": {"urls": ["http://198.51.100.9/login"], "users": ["bob@example.com"], "emails": ["it@examp1e.test"]},
    "email": {
        "message_id": "<m1@examp1e.test>",
        "subject": "Verify your account",
        "from": {"address": "it@examp1e.test", "domain": "examp1e.test"},
        "reply_to": ["pay@collect.test"],
        "reporter": "bob@example.com",
    },
}


def ctx(**kw: Any) -> PlanContext:
    base: Dict[str, Any] = {
        "severity": "medium",
        "evidence": "analyst",
        "title": EMAIL_ALERT["title"],
        "category": "phishing",
        "entities": plan_entities(EMAIL_ALERT),
        "message": {"sender": "it@examp1e.test", "subject": "Verify your account"},
    }
    base.update(kw)
    return PlanContext(**base)


def test_catalogue_entries() -> None:
    assert (ACTION_CATALOG["block_sender"].target_kind, ACTION_CATALOG["block_sender"].risk) == ("email", "medium")
    assert ACTION_CATALOG["block_sender"].containment
    purge = ACTION_CATALOG["purge_message"]
    assert (purge.target_kind, purge.risk, purge.containment) == ("message", "high", True)
    notify = ACTION_CATALOG["notify_reporter"]
    assert (notify.target_kind, notify.risk, notify.containment, notify.requires) == ("alert", "low", False, "reporter")
    assert DEFAULT_BLAST_RADIUS["purge_message"] == 10 and DEFAULT_BLAST_RADIUS["block_sender"] == 20


def test_phishing_playbook_and_recommendations() -> None:
    assert detect_threat_type(["Reported email: x", "phishing"])[0] == "phishing"
    assert actions_from_recommendations(
        ["Block the sender", "Purge the message from all mailboxes", "Notify the reporter"]
    ) == ["block_sender", "purge_message", "notify_reporter"]


def test_email_plan_entities_exclude_the_reporter_from_user_targets() -> None:
    entities = plan_entities(EMAIL_ALERT)
    assert entities["email"] == ["it@examp1e.test", "pay@collect.test"]
    assert entities["message"] == ["<m1@examp1e.test>"] and entities["reporter"] == ["bob@example.com"]
    assert "user" not in entities


def test_candidates_carry_what_the_connector_must_match() -> None:
    threat, cands = build_candidates(ctx(), "a1")
    assert threat == "phishing"
    by_type = {(c.action_type, c.target): c for c in cands}
    purge = by_type[("purge_message", "<m1@examp1e.test>")]
    assert purge.params["match"] == {
        "internet_message_id": "<m1@examp1e.test>", "sender": "it@examp1e.test", "subject": "Verify your account",
    }
    assert ("block_sender", "it@examp1e.test") in by_type and ("block_sender", "pay@collect.test") in by_type
    assert by_type[("notify_reporter", "alert:a1")].params["reporter"] == "bob@example.com"
    assert ("block_url", "http://198.51.100.9/login") in by_type
    # Without a reporter there is nobody to notify.
    no_reporter = {k: v for k, v in plan_entities(EMAIL_ALERT).items() if k != "reporter"}
    _, cands = build_candidates(ctx(entities=no_reporter), "a1")
    assert not any(c.action_type == "notify_reporter" for c in cands)


def test_target_validation() -> None:
    assert validate_target("email", "It@Examp1e.test") is None
    assert validate_target("email", "not-an-address") == "invalid_email"
    assert validate_target("message", "<abc.123@x.test>") is None
    assert validate_target("message", "<with space@x>") == "invalid_message"


def test_guardrails_protect_own_senders_and_protected_domains(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(tools={"internal_domains": ["corp.example"]})
    tenant = {
        "tools": {"internal_domains": ["example.com"]},
        "protected_assets": {"domains": ["partner.test"], "users": ["ceo@vip.test", "admin"]},
    }
    policy = ResponsePolicy.resolve(tenant, settings)
    assert check_guardrails("block_sender", "ceo@example.com", policy).code == "internal_sender"  # type: ignore[union-attr]
    assert check_guardrails("block_sender", "x@mail.corp.example", policy).code == "internal_sender"  # type: ignore[union-attr]
    assert check_guardrails("block_sender", "x@sub.partner.test", policy).code == "protected_asset"  # type: ignore[union-attr]
    assert check_guardrails("block_sender", "CEO@vip.test", policy).code == "protected_asset"  # type: ignore[union-attr]
    # A bare protected account name does not protect that name at every domain.
    assert check_guardrails("block_sender", "admin@attacker.test", policy) is None
    assert check_guardrails("purge_message", "<m1@attacker.test>", policy) is None
    assert check_guardrails("block_sender", "<m1@attacker.test>", policy).code == "invalid_email"  # type: ignore[union-attr]


async def test_plan_writes_phishing_actions_with_approval_by_default(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos(tenants=FakeTenants({"tools": {"internal_domains": ["example.com"]}}))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    result = await service.plan("t1", "a1", ctx(evidence="rules", corroborated_targets=frozenset(
        {("message", "<m1@examp1e.test>")}
    )))
    rows = {(r.action_type, r.target): r for r in repos.actions.rows.values()}
    purge = rows[("purge_message", "<m1@examp1e.test>")]
    assert purge.risk_level == "high" and purge.status == "awaiting_approval"
    assert rows[("notify_reporter", "alert:a1")].risk_level == "low"
    assert result.threat_type == "phishing" and not result.auto


async def test_auto_autonomy_contains_only_corroborated_email_targets(make_settings: Callable[..., Settings]) -> None:
    tenant = {"autonomy": {"low": "auto", "medium": "auto", "high": "auto"}}
    repos = FakeRepos(tenants=FakeTenants(tenant))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    await service.plan("t1", "a1", ctx(evidence="rules", corroborated_targets=frozenset(
        {("message", "<m1@examp1e.test>"), ("email", "pay@collect.test")}
    )))
    rows = {(r.action_type, r.target): r for r in repos.actions.rows.values()}
    assert rows[("purge_message", "<m1@examp1e.test>")].status == "approved"
    assert rows[("block_sender", "pay@collect.test")].status == "approved"
    spoofed = rows[("block_sender", "it@examp1e.test")]
    assert spoofed.status == "awaiting_approval" and spoofed.params["approval_reason"] == "target_not_corroborated"
