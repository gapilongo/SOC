"""Phishing response actions: catalogue, playbook, targets, guardrails and blast radius."""

from __future__ import annotations

from typing import Any, Callable, Dict

from lg_sotf.domain.phishing import PhishingProfile, assess, corroborated_email_targets
from lg_sotf.ingestion.email import parse_email
from lg_sotf.ingestion.normalizers import get_normalizer
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
from tests.unit.ingestion._email import build, wrap
from tests.unit.ingestion._support import ctx as source_ctx
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
        "urls": [{"url": "http://198.51.100.9/login", "host": "198.51.100.9", "ip_host": True, "mismatch": True}],
    },
}
# A link whose visible text is itself a URL: only the link is where the message leads.
DECEIVING = "<p>Your mailbox is full.</p><a href='http://203.0.113.66/owa/login.php'>https://outlook.example.com/verify</a>"
LINK = "http://203.0.113.66/owa/login.php"
SHOWN = "https://outlook.example.com/verify"
# What a model reading the message might recommend.
MODEL_RECOMMENDATIONS = ["Block the domain outlook.example.com", f"Block the URL {SHOWN} in the proxy"]


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


def reported(html: str) -> Dict[str, Any]:
    """The stored alert of a reported message sent from the attacker's own domain."""
    doc = parse_email(wrap(build(sender="it@examp1e.test", reply_to="collect@attacker.test", html=html)))
    return get_normalizer("email").normalize(doc, source_ctx("m365_mailbox")).normalized_document()


def blocks(entities: Dict[str, Any], recommendations: Any = tuple(MODEL_RECOMMENDATIONS)) -> set[tuple[str, str]]:
    _, cands = build_candidates(ctx(entities=entities, recommended_actions=list(recommendations)), "a1")
    return {(c.action_type, c.target) for c in cands if c.action_type in ("block_url", "block_domain", "block_ip")}


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


def test_link_text_is_never_a_block_target_whatever_the_model_recommends() -> None:
    entities = plan_entities(reported(DECEIVING))
    assert entities["url"] == [LINK] and entities["domain"] == ["examp1e.test", "attacker.test"]
    assert blocks(entities, [*MODEL_RECOMMENDATIONS, "Block the IP address"]) == {
        ("block_url", LINK),
        ("block_domain", "examp1e.test"),
        ("block_domain", "attacker.test"),
        ("block_ip", "203.0.113.66"),
    }


def test_a_domain_both_shown_and_linked_to_is_still_blocked() -> None:
    targets = blocks(plan_entities(reported("<a href='https://evil.test/login'>https://evil.test/verify</a>")))
    assert ("block_url", "https://evil.test/login") in targets and ("block_domain", "evil.test") in targets
    assert ("block_url", "https://evil.test/verify") not in targets
    # A URL shown as text and also linked to elsewhere in the message is a link like any other.
    targets = blocks(plan_entities(reported(DECEIVING + f"<a href='{SHOWN}'>the real page</a>")))
    assert ("block_url", SHOWN) in targets and ("block_domain", "outlook.example.com") in targets


def test_email_block_targets_must_be_backed_by_what_the_message_links_to() -> None:
    alert = reported(DECEIVING)
    # An entity list that names the shown URL, its domain or an unrelated address anyway.
    alert["entities"] = {
        **alert["entities"],
        "urls": [LINK, SHOWN, "https://unrelated.test/"],
        "domains": ["examp1e.test", "outlook.example.com", "Attacker.Test.", "unrelated.test"],
        "ips": ["203.0.113.66", "198.51.100.200"],
    }
    entities = plan_entities(alert)
    assert entities["url"] == [LINK]
    assert entities["domain"] == ["examp1e.test", "Attacker.Test."]
    assert entities["ip"] == ["203.0.113.66"]
    # Other alerts keep every entity.
    other = plan_entities({"entities": {"urls": [SHOWN], "domains": ["outlook.example.com"]}})
    assert other["url"] == [SHOWN] and other["domain"] == ["outlook.example.com"]


async def test_a_shown_brand_domain_is_never_corroborated_nor_contained(make_settings: Callable[..., Settings]) -> None:
    alert = reported(DECEIVING)
    # The shown domain embeds this brand's name: as a link, it would be a corroborated lookalike.
    profile = PhishingProfile.from_settings({"phishing": {"protected_brands": ["Outlook"]}}, {})
    triage = {"phishing": assess(alert["email"], profile).digest()}
    corroborated = frozenset((k, v) for k, v in corroborated_email_targets(alert, triage))
    repos = FakeRepos(tenants=FakeTenants({"autonomy": {"low": "auto", "medium": "auto", "high": "auto"}}))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    await service.plan("t1", "a1", ctx(
        entities=plan_entities(alert), evidence="rules", corroborated_targets=corroborated,
        recommended_actions=MODEL_RECOMMENDATIONS,
    ))
    rows = {(r.action_type, r.target): r for r in repos.actions.rows.values()}
    assert not any("outlook.example.com" in target for _, target in rows)
    assert rows[("block_url", LINK)].status == "approved"
