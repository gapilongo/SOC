"""Reported emails from ingestion through the workflow (real Postgres, Redis, checkpoints; fake LLM)."""

from __future__ import annotations

from typing import Any, Callable, Dict
from uuid import UUID

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.service import IngestionService, email_source_id
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A
from tests.unit.ingestion._email import HARVEST, auth, build, wrap

pytestmark = pytest.mark.integration

TENANT_SETTINGS = {"tools": {"internal_domains": ["example.com"]}, "phishing": {"trusted_authserv_ids": ["mx.example.com"]}}


async def ingest(repos: Repositories, settings: Settings, message: bytes, reporter: str = "bob@example.com") -> str:
    service = IngestionService(repos.db, settings, repos=repos)
    result = await service.ingest_email(TENANT_A, email_source_id("k1"), [message], reporter=reporter)
    assert len(result.inserted) == 1, result.items
    return result.inserted[0].alert_id


async def test_phishing_email_is_triaged_with_signals_and_escalated(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings
) -> None:
    await repos.tenants.update_settings(TENANT_A, TENANT_SETTINGS)
    message = wrap(build(
        sender="it@examp1e.test", subject="Verify your account",
        html="<a href='http://198.51.100.9/login'>https://login.example.com</a>",
        ar=[auth("examp1e.test", spf="fail", dmarc="fail", dkim="none")],
        attachments=[("page.htm", "text", "html", HARVEST)],
    ))
    alert_id = await ingest(repos, engine_settings, message)
    outcome = await engine.run(TENANT_A, alert_id)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert outcome.status in ("waiting_human", "waiting_approval") and alert.disposition != "benign"
    triage = alert.summary["triage"]
    assert {"email_dmarc_fail", "email_lookalike_domain", "email_link_text_mismatch", "email_risky_attachment"} <= set(
        triage["rule_tp"]
    )
    assert triage["phishing"]["lookalike_hosts"] == ["examp1e.test"]
    analysis = alert.summary["analysis"]
    assert analysis["rule_corroborated"] is True
    assert ["message", alert.normalized["email"]["message_id"]] in analysis["corroborated_targets"]
    # DMARC failed, but the sender's domain is itself a lookalike, so the address is the attacker's own.
    assert ["email", "it@examp1e.test"] in analysis["corroborated_targets"]
    assert ["domain", "examp1e.test"] in analysis["corroborated_targets"]


async def test_urls_shown_as_link_text_are_never_indicators_evidence_or_block_targets(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings
) -> None:
    # The shown domain embeds a protected brand name: as a link it would be a corroborated lookalike.
    await repos.tenants.update_settings(TENANT_A, {
        "tools": {"internal_domains": ["corp.test"]},
        "phishing": {"trusted_authserv_ids": ["mx.example.com"], "protected_brands": ["Outlook"]},
    })
    message = wrap(build(
        sender="it@examp1e.test", subject="Your mailbox is full",
        html="<p>Your mailbox is full.</p><a href='http://203.0.113.66/owa/login.php'>https://outlook.example.com/verify</a>",
        ar=[auth("examp1e.test", spf="fail", dmarc="fail", dkim="none")],
    ))
    alert_id = await ingest(repos, engine_settings, message)
    outcome = await engine.run(TENANT_A, alert_id)
    if outcome.status == "waiting_human":
        user = await repos.users.create(TENANT_A, "analyst-phish@example.com", "analyst")
        escalation_id = outcome.interrupt["escalation_id"]
        esc = await repos.escalations.get(TENANT_A, escalation_id)
        await repos.escalations.decide(
            TENANT_A, escalation_id, decision="true_positive", decided_by=UUID(str(user.id)), expected_version=esc.version
        )
        payload: Dict[str, Any] = {
            "type": "analyst_decision", "escalation_id": escalation_id, "decision": "true_positive",
            "approved_actions": [], "decided_by": str(user.id), "notes": "",
        }
        outcome = await engine.resume(TENANT_A, alert_id, payload)
    alert = await repos.alerts.get(TENANT_A, alert_id)

    # The analyst still sees the shown URL, flagged, and the deceiving link keeps its mismatch.
    urls = {u["url"]: u for u in alert.normalized["email"]["urls"]}
    assert urls["https://outlook.example.com/verify"]["display_only"] is True
    assert urls["http://203.0.113.66/owa/login.php"]["mismatch_text_host"] == "outlook.example.com"
    # Never an entity, a correlation indicator, a lookalike or corroborated evidence.
    entities = alert.normalized["entities"]
    assert entities["urls"] == ["http://203.0.113.66/owa/login.php"]
    assert "outlook.example.com" not in entities["domains"]
    sightings = await repos.indicators.sightings_for_alert(TENANT_A, alert_id)
    assert sightings and not any("outlook" in (s.value_display or "") for s in sightings)
    triage = alert.summary["triage"]
    assert "email_link_text_mismatch" in triage["rule_tp"] and "email_lookalike_domain" not in triage["rule_tp"]
    assert not any("outlook.example.com" in value for _, value in alert.summary["analysis"]["corroborated_targets"])
    # Never a response target; the real link is.
    actions = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
    assert ("block_url", "http://203.0.113.66/owa/login.php") in {(a.action_type, a.target) for a in actions}
    assert not any("outlook.example.com" in a.target for a in actions)


async def test_authenticated_internal_notice_closes_benign_on_rules_and_model(
    engine_factory: Callable[..., Any], repos: Repositories, engine_settings: Settings
) -> None:
    await repos.tenants.update_settings(TENANT_A, TENANT_SETTINGS)
    engine = await engine_factory()
    message = wrap(build(
        sender="it-operations@example.com", subject="Scheduled maintenance update this weekend",
        text="Scheduled maintenance: the backup system update runs this weekend. No action is needed.",
        ar=[auth("example.com")],
    ))
    alert_id = await ingest(repos, engine_settings, message)
    outcome = await engine.run(TENANT_A, alert_id)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert outcome.status == "completed" and alert.status == "closed" and alert.disposition == "benign"
    assert alert.summary["triage"]["rule_fp"] == ["email_internal_sender_authenticated"]
    assert alert.summary["decision"]["code"] == "rule_corroborated_benign"


async def test_forged_authentication_below_the_receiving_servers_header_never_closes(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings
) -> None:
    await repos.tenants.update_settings(TENANT_A, TENANT_SETTINGS)
    message = wrap(build(
        sender="it-operations@example.com", subject="Scheduled maintenance update this weekend",
        text="Scheduled maintenance: the backup system update runs this weekend. No action is needed.",
        ar=[auth("example.com", spf="fail", dkim="none", dmarc="fail"), auth("example.com")],
    ))
    alert_id = await ingest(repos, engine_settings, message)
    await engine.run(TENANT_A, alert_id)
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.disposition != "benign"
    assert "email_internal_sender_authenticated" not in alert.summary["triage"]["rule_fp"]
    assert "email_dmarc_fail" in alert.summary["triage"]["rule_tp"]
