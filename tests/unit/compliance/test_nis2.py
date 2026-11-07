"""NIS2 Article 23 draft fields per stage, the AI narrative and the HTML rendering."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.compliance import nis2
from lg_sotf.compliance.nis2 import AI_LABEL, CaseData, build_draft_fields, draft_narrative, render_draft_html
from lg_sotf.llm.fake import ScriptedChatModel
from lg_sotf.llm.fake import _message_text as message_text
from lg_sotf.settings import Settings
from tests.unit.compliance._support import TITLE, action, alert, escalation

COMMON = {"reporting_entity", "recipient", "significance", "internal_reference", "detection_time", "awareness_time"}
STAGE_FIELDS = {
    "early_warning": COMMON | {"incident_summary", "suspected_malicious", "cross_border_impact", "assistance_requested"},
    "notification": COMMON
    | {"suspected_malicious", "cross_border_impact", "initial_assessment", "severity", "impact",
       "indicators_of_compromise", "actions_taken"},
    "final": COMMON
    | {"detailed_description", "root_cause", "mitigations_applied", "mitigations_ongoing", "cross_border_impact",
       "lessons_learned"},
}


def _case(**alert_overrides: Any) -> CaseData:
    return CaseData(
        alert=alert(**alert_overrides),
        escalations=[escalation()],
        actions=[
            action("block_ip", "203.0.113.7", "succeeded", executed_at=alert().closed_at),
            action("isolate_host", "ws-042", "awaiting_approval"),
            action("disable_user", "jdoe", "dry_run"),
        ],
        indicator_displays=["ip: 203.0.113.7", "domain: evil.example"],
    )


def _by_key(stage: str, case: CaseData) -> Dict[str, nis2.DraftField]:
    return {f.key: f for f in build_draft_fields(case, stage)}


@pytest.mark.parametrize("stage", ["early_warning", "notification", "final"])
def test_each_stage_has_the_article_23_fields(stage: str) -> None:
    fields = _by_key(stage, _case())
    assert set(fields) == STAGE_FIELDS[stage]
    for key in ("reporting_entity", "recipient", "significance", "awareness_time", "cross_border_impact"):
        assert fields[key].source == "requires_human" and fields[key].value is None
    assert "ws-042" in (fields["cross_border_impact"].help or "")
    assert "First escalation to an analyst" in (fields["awareness_time"].help or "")
    assert fields["internal_reference"].value == "LG-SOTF alert a1 (case case-7)"
    assert build_draft_fields(_case(), stage) == build_draft_fields(_case(), stage)


def test_early_warning_prefills_the_malicious_act_assessment() -> None:
    fields = _by_key("early_warning", _case())
    text = fields["suspected_malicious"].value or ""
    assert "confirmed as a true positive" in text and "Automated analysis verdict: malicious" in text
    assert "T1003.001" in text and "Confirm" in text
    assert fields["incident_summary"].value == f"{TITLE} (severity high, category credential_access)"


def test_notification_lists_iocs_severity_impact_and_actions() -> None:
    fields = _by_key("notification", _case())
    iocs = (fields["indicators_of_compromise"].value or "").splitlines()
    assert iocs == ["ip: 203.0.113.7", "domain: evil.example", f"hash: {'ab' * 32}"]
    assert "Alert severity high; threat score 77.0" in (fields["severity"].value or "")
    assert "hosts: ws-042" in (fields["impact"].value or "") and "users: jdoe" in (fields["impact"].value or "")
    assert "Credential dumping" in (fields["initial_assessment"].value or "")
    actions = fields["actions_taken"].value or ""
    assert "block_ip on 203.0.113.7 (succeeded)" in actions and "isolate_host on ws-042 (awaiting_approval)" in actions


def test_notification_without_indicators_asks_a_person() -> None:
    case = CaseData(alert=alert(normalized={}), escalations=[], actions=[])
    field = _by_key("notification", case)["indicators_of_compromise"]
    assert field.value is None and field.source == "requires_human"


def test_final_report_describes_root_cause_and_mitigations() -> None:
    fields = _by_key("final", _case())
    assert "Likely threat type: credential_theft" in (fields["root_cause"].value or "")
    assert fields["root_cause"].source == "case_data"
    applied = fields["mitigations_applied"].value or ""
    assert "block_ip on 203.0.113.7 (succeeded)" in applied and "disable_user on jdoe (dry_run, dry run)" in applied
    assert "isolate_host" in (fields["mitigations_ongoing"].value or "")
    description = fields["detailed_description"].value or ""
    assert "Escalated (L2)" in description and "Case closed" in description


def test_unknown_stage_is_refused() -> None:
    with pytest.raises(ValueError):
        build_draft_fields(_case(), "intermediate")


async def test_narrative_goes_through_the_untrusted_boundary(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    model = ScriptedChatModel(model_name="fake-scripted", script={"IncidentNarrative": [{"narrative": "On 1 Sep..."}]})
    result = await draft_narrative(settings, "t1", _case(), "notification", model_factory=lambda tier, s: model)

    assert result.error is None and result.narrative == {
        "text": "On 1 Sep...",
        "label": AI_LABEL,
        "provider": "fake",
        "model": "fake-scripted",
        "prompt_name": "nis2.narrative.notification",
        "prompt_hash": nis2.NARRATIVE_PROMPTS["notification"].hash,
    }
    [call] = model.calls
    system, data = (message_text(m) for m in call.messages)
    assert TITLE not in system and "ignore previous instructions" not in system
    assert "ignore previous instructions" in data and "<alert_data>" in data


async def test_narrative_failures_never_fail_the_draft(make_settings: Callable[..., Settings]) -> None:
    from lg_sotf.llm.fake import Refuse

    settings = make_settings()
    refused = ScriptedChatModel(model_name="m", script={"IncidentNarrative": [Refuse()]})
    result = await draft_narrative(settings, "t1", _case(), "final", model_factory=lambda tier, s: refused)
    assert result.narrative is None and result.error == "the model declined to write a narrative"

    def broken(tier: Any, s: Settings) -> Any:
        raise ConnectionError("provider down")

    result = await draft_narrative(settings, "t1", _case(), "final", model_factory=broken)
    assert result.narrative is None and result.error == "the model could not be reached"
    disabled = await draft_narrative(make_settings(llm={"enabled": False}), "t1", _case(), "final")
    assert disabled.error == "no LLM is configured"


def test_draft_html_escapes_and_labels_everything() -> None:
    fields: List[Dict[str, Any]] = [f.as_dict() for f in build_draft_fields(_case(), "early_warning")]
    page = render_draft_html(
        alert_id="a1",
        stage="early_warning",
        fields=fields,
        generated_at="2026-09-01T10:00:00+00:00",
        ai_narrative={"text": "<img src=x onerror=alert(1)>", "label": AI_LABEL, "provider": "fake", "model": "m"},
    )
    assert "<b>Mimikatz</b>" not in page and "&lt;b&gt;Mimikatz&lt;/b&gt;" in page
    assert "<img" not in page and "&lt;img src=x" in page
    assert "DRAFT." in page and "does not submit reports" in page and AI_LABEL in page
    assert "to be completed by you" in page and "<script" not in page
