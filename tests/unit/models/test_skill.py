"""The skill format (ADR 0014 section 1, the part AI-E3.3 needs): a strict model that refuses what it does not implement."""

from __future__ import annotations

import copy
from typing import Any, Dict

import pytest
import yaml
from pydantic import ValidationError

from lg_sotf.agents.investigation.catalog import SKILLS_DIR
from lg_sotf.models.skill import SKILL_SCHEMA, AnyTechniqueIn, Const, MaxLevelGe, Maybe, Not, SkillSpec

pytestmark = pytest.mark.unit

DEFAULT = SKILLS_DIR / "wazuh.default.yaml"


def document() -> Dict[str, Any]:
    loaded: Dict[str, Any] = yaml.safe_load(DEFAULT.read_text(encoding="utf-8"))
    return loaded


def changed(**patch: Any) -> Dict[str, Any]:
    return {**copy.deepcopy(document()), **patch}


def test_the_default_skill_is_what_amendment_1_asks_for() -> None:
    skill = SkillSpec.model_validate(document())
    assert (skill.schema_id, skill.id, skill.status) == (SKILL_SCHEMA, "wazuh.default", "active")
    assert skill.applies_to.source_types == ["wazuh"] and skill.view == "wazuh.alert"
    # Host activity around the alert, prevalence of its main object, logon fan-out by user and by source address.
    assert [(ref.id, ref.tool, ref.when) for ref in skill.evidence] == [
        ("host", "wazuh.host_activity:1", "always"), ("prevalence", "wazuh.prevalence:1", "always"),
        ("logons_user", "wazuh.logon_fanout:1", "always"), ("logons_source", "wazuh.logon_fanout:1", "always"),
    ]
    assert skill.evidence[0].required and (skill.evidence[0].tool_name, skill.evidence[0].tool_version) == ("wazuh.host_activity", 1)
    # Every argument is a binding, a whole number or a constant of the file. One binding is optional: the
    # alert's rule, which names the alert's own event for the host lookup to leave out.
    args = [arg.optional if isinstance(arg, Maybe) else arg for ref in skill.evidence for arg in ref.args.values()]
    assert all(isinstance(arg, (int, Const)) or arg.startswith(("view.", "alert.")) for arg in args)
    assert skill.evidence[0].args["exclude_rule_id"] == Maybe(optional="view.rule_id")
    assert skill.evidence[1].args["at"] == "alert.occurred_at"  # prevalence as of the alert, not as of now
    assert skill.evidence[2].args["pivot"] == Const(const="target_user")
    # Malicious indicators are declared; it has no benign proof (the model has no such field at all).
    assert [h.id for h in skill.hypotheses.malicious] == ["never_close_class_on_host", "high_level_alert_on_host"]
    assert isinstance(skill.hypotheses.malicious[0].indicator, AnyTechniqueIn)
    assert skill.hypotheses.malicious[1].indicator == MaxLevelGe(fact="host", max_level_ge=12)
    assert "benign" not in type(skill.hypotheses).model_fields


@pytest.mark.parametrize(
    "patch",
    [
        {"close": {"severities": ["low"]}},  # closing is not this file's to say
        {"never_close": []},
        {"settle_min": 10},
        {"budget": {"usd": 5}},
        {"hypotheses": {"benign": [{"id": "ok", "says": "fine", "proof": {"fact": "host", "max_level_ge": 0}}]}},
        {"schema": "lg-sotf/investigation-skill/v2"},
        {"status": "enabled"},
        {"id": "Wazuh Default"},
        {"version": "1"},
    ],
)
def test_a_file_that_uses_anything_else_is_refused(patch: Dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SkillSpec.model_validate(changed(**patch))


@pytest.mark.parametrize(
    "arg",
    ["SRV-01", "view.host; DROP", "alert.title", "model.answer", 1.5, True, {"const": "Target User"}, {"literal": "x"}, None,
     ["view.host"], {"optional": "SRV-01"}, {"optional": "alert.title"}, {"optional": 5}, {"optional": {"const": "x"}},
     {"optional": "view.host", "default": "SRV-01"}],
)
def test_an_argument_is_never_free_text(arg: Any) -> None:
    """A host name typed into the file, a field of the alert that an attacker writes, a model's answer: refused."""
    doc = document()
    doc["evidence"][0]["args"]["host"] = arg
    with pytest.raises(ValidationError):
        SkillSpec.model_validate(doc)


def test_evidence_and_indicators_must_hang_together() -> None:
    doc = document()
    doc["evidence"][1]["id"] = "host"
    with pytest.raises(ValidationError, match="evidence ids must be unique"):
        SkillSpec.model_validate(doc)
    doc = document()
    doc["hypotheses"]["malicious"][0]["indicator"] = {"not": {"fact": "lineage", "max_level_ge": 3}}
    with pytest.raises(ValidationError, match="does not collect: lineage"):
        SkillSpec.model_validate(doc)
    doc = document()
    doc["evidence"][0]["when"] = "optional"  # optional queries come with the planner
    with pytest.raises(ValidationError):
        SkillSpec.model_validate(doc)
    doc = document()
    doc["hypotheses"]["malicious"][0]["indicator"] = {"any": [{"not": {"fact": "host", "max_level_ge": 3}}, {"all": [
        {"fact": "host", "any_group_in": ["authentication_failed"]}]}]}
    nested = SkillSpec.model_validate(doc).hypotheses.malicious[0].indicator
    assert isinstance(nested.any[0], Not) and nested.any[0].negated == MaxLevelGe(fact="host", max_level_ge=3)  # type: ignore[union-attr]


def test_a_skill_is_frozen() -> None:
    skill = SkillSpec.model_validate(document())
    with pytest.raises(ValidationError):
        skill.status = "retired"  # type: ignore[misc]
