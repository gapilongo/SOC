"""The skill catalogue (ADR 0014 section 1.1): the shipped files load, and a file that does not fit refuses."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict

import pytest
import yaml

from lg_sotf.agents.investigation.catalog import SKILLS_DIR, SkillError, check_catalog, load_catalog, load_skill
from lg_sotf.models.skill import SkillSpec
from tests.unit.agents.investigation._executor import Answers
from tests.unit.agents.investigation._support import fact_tools
from tests.unit.tools._support import Handler

pytestmark = pytest.mark.unit


def document() -> Dict[str, Any]:
    loaded: Dict[str, Any] = yaml.safe_load((SKILLS_DIR / "wazuh.default.yaml").read_text(encoding="utf-8"))
    return loaded


def skill(change: Callable[[Dict[str, Any]], None]) -> SkillSpec:
    doc = document()
    change(doc)
    return SkillSpec.model_validate(doc)


def test_the_shipped_catalogue_loads_and_fits_the_registry() -> None:
    catalog = load_catalog()
    assert [s.id for s in catalog] == ["wazuh.default"]
    assert [path.name for path in sorted(SKILLS_DIR.glob("*"))] == ["wazuh.default.yaml"]  # one file a skill
    check_catalog(catalog, Answers().registry)


def test_no_two_skills_overlap_at_equal_specificity() -> None:
    twin = skill(lambda doc: doc.update(id="wazuh.other"))
    with pytest.raises(SkillError, match="wazuh.other and wazuh.default both apply to wazuh"):
        check_catalog([*load_catalog(), twin], Answers().registry)
    retired = skill(lambda doc: doc.update(id="wazuh.other", status="retired"))
    check_catalog([*load_catalog(), retired], Answers().registry)
    with pytest.raises(SkillError, match="a skill id appears twice"):
        check_catalog([*load_catalog(), skill(lambda doc: doc.update(status="draft"))], Answers().registry)


def _tool(doc: Dict[str, Any], tool: str) -> None:
    doc["evidence"][0]["tool"] = tool


def _arg(doc: Dict[str, Any], name: str, value: Any) -> None:
    doc["evidence"][0]["args"][name] = value


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda d: _tool(d, "wazuh.file_integrity:1"), "host: no tool wazuh.file_integrity"),
        (lambda d: _tool(d, "wazuh.host_activity:3"), "wazuh.host_activity is version 1, not 3"),
        (lambda d: _arg(d, "index", {"const": "everything"}), r"arguments not taken: \['index'\]"),
        (lambda d: d["evidence"][0]["args"].pop("before_min"), r"required and not given: \['before_min'\]"),
        (lambda d: _arg(d, "host", "view.hostname"), "the view has no field view.hostname"),
        (lambda d: d.update(view="splunk.alert"), "view splunk.alert is not registered"),
        # A constant or a number the tool would refuse on every alert: the query could never run.
        (lambda d: d["evidence"][2]["args"].update(pivot={"const": "bogus"}), "logons_user: pivot is not a value wazuh.logon_fanout takes"),
        (lambda d: _arg(d, "before_min", 99_999), "host: before_min is not a value wazuh.host_activity takes"),
        (lambda d: d["evidence"][1]["args"].update(days={"const": "thirty"}), "prevalence: days is not a value"),
        (lambda d: _arg(d, "host", "view.user"), "a Wazuh skill runs wazuh.host_activity on the alert's host"),
        (lambda d: d["hypotheses"]["malicious"][0]["indicator"].update(fact="prevalence"),
         "never_close_class_on_host: evidence prevalence holds no host_activity fact"),
    ],
)
def test_a_skill_that_does_not_fit_the_registry_refuses_the_catalogue(change: Callable[[Dict[str, Any]], Any], problem: str) -> None:
    with pytest.raises(SkillError, match=problem):
        check_catalog([skill(change)], Answers().registry)


def test_an_empty_catalogue_is_an_error_not_a_harness_that_never_runs(tmp_path: Path) -> None:
    assert load_catalog(tmp_path) == ()
    with pytest.raises(SkillError, match="holds no skill"):
        check_catalog(load_catalog(tmp_path), Answers().registry)


def test_a_registry_without_the_evidence_tools_refuses_the_catalogue() -> None:
    with pytest.raises(SkillError, match="no tool wazuh.host_activity"):
        check_catalog(load_catalog(), fact_tools(Handler()))


def test_a_file_is_named_after_its_skill_and_must_be_a_valid_skill(tmp_path: Path) -> None:
    good = (SKILLS_DIR / "wazuh.default.yaml").read_text(encoding="utf-8")
    (tmp_path / "wazuh.default.yaml").write_text(good, encoding="utf-8")
    assert load_skill(tmp_path / "wazuh.default.yaml").id == "wazuh.default"
    (tmp_path / "renamed.yaml").write_text(good, encoding="utf-8")
    with pytest.raises(SkillError, match="named after the skill id"):
        load_skill(tmp_path / "renamed.yaml")
    (tmp_path / "broken.yaml").write_text("id: [unclosed", encoding="utf-8")
    with pytest.raises(SkillError, match="broken.yaml: not a valid skill"):
        load_skill(tmp_path / "broken.yaml")
    (tmp_path / "extra.yaml").write_text(good + "\nclose:\n  severities: [low]\n", encoding="utf-8")
    with pytest.raises(SkillError, match="extra.yaml: not a valid skill"):
        load_skill(tmp_path / "extra.yaml")
    with pytest.raises(SkillError):  # one bad file refuses the whole catalogue
        load_catalog(tmp_path)
    (tmp_path / "huge.yaml").write_text(good + "#" * 70_000, encoding="utf-8")
    with pytest.raises(SkillError, match="at most 65536 bytes"):
        load_skill(tmp_path / "huge.yaml")


def test_the_skill_files_ship_in_the_package() -> None:
    import tomllib

    root = Path(__file__).resolve().parents[4]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert "agents/investigation/skills/*.yaml" in data["tool"]["setuptools"]["package-data"]["lg_sotf"]
