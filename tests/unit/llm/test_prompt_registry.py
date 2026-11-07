"""Prompt registry: stable names and content hashes, recorded with the model on every LLM call (AI-E1.2)."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Callable, Dict

import pytest
from pydantic import BaseModel
from structlog.testing import capture_logs

import lg_sotf
from lg_sotf.agents.analysis.base import VERDICT_PROMPT
from lg_sotf.agents.analysis.react import STEP_PROMPT
from lg_sotf.agents.correlation.base import PROMPT as CORRELATION_PROMPT
from lg_sotf.agents.triage.base import PROMPT as TRIAGE_PROMPT
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.compliance.evidence_html import render_evidence_html
from lg_sotf.compliance.nis2 import NARRATIVE_PROMPTS
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.report import build_report, render_markdown
from lg_sotf.eval.results import ItemResult, llm_provenance
from lg_sotf.ingestion.llm_fallback import PROMPT as NORMALIZE_PROMPT
from lg_sotf.llm import registry
from lg_sotf.llm.prompting import build_messages
from lg_sotf.llm.registry import PROMPT_HASH_CHARS, PromptTemplate, prompt_manifest, register_prompt
from lg_sotf.llm.structured import ainvoke_structured
from lg_sotf.services.llm_check import PROMPT as PROBE_PROMPT
from lg_sotf.settings import Settings
from tests.unit.agents._support import AMBIGUOUS, ASSESSMENT, ctx, factory, fake_repos, scripted
from tests.unit.eval._support import result

pytestmark = pytest.mark.unit

HASH_RE = re.compile(rf"^[0-9a-f]{{{PROMPT_HASH_CHARS}}}$")


class Answer(BaseModel):
    text: str


class OtherAnswer(BaseModel):
    text: str
    score: int


def test_hash_covers_instructions_task_and_schema_only() -> None:
    base = PromptTemplate(name="test.a", system="You are a test.", task="Answer.", schema=Answer)
    assert HASH_RE.match(base.hash)
    assert PromptTemplate(name="test.renamed", system="You are a test.", task="Answer.", schema=Answer).hash == base.hash
    assert PromptTemplate(name="test.a", system="You are a test!", task="Answer.", schema=Answer).hash != base.hash
    assert PromptTemplate(name="test.a", system="You are a test.", task="Answer!", schema=Answer).hash != base.hash
    assert PromptTemplate(name="test.a", system="You are a test.", task="Answer.", schema=OtherAnswer).hash != base.hash


def test_register_prompt_names_are_unique_per_content(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_REGISTRY", {})
    first = register_prompt("test.one", system="S", task="T", schema=Answer)
    assert register_prompt("test.one", system="S", task="T", schema=Answer) == first  # re-import is fine
    with pytest.raises(ValueError, match="different content"):
        register_prompt("test.one", system="S", task="T2", schema=Answer)
    for bad in ("Test.One", "test..one", "", "test one", "x" * 65):
        with pytest.raises(ValueError, match="invalid prompt name"):
            register_prompt(bad, system="S", task="T", schema=Answer)
    assert prompt_manifest() == {"test.one": first.hash}


def test_every_production_prompt_is_registered() -> None:
    manifest = prompt_manifest()
    templates = [TRIAGE_PROMPT, CORRELATION_PROMPT, VERDICT_PROMPT, STEP_PROMPT, NORMALIZE_PROMPT, PROBE_PROMPT,
                 *NARRATIVE_PROMPTS.values()]
    assert {t.name: t.hash for t in templates}.items() <= manifest.items()
    assert {"triage.assess", "correlation.assess", "analysis.verdict", "analysis.react_step", "ingestion.normalize",
            "llm_check.probe", "nis2.narrative.early_warning", "nis2.narrative.notification",
            "nis2.narrative.final"} <= set(manifest)
    assert all(HASH_RE.match(h) for h in manifest.values())


def _llm_calls_without_prompt(tree: ast.AST) -> list[int]:
    missing = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
        if name in ("ainvoke_structured", "call_llm") and "prompt" not in {k.arg for k in node.keywords}:
            missing.append(node.lineno)
    return missing


def test_every_production_llm_call_passes_a_registered_prompt() -> None:
    """``ainvoke_structured`` accepts no prompt (tests); production code must always name one."""
    root = Path(lg_sotf.__file__).parent
    offenders = [
        f"{path.relative_to(root)}:{line}"
        for path in sorted(root.rglob("*.py"))
        for line in _llm_calls_without_prompt(ast.parse(path.read_text(encoding="utf-8")))
    ]
    assert offenders == []


async def test_a_prompt_must_answer_the_requested_schema(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    prompt = PromptTemplate(name="test.a", system="S", task="T", schema=Answer)
    messages = build_messages("S", "T", {"x": 1}, settings=settings)
    with pytest.raises(ValueError, match="answers Answer, not OtherAnswer"):
        await ainvoke_structured(
            scripted(), OtherAnswer, messages, agent="test", tier="fast", settings=settings, prompt=prompt
        )


async def test_every_llm_call_records_prompt_hash_and_model_id(make_settings: Callable[..., Settings]) -> None:
    """Acceptance: the call's log event, the alert summary, the usage totals, the evaluation report and the
    evidence pack all carry the prompt name and hash with the model id."""
    settings = make_settings()
    repos = fake_repos()
    model = scripted(TriageAssessment=[ASSESSMENT])
    expected = {"prompt_name": "triage.assess", "prompt_hash": TRIAGE_PROMPT.hash}

    with capture_logs() as logs:
        await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings, repos=repos), AMBIGUOUS)

    (event,) = [e for e in logs if e["event"] == "llm.call"]
    assert {k: event[k] for k in ("prompt_name", "prompt_hash", "model")} == {**expected, "model": "fake-scripted"}

    summary: Dict[str, Any] = repos.alerts.rows[("t1", "a1")].summary
    assert summary["llm_models"]["triage"] == {**expected, "provider": "fake", "model": "fake-scripted", "tier": "fast"}
    usage = summary["llm_usage"]
    assert {k: usage["by_agent"]["triage"][k] for k in ("provider", "model", "prompt_name", "prompt_hash")} == {
        **expected, "provider": "fake", "model": "fake-scripted"
    }

    item = result("m1", "malicious", "waiting_human", llm_provenance=llm_provenance(usage))
    other = result("m2", "malicious", "waiting_human", llm_provenance=llm_provenance(usage))
    report = build_report([item, other, result("e1", "benign", "error")], dataset=_dataset())
    assert report["llm_provenance"] == [
        {"agent": "triage", "provider": "fake", "model": "fake-scripted", **expected, "items": 2}
    ]
    assert ItemResult.from_dict(report["items"][0]).llm_provenance["triage"]["prompt_hash"] == TRIAGE_PROMPT.hash
    markdown = render_markdown(report)
    assert "## Models and prompts" in markdown
    assert f"| triage | fake | fake-scripted | triage.assess | `{TRIAGE_PROMPT.hash}` | 2 |" in markdown

    page = render_evidence_html({"agents": {"triage": {"model": {**summary["llm_models"]["triage"], "recorded": True}}}})
    assert f"triage.assess (version {TRIAGE_PROMPT.hash})" in page and "fake / fake-scripted (fast tier)" in page


def test_report_without_llm_calls_says_so() -> None:
    report = build_report([result("b1", "benign", "closed")], dataset=_dataset())
    assert report["llm_provenance"] == []
    assert "No LLM call was recorded." in render_markdown(report)


def test_evidence_html_marks_models_recorded_before_prompt_versions() -> None:
    page = render_evidence_html(
        {"agents": {"analysis": {"model": {"provider": "p", "model": "m", "tier": "deep", "recorded": True}}}}
    )
    assert "not recorded (processed before prompt versions were recorded)" in page


def _dataset() -> Any:
    return parse_dataset(
        '{"id": "m1", "source_type": "canonical", "alert": {"title": "a"}, "expected": {"disposition": "malicious"}}',
        path="small.jsonl",
    )
