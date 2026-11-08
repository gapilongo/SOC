"""The AI system card (``docs/ai-system-card.md``, AI-E6.2) lists the invariants, the models and the limits.

* The invariants table is the registry's own rendering (``scripts/export_invariants.py``).
* Every model profile the wizard offers appears with its models and where it runs,
  and DeepSeek is never presented as a supported profile.
* Every registered prompt (every kind of model call) is described.
* The regulatory mapping and the limits sections are present, its relative
  links resolve, and the card is linked from the index and the security docs.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from typing import List

import pytest

from lg_sotf.invariants.registry import INVARIANTS, render_markdown
from lg_sotf.onboarding.llm_profiles import PROFILES
from tests.deploy._support import REPO_ROOT

DOCS = REPO_ROOT / "docs"
CARD = DOCS / "ai-system-card.md"
SRC = REPO_ROOT / "src" / "lg_sotf"
REGISTER_RE = re.compile(r"register_prompt\(\s*f?\"([^\"]+)\"")
LINK_RE = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
RESIDENCY_WORDS = {"eu": "EU", "local": "Local", "us": "United States"}

_spec = importlib.util.spec_from_file_location("export_invariants_script", REPO_ROOT / "scripts" / "export_invariants.py")
assert _spec and _spec.loader
export_invariants = importlib.util.module_from_spec(_spec)
sys.modules["export_invariants_script"] = export_invariants
_spec.loader.exec_module(export_invariants)


def card_text() -> str:
    return CARD.read_text(encoding="utf-8")


def section(text: str, heading: str) -> str:
    """The body of the ``## <heading>`` section."""
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, f"section {heading!r} missing"
    return match.group(1)


def registered_prompts() -> List[str]:
    """Every prompt name registered in the source, f-string placeholders written as ``<name>``."""
    names = set()
    for path in SRC.rglob("*.py"):
        for raw in REGISTER_RE.findall(path.read_text(encoding="utf-8")):
            names.add(re.sub(r"\{(\w+)\}", r"<\1>", raw))
    return sorted(names)


def test_the_invariants_table_is_generated_from_the_registry() -> None:
    text = card_text()
    expected = export_invariants.card_with_table(text, export_invariants.summary_table(render_markdown()))
    assert text == expected, "docs/ai-system-card.md is stale; regenerate with: python scripts/export_invariants.py"
    for invariant in INVARIANTS:
        assert f"| {invariant.id} | {invariant.title} |" in text, invariant.id
    assert "(invariants.md)" in section(text, "6. Safety invariants")


def test_every_offered_model_profile_is_listed_with_its_models_and_residency() -> None:
    models = section(card_text(), "3. Models and where they run")
    for profile in PROFILES:
        rows = [line for line in models.splitlines() if line.startswith(f"| `{profile.id}`")]
        assert len(rows) == 1, f"{profile.id}: expected one row"
        row = rows[0]
        assert profile.provider in row, profile.id
        assert RESIDENCY_WORDS[profile.residency] in row, profile.id
        for model in (profile.fast_model, profile.deep_model):
            if not model.startswith("<"):
                assert f"`{model}`" in row, f"{profile.id}: {model}"


def test_deepseek_is_never_presented_as_supported() -> None:
    assert not any("deepseek" in f"{p.id} {p.base_url} {p.fast_model} {p.deep_model}".lower() for p in PROFILES)
    models = section(card_text(), "3. Models and where they run")
    assert "**DeepSeek is not supported for customer data.**" in models
    table_rows = [line for line in models.splitlines() if line.startswith("| `")]
    assert not any("deepseek" in row.lower() for row in table_rows)


def test_every_registered_prompt_is_described() -> None:
    agents = section(card_text(), "4. Agents and their tools")
    prompts = registered_prompts()
    assert len(prompts) >= 6, prompts
    missing = [name for name in prompts if f"`{name}`" not in agents]
    assert not missing, f"describe these model calls in section 4 of the card: {missing}"


@pytest.mark.parametrize(
    "heading",
    [
        "2. Intended use and out-of-scope uses",
        "5. What the AI decides and what people decide",
        "7. Evaluation evidence",
        "8. Logging and traceability",
        "9. Data handling and retention",
        "10. Human oversight design",
        "11. Known limits",
        "12. EU AI Act mapping",
        "13. NIS2 mapping",
        "14. Sources",
    ],
)
def test_required_sections_exist(heading: str) -> None:
    assert section(card_text(), heading).strip()


def test_the_regulatory_mapping_names_its_articles_and_caveats() -> None:
    text = card_text()
    assert "not legal advice" in text.lower()
    act = section(text, "12. EU AI Act mapping")
    for needle in ("Art. 12", "Art. 13", "Art. 14", "Art. 15", "Art. 26(6)", "Annex III point 2", "Recital 55",
                   "Art. 6(3)", "Art. 4", "Art. 50", "*Uncertain"):
        assert needle in act, needle
    nis2 = section(text, "13. NIS2 mapping")
    assert "Art. 21(2)" in nis2 and "2024/2690" in nis2
    assert "(compliance.md#nis2-incident-report-drafts)" in nis2
    sources = section(text, "14. Sources")
    assert "eur-lex.europa.eu" in sources


def test_the_evaluation_section_states_synthetic_data_small_samples_and_known_gaps() -> None:
    evaluation = section(card_text(), "7. Evaluation evidence")
    for needle in ("synthetic", "small samples", "95%", "scorecards/v1/qwen2.5-7b/scorecard.md",
                   "scorecards/v2/deepseek-v4/scorecard.md", "adversarial_v2.jsonl", "title-camouflage", "#299"):
        assert needle in evaluation, needle


def test_relative_links_resolve() -> None:
    broken = []
    for target in LINK_RE.findall(card_text()):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        if not (DOCS / target).resolve().exists():
            broken.append(target)
    assert not broken, f"broken links in the card: {broken}"


@pytest.mark.parametrize("doc", ["index.md", "security.md", "threat-model.md", "compliance.md"])
def test_the_card_is_linked(doc: str) -> None:
    assert "(ai-system-card.md)" in (DOCS / doc).read_text(encoding="utf-8")
