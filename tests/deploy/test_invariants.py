"""CI gate for the safety-invariant registry (SEC9.1, ``src/lg_sotf/invariants/registry.py``).

Fails when:

* an invariant has no proving test, or a pending one names no delivering story;
* a proving test node id does not exist (file, class or function missing);
* a proving test of an ``enforced`` invariant is marked skip, skipif or xfail,
  or skips unconditionally (statically: a test that skips at run time for a
  missing service is still run by the service-backed CI job);
* a threat-model row, code path or runtime check named by an invariant does not exist;
* a test in ``tests/invariants/`` proves no invariant;
* ``docs/invariants.md`` is not the registry's rendering.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

import pytest

from lg_sotf.invariants.checks import CHECKS
from lg_sotf.invariants.registry import INVARIANTS, render_markdown
from tests.deploy._support import REPO_ROOT

INVARIANT_TESTS = REPO_ROOT / "tests" / "invariants"
THREAT_MODEL = REPO_ROOT / "docs" / "threat-model.md"
DOCS_PAGE = REPO_ROOT / "docs" / "invariants.md"
SKIP_MARKS = frozenset({"skip", "skipif", "xfail"})
EPIC_RE = re.compile(r"^(ARCH-E|AI-E|PRD-|SEC|INT|GTM)\d+$")
STORY_RE = re.compile(r"^(ARCH-E|AI-E|PRD-|SEC|INT|GTM)\d+\.\d+[a-z]?$")

Def = Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef]


def _mark_names(node: ast.expr) -> List[str]:
    """``pytest.mark.<name>`` names in a decorator or ``pytestmark`` value."""
    if isinstance(node, ast.List | ast.Tuple):
        return [n for elt in node.elts for n in _mark_names(elt)]
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute) and node.value.attr == "mark":
        return [node.attr]
    return []


def _unconditional_skip(fn: Def) -> bool:
    for stmt in fn.body:
        call = stmt.value if isinstance(stmt, ast.Expr) else None
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr in ("skip", "xfail"):
            return True
    return False


def _find(body: Sequence[ast.stmt], name: str) -> Optional[Def]:
    for node in body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and node.name == name:
            return node
    return None


def resolve(node_id: str, root: Path = REPO_ROOT) -> Optional[List[Def]]:
    """The definitions a pytest node id names, outermost first; ``None`` when it does not exist."""
    path, *names = node_id.split("[", 1)[0].split("::")
    file = root / path
    if not names or not file.is_file():
        return None
    body: Sequence[ast.stmt] = ast.parse(file.read_text(encoding="utf-8")).body
    chain: List[Def] = []
    for name in names:
        found = _find(body, name)
        if found is None:
            return None
        chain.append(found)
        body = found.body
    return chain if isinstance(chain[-1], ast.FunctionDef | ast.AsyncFunctionDef) else None


def skip_reasons(node_id: str, root: Path = REPO_ROOT) -> List[str]:
    """Why the test would not run: module ``pytestmark``, decorators, or an unconditional skip call."""
    chain = resolve(node_id, root)
    assert chain is not None, node_id
    module = ast.parse((root / node_id.split("::", 1)[0]).read_text(encoding="utf-8"))
    reasons: List[str] = []
    for stmt in module.body:
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in stmt.targets):
            reasons += [f"module pytestmark {m}" for m in _mark_names(stmt.value) if m in SKIP_MARKS]
    for definition in chain:
        for decorator in definition.decorator_list:
            reasons += [f"{definition.name}: @{m}" for m in _mark_names(decorator) if m in SKIP_MARKS]
    if _unconditional_skip(chain[-1]):
        reasons.append(f"{chain[-1].name}: unconditional skip call")
    return reasons


# ------------------------------------------------------------------ the gate


def test_ids_are_unique_and_numbered_in_order() -> None:
    assert [inv.id for inv in INVARIANTS] == [f"INV-{i:02d}" for i in range(1, len(INVARIANTS) + 1)]


def test_every_invariant_is_complete() -> None:
    problems: List[str] = []
    for inv in INVARIANTS:
        if not (inv.title and inv.rationale and inv.threats):
            problems.append(f"{inv.id}: title, rationale and threats are required")
        if not EPIC_RE.match(inv.epic):
            problems.append(f"{inv.id}: owner epic {inv.epic!r} is not a backlog epic id")
        if not inv.proofs:
            problems.append(f"{inv.id}: no proving test")
        if inv.status == "enforced" and (inv.pending_story or not inv.code):
            problems.append(f"{inv.id}: an enforced invariant names the code that enforces it and no pending story")
        if inv.status == "pending" and not (inv.pending_story and STORY_RE.match(inv.pending_story)):
            problems.append(f"{inv.id}: a pending invariant names the story that delivers it")
    assert problems == []


def test_every_proving_test_exists() -> None:
    missing = [f"{inv.id}: {node}" for inv in INVARIANTS for node in inv.proofs if resolve(node) is None]
    assert missing == [], "proving tests that do not exist (renamed or moved?):\n" + "\n".join(missing)


def test_no_enforced_invariant_rests_on_a_skipped_test() -> None:
    skipped = [
        f"{inv.id}: {node}: {', '.join(reasons)}"
        for inv in INVARIANTS
        if inv.status == "enforced"
        for node in inv.proofs
        if resolve(node) is not None and (reasons := skip_reasons(node))
    ]
    assert skipped == [], "an enforced invariant's proof is skipped:\n" + "\n".join(skipped)


def test_threat_rows_code_paths_and_checks_exist() -> None:
    rows = set(re.findall(r"^\| (TM-[A-Z]+-\d+) \|", THREAT_MODEL.read_text(encoding="utf-8"), re.MULTILINE))
    problems = [f"{inv.id}: no threat-model row {t}" for inv in INVARIANTS for t in inv.threats if t not in rows]
    problems += [f"{inv.id}: no file {p}" for inv in INVARIANTS for p in inv.code if not (REPO_ROOT / p).is_file()]
    problems += [
        f"{inv.id}: runtime check {c} belongs to {CHECKS.get(c)}"
        for inv in INVARIANTS
        for c in inv.checks
        if CHECKS.get(c) != inv.id
    ]
    named = {c for inv in INVARIANTS for c in inv.checks}
    problems += [f"runtime check {c} is in no invariant" for c in sorted(set(CHECKS) - named)]
    assert problems == []


def test_every_test_in_tests_invariants_proves_an_invariant() -> None:
    proofs = {node.split("[", 1)[0] for inv in INVARIANTS for node in inv.proofs}
    orphans: List[str] = []
    for file in sorted(INVARIANT_TESTS.glob("test_*.py")):
        rel = file.relative_to(REPO_ROOT).as_posix()
        for node in ast.parse(file.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith("test_"):
                if f"{rel}::{node.name}" not in proofs:
                    orphans.append(f"{rel}::{node.name}")
    assert orphans == [], "add these to an invariant's proofs, or move them out of tests/invariants"


def test_docs_page_is_generated_from_the_registry() -> None:
    assert DOCS_PAGE.read_text(encoding="utf-8") == render_markdown(), (
        "docs/invariants.md is stale; regenerate with: python scripts/export_invariants.py"
    )


@pytest.mark.parametrize("doc", ["security.md", "threat-model.md", "index.md"])
def test_the_invariants_page_is_linked(doc: str) -> None:
    assert "(invariants.md)" in (REPO_ROOT / "docs" / doc).read_text(encoding="utf-8")


# ------------------------------------------------------------------ the gate's own helpers

SAMPLE = '''
import pytest

pytestmark = [pytest.mark.unit]

def test_runs(): pass

@pytest.mark.skip(reason="later")
def test_skipped(): pass

@pytest.mark.skipif(True, reason="never")
async def test_skipped_if(): pass

def test_skips_itself():
    pytest.skip("no")

def test_skips_conditionally(x=None):
    if x is None:
        pytest.skip("only without x")

@pytest.mark.xfail
class TestGroup:
    def test_member(self): pass

def helper(): pass
'''


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "test_sample.py").write_text(SAMPLE, encoding="utf-8")
    return tmp_path


def test_resolve_finds_functions_methods_and_parametrized_ids(sample: Path) -> None:
    assert resolve("t/test_sample.py::test_runs", sample) is not None
    assert resolve("t/test_sample.py::test_runs[case-1]", sample) is not None
    assert resolve("t/test_sample.py::TestGroup::test_member", sample) is not None
    for missing in ("t/test_sample.py::test_gone", "t/test_sample.py", "t/test_other.py::test_runs",
                    "t/test_sample.py::TestGroup", "t/test_sample.py::TestGroup::test_gone"):
        assert resolve(missing, sample) is None, missing


def test_skip_reasons_find_static_skips_only(sample: Path) -> None:
    reasons: Dict[str, List[str]] = {
        name: skip_reasons(f"t/test_sample.py::{name}", sample)
        for name in ("test_runs", "test_skipped", "test_skipped_if", "test_skips_itself", "test_skips_conditionally",
                     "TestGroup::test_member")
    }
    assert reasons == {
        "test_runs": [],
        "test_skipped": ["test_skipped: @skip"],
        "test_skipped_if": ["test_skipped_if: @skipif"],
        "test_skips_itself": ["test_skips_itself: unconditional skip call"],
        "test_skips_conditionally": [],
        "TestGroup::test_member": ["TestGroup: @xfail"],
    }


def test_a_module_level_skip_mark_counts(tmp_path: Path) -> None:
    (tmp_path / "test_m.py").write_text("import pytest\npytestmark = pytest.mark.skip\ndef test_a(): pass\n")
    assert skip_reasons("test_m.py::test_a", tmp_path) == ["module pytestmark skip"]
