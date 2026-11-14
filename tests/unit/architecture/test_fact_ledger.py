"""Facts get their ids in one place and reach the store through one door (AI-E3.2).

The ledger's guarantee (code mints every fact id, a model supplies none) only holds while nothing else
builds a ledger entry or writes the table, so this test reads the source of ``src/lg_sotf``:

* **The entry types and builders** (``LedgerEntry``, ``StoredFact``, ``build_entries``, ``plan_record``,
  ``mint_fact_id``) are used as values (called, ``model_validate``d, ``model_construct``ed, passed on)
  only by the ledger's rules, the run's ledger and the table's repository. Elsewhere they may only be
  written in a type annotation. Aliases count: an import under another name, or through the module.
* **The repository class** is named only in its own module and where the repositories are assembled.
* **The store** (``<repos>.evidence_facts``) is taken only by the run's ledger, which writes, and by the
  investigation view, which calls its one read. ``getattr(x, "evidence_facts")`` is the same thing.
* **The table's name** appears in code (any string that is not documentation) only in its repository,
  its migration, the runtime grants and the tenant export; and no SQL there updates, deletes or
  truncates it, in any spelling (``public.``, ``ONLY``, quotes).
* **No id is stamped around the ledger**: nothing defines or imports a ``cited`` helper again.

The review of PR #438 showed a second writer that the first version of these scans missed. Its three
mutations are kept here as source text and must each be caught, line by line.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, Iterator, List, Set

import pytest

from lg_sotf.db.migrate import RUNTIME_TABLE_PRIVILEGES
from tests.unit.architecture._support import source_files

pytestmark = pytest.mark.unit

TABLE = "evidence_facts"
ENTRY_NAMES = frozenset({"LedgerEntry", "StoredFact", "build_entries", "plan_record", "mint_fact_id"})
REPO_NAME = "EvidenceFactsRepo"
MAY_USE_ENTRIES = frozenset({"domain/ledger.py", "agents/investigation/ledger.py", "db/repos/evidence_facts.py"})
MAY_NAME_THE_REPO = frozenset({"db/repos/evidence_facts.py", "db/repos/__init__.py"})
# The modules that may take the store (``repos.evidence_facts``), and the methods each may call on it.
# The run's ledger hands it to ``FactLedger`` as its store; the investigation view only reads.
MAY_REACH_THE_STORE: Dict[str, frozenset[str]] = {
    "agents/investigation/ledger.py": frozenset(),
    "services/investigation.py": frozenset({"latest_run"}),
}
# Where the table's name may appear in code, and exactly which strings in the two that only mention it.
REPO, MIGRATION = "db/repos/evidence_facts.py", "db/migrations/versions/0021_evidence_facts.py"
MAY_SPELL_THE_TABLE: Dict[str, frozenset[str] | None] = {
    REPO: None,
    MIGRATION: None,
    "db/migrate.py": frozenset({TABLE}),
    "compliance/tenant_data.py": frozenset({TABLE, f"{TABLE}.jsonl"}),
}
_NAME = r"""(?:ONLY\s+)?(?:"?public"?\s*\.\s*)?"?evidence_facts\b"""
MUTATION = re.compile(rf"\b(?:UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+{_NAME}", re.IGNORECASE)
MUTATING_WORD = re.compile(r"\b(UPDATE|DELETE|TRUNCATE|DROP|ALTER)\b", re.IGNORECASE)


def _annotations(tree: ast.AST) -> Set[int]:
    """The ids of every node inside a type annotation (an argument's, a return's, a variable's)."""
    inside: Set[int] = set()
    for node in ast.walk(tree):
        found: List[ast.AST | None] = []
        if isinstance(node, ast.arg):
            found.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            found.append(node.annotation)
        for annotation in found:
            if annotation is not None:
                inside.update(id(n) for n in ast.walk(annotation))
    return inside


def _bound(tree: ast.AST, names: frozenset[str]) -> Set[str]:
    """Every local name an import binds to one of ``names``, whatever it is called here."""
    local: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            local.update(alias.asname or alias.name for alias in node.names if alias.name in names)
    return local | set(names)


def value_uses(tree: ast.AST, names: frozenset[str]) -> List[str]:
    """Each use of one of ``names`` (or an alias) as a value: anything but an import or a type annotation."""
    annotations, local = _annotations(tree), _bound(tree, names)
    uses: List[str] = []
    for node in ast.walk(tree):
        if id(node) in annotations:
            continue
        if isinstance(node, ast.Name) and node.id in local:
            uses.append(f"{node.lineno}: {node.id}")
        elif isinstance(node, ast.Attribute) and node.attr in names:
            uses.append(f"{node.lineno}: {ast.unparse(node)}")
    return uses


def _is_store(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == TABLE


def store_reaches(tree: ast.AST, allowed: frozenset[str] | None) -> List[str]:
    """Each place the store is taken (``x.evidence_facts``) or one of its methods named, outside ``allowed``
    (``None``: the module may not take the store at all)."""
    reaches: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if _is_store(node) and allowed is None:
            reaches.append(f"{node.lineno}: {ast.unparse(node)}")
        elif _is_store(node.value) and node.attr not in (allowed or frozenset()):
            reaches.append(f"{node.lineno}: {ast.unparse(node)}")
    return reaches


def _documentation(tree: ast.AST) -> Set[int]:
    """Strings that are statements of their own (docstrings): they do nothing."""
    return {
        id(node.value) for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
    }


def code_strings(tree: ast.AST) -> Iterator[ast.Constant]:
    """Every string the code can use: constants and the fixed parts of f-strings, documentation left out."""
    documentation = _documentation(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in documentation:
            yield node


def table_strings(tree: ast.AST) -> List[str]:
    """Each string in code that spells the table's name (a table name, an attribute name, SQL)."""
    return [f"{node.lineno}: {node.value[:60]!r}" for node in code_strings(tree) if TABLE in node.value]


def stamps(tree: ast.AST) -> List[str]:
    """A ``cited`` helper defined or imported: the name of the function that numbered ids per call."""
    found: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "cited":
            found.append(f"{node.lineno}: def cited")
        elif isinstance(node, ast.ImportFrom) and any(alias.name == "cited" for alias in node.names):
            found.append(f"{node.lineno}: import cited")
    return found


def findings(rel: str, tree: ast.AST) -> List[str]:
    """Everything in one module that goes around the ledger."""
    found: List[str] = []
    if rel not in MAY_USE_ENTRIES:
        found += [f"{rel}:{use} (an entry type or builder used outside the ledger)" for use in value_uses(tree, ENTRY_NAMES)]
    if rel not in MAY_NAME_THE_REPO:
        named = value_uses(tree, frozenset({REPO_NAME})) + [
            f"{node.lineno}: import {REPO_NAME}" for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and any(alias.name == REPO_NAME for alias in node.names)
        ]
        found += [f"{rel}:{use} (the repository named outside the repositories)" for use in named]
    found += [f"{rel}:{reach} (the store reached)" for reach in store_reaches(tree, MAY_REACH_THE_STORE.get(rel))]
    spelled, allowed = table_strings(tree), MAY_SPELL_THE_TABLE.get(rel, frozenset())
    if rel not in MAY_SPELL_THE_TABLE:
        found += [f"{rel}:{string} (the table named in code)" for string in spelled]
    elif allowed is not None:
        extra = sorted({node.value for node in code_strings(tree) if TABLE in node.value} - allowed)
        found += [f"{rel}: {string!r} (another use of the table's name)" for string in extra]
    found += [f"{rel}:{stamp} (ids stamped around the ledger)" for stamp in stamps(tree)]
    return found


def test_nothing_in_the_source_goes_around_the_ledger() -> None:
    around = [finding for src in source_files() for finding in findings(src.rel, src.tree)]
    assert around == [], "a fact gets its id from FactLedger.record and reaches the table through it, nowhere else"


def test_the_scans_see_what_they_guard() -> None:
    """The allowed call sites exist, so a scan that stopped seeing them would fail here."""
    trees = {src.rel: src.tree for src in source_files()}
    assert set(MAY_USE_ENTRIES) | set(MAY_NAME_THE_REPO) | set(MAY_REACH_THE_STORE) | set(MAY_SPELL_THE_TABLE) <= set(trees)
    assert all(value_uses(trees[rel], ENTRY_NAMES) for rel in MAY_USE_ENTRIES)
    assert value_uses(trees["db/repos/__init__.py"], frozenset({REPO_NAME}))  # where the repositories are assembled
    reached = {rel: sorted({r.split(": ")[1] for r in store_reaches(trees[rel], None)}) for rel in MAY_REACH_THE_STORE}
    assert reached == {
        "agents/investigation/ledger.py": ["ctx.repos.evidence_facts"],
        "services/investigation.py": ["repos.evidence_facts", "repos.evidence_facts.latest_run"],
    }
    assert all(table_strings(trees[rel]) for rel in MAY_SPELL_THE_TABLE)
    assert RUNTIME_TABLE_PRIVILEGES[TABLE] == ("SELECT", "INSERT")


def test_sql_on_the_table_never_updates_deletes_or_truncates() -> None:
    trees = {src.rel: src.tree for src in source_files()}
    sql = {rel: [node.value for node in code_strings(trees[rel]) if TABLE in node.value] for rel in (REPO, MIGRATION)}
    assert all(sql.values())
    assert [s for strings in sql.values() for s in strings if MUTATION.search(s)] == []
    # The repository only inserts and selects: none of its SQL holds a word that changes or removes.
    assert [s for s in sql[REPO] if MUTATING_WORD.search(s)] == []
    assert all(re.match(r"\s*(INSERT INTO|SELECT)\b", s) for s in sql[REPO])


# The reviewer's three second writers (scratchpad/rev438_probe/mutation_*.py), as they would sit in the tree.
SECOND_WRITER = '''
from lg_sotf.db.repos.evidence_facts import EvidenceFactsRepo
from lg_sotf.domain.ledger import LedgerEntry
from lg_sotf.tools.wazuh.tools import cited as stamp

TABLE = "evidence_facts"


async def second_writer(db, conn, tenant_id, alert_id, model_text, result):
    entry = LedgerEntry.model_validate({"fact_id": model_text})
    forged = LedgerEntry.model_construct(fact_id=model_text)
    await EvidenceFactsRepo(db).append(tenant_id, alert_id, "r", [entry, forged])
    store = getattr(db, "evidence_facts")
    await store.append(tenant_id, alert_id, "r", [entry])
    await conn.execute("INSERT INTO public.evidence_facts (tenant_id) VALUES ($1)", tenant_id)
    await conn.execute(f"DELETE FROM {TABLE} WHERE tenant_id = $1", tenant_id)
    await conn.execute("UPDATE public.evidence_facts SET outcome = $1", "success")
    return stamp(result, "host")
'''
REPO_SECOND_WRITER = '''
from lg_sotf.db.repos._base import Repository


class ProbeRepo(Repository):
    async def rewrite(self, tenant_id, model_text):
        async with self._tenant(tenant_id, None) as c:
            await c.execute("INSERT INTO public.evidence_facts (tenant_id, fact_id) VALUES ($1, $2)", tenant_id, model_text)
            await c.execute("UPDATE public.evidence_facts SET outcome = $1", "success")
            await c.execute("DELETE FROM ONLY evidence_facts WHERE tenant_id = $1", tenant_id)
'''


@pytest.mark.parametrize("rel", ["agents/analysis/second_writer.py", "services/second_writer.py", "db/repos/second_writer.py"])
def test_a_second_writer_is_caught_line_by_line(rel: str) -> None:
    caught = findings(rel, ast.parse(SECOND_WRITER))
    lines = {int(finding.split(":")[1]) for finding in caught}
    source = SECOND_WRITER.splitlines()
    # Reported: the repository's import and its use, the old helper's import, the table's name as a constant,
    # as an attribute name and in SQL, and both ways to build an entry.
    wanted = ("import EvidenceFactsRepo", "cited as stamp", "TABLE =", "model_validate", "model_construct",
              "EvidenceFactsRepo(db)", "getattr(db", "INSERT INTO public", "UPDATE public")
    expected = {n for n, line in enumerate(source, start=1) if any(part in line for part in wanted)}
    assert len(expected) == len(wanted) and lines == expected, sorted(expected ^ lines)
    # Not reported on their own line, and caught where they come from: the entry type's import (an annotation
    # may use it), ``store.append`` (the ``getattr`` line), the f-string SQL (the constant) and ``stamp(...)``.
    assert [source[n - 1].strip()[:24] for n in sorted(lines)][:3] == [
        "from lg_sotf.db.repos.ev", "from lg_sotf.tools.wazuh", 'TABLE = "evidence_facts"'
    ]


def test_a_second_repository_is_caught_and_its_sql_reads_as_a_mutation() -> None:
    caught = findings("db/repos/probe.py", ast.parse(REPO_SECOND_WRITER))
    assert len(caught) == 3 and all("the table named in code" in finding for finding in caught)
    statements = [node.value for node in code_strings(ast.parse(REPO_SECOND_WRITER)) if TABLE in node.value]
    assert [bool(MUTATION.search(s)) for s in statements] == [False, True, True]
    for spelled in ('DELETE FROM "public"."evidence_facts"', "truncate table only evidence_facts", "update  evidence_facts set x = 1",
                    "TRUNCATE evidence_facts", "DELETE FROM public . evidence_facts"):
        assert MUTATION.search(spelled), spelled
    for harmless in ("BEFORE UPDATE OR DELETE ON evidence_facts", "BEFORE TRUNCATE ON evidence_facts", "SELECT * FROM evidence_facts"):
        assert not MUTATION.search(harmless), harmless


def test_an_alias_or_a_module_import_does_not_hide_a_use() -> None:
    hidden = ast.parse(
        "from lg_sotf.domain.ledger import LedgerEntry as Row, build_entries as make\n"
        "import lg_sotf.domain.ledger as rules\n"
        "from lg_sotf.db import repos\n"
        "def f(entry: Row, rows: 'list[Row]') -> Row:\n"
        "    return entry\n"
        "a = Row.model_construct()\n"
        "b = make(None, [], None)\n"
        "c = rules.LedgerEntry\n"
        "d = repos.EvidenceFactsRepo\n"
        "e = repos.StoredFact\n"
    )
    caught = findings("services/hidden.py", hidden)
    assert sorted(int(finding.split(":")[1]) for finding in caught) == [6, 7, 8, 9, 10]
    # A type annotation alone is what the read model and the checker do, and is fine.
    annotated = ast.parse("from lg_sotf.domain.ledger import LedgerEntry\ndef f(entry: LedgerEntry) -> None: ...\n")
    assert findings("domain/citations.py", annotated) == []
