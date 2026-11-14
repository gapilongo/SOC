"""Facts get their ids in one place and reach the store through one door (AI-E3.2).

The ledger's guarantee (code mints every fact id, a model supplies none) only holds while nothing else
builds a ledger entry or writes the table, so this test reads the source:

* a ledger entry is built only by the ledger's rules (``domain/ledger.py``): nothing else constructs a
  ``LedgerEntry`` or a stored one, or calls ``build_entries`` or ``mint_fact_id``, but the run's ledger
  (``agents/investigation/ledger.py``);
* the store (``repos.evidence_facts``) is reached only by the run's ledger, which writes, and by the
  investigation view, which reads;
* SQL that names the table lives in its repository and its migration, and none of it updates or deletes.
"""

from __future__ import annotations

import ast
import re
from typing import List

import pytest

from tests.unit.architecture._support import source_files

pytestmark = pytest.mark.unit

BUILDERS = frozenset({"LedgerEntry", "StoredFact", "build_entries", "mint_fact_id"})
MAY_BUILD = frozenset({"domain/ledger.py", "agents/investigation/ledger.py"})
# The modules that may take the repository (``repos.evidence_facts``), and the methods each may call on it.
# The run's ledger hands it to ``FactLedger`` as its store; the investigation view only reads.
MAY_REACH_THE_STORE = {
    "agents/investigation/ledger.py": frozenset[str](),
    "services/investigation.py": frozenset({"list_latest_run"}),
}
SQL_HOMES = frozenset({"db/repos/evidence_facts.py", "db/migrations/versions/0021_evidence_facts.py"})
TABLE_SQL = re.compile(r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE|FROM|JOIN)\s+evidence_facts\b", re.IGNORECASE)
MUTATION = re.compile(r"\b(UPDATE|DELETE\s+FROM|TRUNCATE)\s+evidence_facts\b", re.IGNORECASE)


def _called(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return ""
    return node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""


def _is_store(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "evidence_facts"


def test_only_the_ledger_builds_ledger_entries() -> None:
    elsewhere: List[str] = []
    for src in source_files():
        if src.rel in MAY_BUILD:
            continue
        elsewhere += [f"{src.rel}:{node.lineno}: {_called(node)}(...)" for node in ast.walk(src.tree) if _called(node) in BUILDERS]
    assert elsewhere == [], "a fact gets its id from FactLedger.record, nowhere else"


def test_no_code_stamps_fact_ids_around_the_ledger() -> None:
    """``tools.wazuh.tools.cited`` (INT3.4) also writes ``<evidence id>:<n>`` on a call's facts, numbered per
    call, not per run. The tools' own tests use it; an investigation must not: its ids come from the ledger."""
    callers = [
        f"{src.rel}:{node.lineno}" for src in source_files() for node in ast.walk(src.tree) if _called(node) == "cited"
    ]
    assert callers == [], "record the result with FactLedger.record; it mints the ids a verdict may cite"


def test_only_the_ledger_and_the_investigation_view_reach_the_store() -> None:
    reached: List[str] = []
    for src in source_files():
        if src.rel.startswith("db/repos/"):
            continue
        for node in ast.walk(src.tree):
            if not isinstance(node, ast.Attribute):
                continue
            if _is_store(node) and src.rel not in MAY_REACH_THE_STORE:
                reached.append(f"{src.rel}:{node.lineno}: {ast.unparse(node)}")
            elif _is_store(node.value) and node.attr not in MAY_REACH_THE_STORE.get(src.rel, frozenset()):
                reached.append(f"{src.rel}:{node.lineno}: {ast.unparse(node)}")
    assert reached == [], "write through FactLedger.record; read a run with FactLedger.facts"
    # The scan sees what it guards: the ledger takes the repository, the view reads the newest run.
    sites = {
        (src.rel, node.attr)
        for src in source_files()
        for node in ast.walk(src.tree)
        if isinstance(node, ast.Attribute) and src.rel in MAY_REACH_THE_STORE and (_is_store(node) or _is_store(node.value))
    }
    assert sites == {
        ("agents/investigation/ledger.py", "evidence_facts"),
        ("services/investigation.py", "evidence_facts"), ("services/investigation.py", "list_latest_run"),
    }


def test_sql_on_the_table_lives_in_its_repository_and_never_updates_or_deletes() -> None:
    stray = [src.rel for src in source_files() if src.rel not in SQL_HOMES and TABLE_SQL.search(src.text)]
    assert stray == [], "SQL on evidence_facts belongs in db/repos/evidence_facts.py"
    homes = {src.rel: src.text for src in source_files() if src.rel in SQL_HOMES}
    assert set(homes) == SQL_HOMES
    assert all(MUTATION.search(text) is None for text in homes.values())


def test_the_scan_catches_a_second_writer() -> None:
    tree = ast.parse(
        "async def f(repos, entry):\n"
        "    await repos.evidence_facts.append('t', 'a', 'r', [LedgerEntry(fact_id='host:9')])\n"
    )
    assert [_called(n) for n in ast.walk(tree) if _called(n) in BUILDERS] == ["LedgerEntry"]
    attributes = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
    assert [ast.unparse(n) for n in attributes if _is_store(n)] == ["repos.evidence_facts"]
    assert [n.attr for n in attributes if _is_store(n.value)] == ["append"]
    assert MUTATION.search("UPDATE evidence_facts SET outcome = 'success'") is not None
