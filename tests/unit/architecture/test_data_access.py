"""Data-access ratchets: who may run SQL, open transactions, audit, read settings and lock.

Each rule scans ``src/lg_sotf`` with the AST and compares what it finds with a
baseline file next to this test, one ``path::qualname`` per occurrence (a
function with two hits is listed twice). The baselines only shrink:

* an occurrence that is not in the baseline fails: fix the code, do not add a line;
* a baseline line that no longer matches anything fails: delete that line.

Rules:

``raw_sql_baseline.txt``
    ``.execute/.fetch/.fetchrow/.fetchval/.executemany`` outside ``db/`` whose first
    argument is a string literal, an f-string or a name ending in ``_SQL``. SQL belongs
    in ``db/`` repositories. ``await pipe.execute()`` (Redis) and
    ``handler.execute(action)`` are not SQL and are not flagged.
``router_tx_baseline.txt``
    ``.tenant_tx(``, ``.system_tx(`` and ``.connection(`` calls under ``api/``.
    Services own transactions; routers call services.
``audit_without_conn_baseline.txt``
    ``<...>audit.record(...)`` calls without ``conn=``. An audit row written outside
    the caller's transaction can disagree with the change it records.
``.audit.append(`` (no baseline)
    ``<...>.audit.append(...)`` outside ``audit/logger.py`` and ``db/``. Every audit row goes
    through ``AuditLogger``, which redacts the details and logs the entry.
``tenants.provision/create`` (no baseline)
    ``<...>.tenants.provision(...)`` and ``<...>.tenants.create(...)`` outside
    ``services/tenancy.py`` and ``db/``. Tenants are provisioned by
    ``provision_tenant`` (one transaction for the API and the CLI); the bootstrap
    tenant of ``migrate`` uses ``tenants.ensure``.
``get_settings_baseline.txt``
    ``get_settings()`` calls outside the composition roots (``cli.py``,
    ``api/app.py``, ``runtime/``, ``settings.py``, ``__main__.py``). Everything else
    takes its settings as a parameter.
``locks_baseline.txt``
    Advisory-lock class numbers declared outside ``db/locks.py``: module constants
    named ``*_LOCK`` or valued in the ``710_000`` namespace, and integer literals
    passed with, or written into, ``pg_advisory*`` SQL. ``db/locks.py`` owns every
    class number, and its numbers are unique.
"""

from __future__ import annotations

import ast
import re
from typing import Callable, Iterable

import pytest

from tests.unit.architecture._support import (
    MODULE_LEVEL,
    SourceFile,
    attr_name,
    baseline_path,
    in_dir,
    iter_calls,
    ratchet_problems,
    read_entries,
    source_files,
    walk_scoped,
)

pytestmark = pytest.mark.unit

Scanner = Callable[[str, ast.Module], list[str]]

SQL_METHODS = frozenset({"execute", "fetch", "fetchrow", "fetchval", "executemany"})
TX_METHODS = frozenset({"tenant_tx", "system_tx", "connection"})
SETTINGS_ROOTS = ("cli.py", "api/app.py", "settings.py", "__main__.py")
SETTINGS_ROOT_DIRS = ("runtime",)
LOCKS_MODULE = "db/locks.py"
LOCK_NAMESPACE = range(710_000, 711_000)
_ADVISORY_LITERAL = re.compile(r"pg_(?:try_)?advisory\w*\(\s*\d")


def _loc(rel: str, qual: str) -> str:
    return f"{rel}::{qual}"


def _is_sql_argument(arg: ast.expr) -> bool:
    if isinstance(arg, ast.Constant):
        return isinstance(arg.value, str)
    if isinstance(arg, ast.JoinedStr):
        return True
    if isinstance(arg, ast.Name):
        return arg.id.endswith("_SQL")
    if isinstance(arg, ast.Attribute):
        return arg.attr.endswith("_SQL")
    return False


def scan_raw_sql(rel: str, tree: ast.Module) -> list[str]:
    """SQL-looking ``execute``/``fetch*`` calls; the caller filters out ``db/``."""
    return [
        _loc(rel, qual)
        for call, qual in iter_calls(tree)
        if attr_name(call) in SQL_METHODS and call.args and _is_sql_argument(call.args[0])
    ]


def scan_tx_calls(rel: str, tree: ast.Module) -> list[str]:
    """``.tenant_tx(`` / ``.system_tx(`` / ``.connection(`` attribute calls."""
    return [_loc(rel, qual) for call, qual in iter_calls(tree) if attr_name(call) in TX_METHODS]


def is_audit_record(call: ast.Call) -> bool:
    """``X.record(...)`` where X's source ends in ``audit`` or X is ``AuditLogger(...)``."""
    if attr_name(call) != "record":
        return False
    assert isinstance(call.func, ast.Attribute)
    receiver = call.func.value
    if isinstance(receiver, ast.Call):
        return ast.unparse(receiver.func).split(".")[-1] == "AuditLogger"
    return ast.unparse(receiver).lower().endswith("audit")


def scan_audit_without_conn(rel: str, tree: ast.Module) -> list[str]:
    """Audit ``.record(...)`` calls (see :func:`is_audit_record`) that pass no ``conn=``.

    A ``**kwargs`` splat might carry ``conn``, so it is given the benefit of the doubt.
    """
    found: list[str] = []
    for call, qual in iter_calls(tree):
        if not is_audit_record(call):
            continue
        if any(kw.arg in ("conn", None) for kw in call.keywords):
            continue
        found.append(_loc(rel, qual))
    return found


def scan_audit_append(rel: str, tree: ast.Module) -> list[str]:
    """``X.audit.append(...)`` calls: the audit repository written to directly."""
    found: list[str] = []
    for call, qual in iter_calls(tree):
        if attr_name(call) != "append":
            continue
        assert isinstance(call.func, ast.Attribute)
        receiver = call.func.value
        if isinstance(receiver, ast.Attribute) and receiver.attr == "audit":
            found.append(_loc(rel, qual))
    return found


TENANT_CREATION = frozenset({"provision", "create"})
TENANT_CREATION_OWNERS = ("services/tenancy.py",)


def scan_tenant_creation(rel: str, tree: ast.Module) -> list[str]:
    """``X.tenants.provision(...)`` / ``X.tenants.create(...)`` calls."""
    found: list[str] = []
    for call, qual in iter_calls(tree):
        if attr_name(call) not in TENANT_CREATION:
            continue
        assert isinstance(call.func, ast.Attribute)
        receiver = call.func.value
        if isinstance(receiver, ast.Attribute) and receiver.attr == "tenants":
            found.append(_loc(rel, qual))
    return found


def scan_get_settings(rel: str, tree: ast.Module) -> list[str]:
    """Calls to ``get_settings()``, bare or as ``module.get_settings()``."""
    found: list[str] = []
    for call, qual in iter_calls(tree):
        func = call.func
        name = func.id if isinstance(func, ast.Name) else attr_name(call)
        if name == "get_settings":
            found.append(_loc(rel, qual))
    return found


def _int_value(node: ast.expr | None) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def module_int_constants(tree: ast.Module) -> dict[str, int]:
    """Module-level ``NAME = <int literal>`` (or annotated) assignments."""
    constants: dict[str, int] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            value = _int_value(stmt.value)
            targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            value = _int_value(stmt.value)
            targets = [stmt.target.id]
        else:
            continue
        if value is not None:
            constants.update(dict.fromkeys(targets, value))
    return constants


def _string_text(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def scan_lock_classes(rel: str, tree: ast.Module) -> list[str]:
    """Lock class numbers declared or written inline in this module.

    * ``NAME = <int>`` at module level, when NAME ends in ``_LOCK`` or the value is
      in the lock namespace (``710_000``-``710_999``): reported as ``path::NAME``;
    * a call whose SQL argument mentions ``pg_*advisory*`` and that passes an integer
      literal, or SQL text with a digit right after ``pg_*advisory*_lock(``:
      reported as ``path::qualname``.
    """
    found = [
        _loc(rel, name)
        for name, value in module_int_constants(tree).items()
        if name.endswith("_LOCK") or value in LOCK_NAMESPACE
    ]
    # An f-string's literal parts are also Constant nodes; read them once, through the f-string.
    fstring_parts = {id(part) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr) for part in node.values}
    for node, qual in walk_scoped(tree):
        text = _string_text(node) if isinstance(node, ast.expr) and id(node) not in fstring_parts else None
        if text is not None and _ADVISORY_LITERAL.search(text):
            found.append(_loc(rel, qual))
        if isinstance(node, ast.Call) and node.args:
            sql = _string_text(node.args[0])
            if sql is not None and "advisory" in sql and any(_int_value(a) is not None for a in node.args[1:]):
                found.append(_loc(rel, qual))
    return found


def collect(scanner: Scanner, include: Callable[[str], bool]) -> list[str]:
    hits: list[str] = []
    for src in source_files():
        if include(src.rel):
            hits.extend(scanner(src.rel, src.tree))
    return hits


def check(name: str, found: Iterable[str], baseline_file: str) -> None:
    path = baseline_path(baseline_file)
    problems = ratchet_problems(name, found, read_entries(path))
    assert not problems, f"{path.name} ratchet:\n" + "\n".join(problems)


def _outside_db(rel: str) -> bool:
    return not in_dir(rel, "db")


def _is_settings_root(rel: str) -> bool:
    return rel in SETTINGS_ROOTS or rel.endswith("/__main__.py") or in_dir(rel, *SETTINGS_ROOT_DIRS)


# --------------------------------------------------------------------------- ratchets


def test_raw_sql_stays_in_db() -> None:
    check("raw SQL outside db/", collect(scan_raw_sql, _outside_db), "raw_sql_baseline.txt")


def test_routers_do_not_open_transactions() -> None:
    check(
        "transaction call under api/", collect(scan_tx_calls, lambda rel: in_dir(rel, "api")), "router_tx_baseline.txt"
    )


def test_audit_records_pass_conn() -> None:
    check(
        "audit .record() without conn=",
        collect(scan_audit_without_conn, lambda rel: True),
        "audit_without_conn_baseline.txt",
    )


def test_audit_rows_are_written_only_through_audit_logger() -> None:
    allowed = ("audit/logger.py",)
    found = collect(scan_audit_append, lambda rel: rel not in allowed and not in_dir(rel, "db"))
    assert not found, "write audit entries with AuditLogger.record/record_event, not repos.audit.append: " + ", ".join(
        found
    )


def test_tenants_are_created_only_by_provision_tenant() -> None:
    found = collect(scan_tenant_creation, lambda rel: rel not in TENANT_CREATION_OWNERS and not in_dir(rel, "db"))
    assert not found, "create tenants with services.tenancy.provision_tenant: " + ", ".join(found)


def test_get_settings_only_in_composition_roots() -> None:
    found = collect(scan_get_settings, lambda rel: not _is_settings_root(rel))
    check("get_settings() outside composition roots", found, "get_settings_baseline.txt")


def test_lock_classes_declared_in_locks_module() -> None:
    found = collect(scan_lock_classes, lambda rel: rel != LOCKS_MODULE)
    check("advisory-lock class outside db/locks.py", found, "locks_baseline.txt")


def test_lock_class_numbers_are_unique() -> None:
    """``db/locks.py`` numbers are unique, and no stray ``*_LOCK`` constant reuses one."""
    by_file = {src.rel: src for src in source_files()}
    declared = module_int_constants(by_file[LOCKS_MODULE].tree)
    assert declared, f"{LOCKS_MODULE} declares no lock classes"
    owners: dict[int, list[str]] = {}
    for name, value in declared.items():
        owners.setdefault(value, []).append(f"{LOCKS_MODULE}::{name}")
    for entry in sorted(set(read_entries(baseline_path("locks_baseline.txt")))):
        rel, _, name = entry.partition("::")
        value = module_int_constants(by_file[rel].tree).get(name) if rel in by_file else None
        if value is not None:
            owners.setdefault(value, []).append(entry)
    clashes = {value: names for value, names in owners.items() if len(names) > 1}
    assert not clashes, f"advisory-lock class numbers reused: {clashes}"


# --------------------------------------------------------------------------- scanner self-tests


def _scan(scanner: Scanner, code: str) -> list[str]:
    return scanner("m.py", ast.parse(code))


def test_raw_sql_scanner_flags_sql_shaped_first_arguments() -> None:
    code = """
LIST_SQL = "SELECT 1"


class Repo:
    _SQL = "SELECT 2"

    async def run(self, conn, table):
        await conn.execute("SELECT 1")
        await conn.fetch(f"SELECT * FROM {table}")
        await conn.fetchrow(LIST_SQL, 1)
        await conn.fetchval(self._SQL)
        await conn.executemany("INSERT INTO t VALUES ($1)", [(1,)])


async def top(conn):
    await conn.execute("SELECT 3")
"""
    assert _scan(scan_raw_sql, code) == ["m.py::Repo.run"] * 5 + ["m.py::top"]


def test_raw_sql_scanner_ignores_non_sql_calls() -> None:
    code = """
async def run(pipe, handler, action, query, cursor):
    await pipe.execute()
    await handler.execute(action)
    await handler.execute(action, timeout=5)
    cursor.execute(query)
    execute("SELECT 1")
"""
    assert _scan(scan_raw_sql, code) == []


def test_tx_scanner_flags_attribute_calls_only() -> None:
    code = """
async def handler(ctx, db):
    async with ctx.db.tenant_tx(ctx.tenant_id) as conn:
        pass
    async with db.system_tx() as conn:
        pass
    async with db.connection() as conn:
        pass
    connection()
    tenant_tx = db.tenant_tx
"""
    assert _scan(scan_tx_calls, code) == ["m.py::handler"] * 3


def test_audit_scanner_flags_only_audit_records_without_conn() -> None:
    code = """
async def handler(ctx, self, audit, recorder, conn, kw):
    await ctx.audit.record("a")
    await self._audit.record("b", conn=conn)
    await audit.record("c")
    await recorder.record("d")
    await self._audit.record("e", **kw)
    await self.services.audit.record("f", conn=None)
    await AuditLogger(ctx.repos).record("g")
    await audit_mod.AuditLogger(ctx.repos).record("h", conn=conn)
    await Recorder(ctx).record("i")
"""
    assert _scan(scan_audit_without_conn, code) == ["m.py::handler"] * 3


def test_audit_append_scanner_flags_the_audit_repository_only() -> None:
    code = """
async def handler(self, repos, items, audit):
    await self._repos.audit.append("t", "system", None, "a", "r")
    await repos.audit.append("t", "system", None, "a", "r")
    items.append(1)
    audit.append(2)
    self.audit_trail.append(3)
"""
    assert _scan(scan_audit_append, code) == ["m.py::handler"] * 2


def test_tenant_creation_scanner_flags_the_tenants_repository_only() -> None:
    code = """
async def handler(ctx, repos, users):
    await ctx.repos.tenants.provision("t", "T")
    await repos.tenants.create("t", "T")
    await repos.tenants.ensure("t", "T")
    await repos.users.create("t", "e", "admin")
    await users.create("x")
"""
    assert _scan(scan_tenant_creation, code) == ["m.py::handler"] * 2


def test_get_settings_scanner_flags_calls_not_references() -> None:
    code = """
from lg_sotf import settings as settings_mod
from lg_sotf.settings import get_settings


def build(settings=None):
    settings = settings or get_settings()
    return settings_mod.get_settings()


FACTORY = get_settings
"""
    assert _scan(scan_get_settings, code) == ["m.py::build"] * 2


def test_lock_scanner_flags_declarations_and_inline_numbers() -> None:
    code = """
from lg_sotf.db import locks

CAP_LOCK = 710_020
OTHER = 710_500
PAGE_SIZE = 50
_LOCK_SQL = "SELECT pg_advisory_xact_lock($1, hashtext($2))"


async def take(conn, key):
    await conn.execute("SELECT pg_advisory_xact_lock($1, hashtext($2))", 710_030, key)
    await conn.execute(f"SELECT pg_advisory_lock(710031, {key})")
    await conn.execute(f"SELECT pg_advisory_lock({locks.MIGRATIONS}, 0)")
    await conn.execute(_LOCK_SQL, CAP_LOCK, key)
"""
    assert _scan(scan_lock_classes, code) == ["m.py::CAP_LOCK", "m.py::OTHER", "m.py::take", "m.py::take"]


def test_ratchet_reports_new_and_stale_entries() -> None:
    problems = ratchet_problems("x", ["a::f", "a::f", "b::g"], ["a::f", "c::h"])
    assert problems == [
        "new x: a::f (move it behind the proper owner; do not add it to the baseline)",
        "new x: b::g (move it behind the proper owner; do not add it to the baseline)",
        "stale x baseline line, delete it: c::h",
    ]


def test_module_level_hits_use_module_qualname() -> None:
    assert _scan(scan_get_settings, "from lg_sotf.settings import get_settings\nS = get_settings()\n") == [
        f"m.py::{MODULE_LEVEL}"
    ]


def test_settings_roots_are_exempt() -> None:
    assert _is_settings_root("cli.py")
    assert _is_settings_root("api/app.py")
    assert _is_settings_root("runtime/worker.py")
    assert _is_settings_root("mcp/__main__.py")
    assert not _is_settings_root("api/routers/alerts.py")
    assert not _is_settings_root("runtimes.py")


def test_source_files_are_package_relative() -> None:
    rels = {src.rel for src in source_files()}
    assert LOCKS_MODULE in rels and "settings.py" in rels
    assert all(isinstance(src, SourceFile) and not src.rel.startswith("src/") for src in source_files())
