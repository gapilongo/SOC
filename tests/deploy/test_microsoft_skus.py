"""``docs/microsoft-skus.md`` (INT1.10) covers every Microsoft API path the code sends, and nothing it does not.

The scan reads the Microsoft code with ``ast``: every string literal and every
literal part of an f-string that builds a path (one that starts with ``/``,
``https://`` or an interpolated value) and looks like ``/segment...``, plus
the verbs passed to ``post_action`` (``/api/machines/{id}/<verb>``). Each such
fragment must be a substring of an endpoint documented in section 4 of the
page, with ``{...}`` placeholders written as in the code. In the other
direction, the last literal segment of every documented endpoint must still
appear in the code.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from lg_sotf.integrations.microsoft.catalog import capabilities
from tests.deploy._support import REPO_ROOT

DOC = REPO_ROOT / "docs" / "microsoft-skus.md"
SRC = REPO_ROOT / "src" / "lg_sotf"
SCANNED: Tuple[Path, ...] = (
    *sorted((SRC / "integrations" / "microsoft").rglob("*.py")),
    SRC / "ingestion" / "sources" / "m365.py",
    SRC / "ingestion" / "sources" / "sentinel.py",
    SRC / "services" / "connectors" / "microsoft.py",
)
FRAGMENT_RE = re.compile(r"^/[A-Za-z$][A-Za-z0-9._$/{}()'=-]*$")
ENDPOINT_RE = re.compile(r"`(GET|POST|PATCH|DELETE) ([^`\s]+)`")
LAB_EVIDENCE = "pending (Microsoft lab tenant)"
LEARN = "https://learn.microsoft.com/"


def section(text: str, number: int) -> str:
    match = re.search(rf"^## {number}\. .*?(?=^## {number + 1}\. |\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, f"section {number} missing"
    return match.group(0)


def matrix() -> str:
    return section(DOC.read_text(encoding="utf-8"), 4)


def documented_endpoints() -> List[str]:
    return [path for _, path in ENDPOINT_RE.findall(matrix())]


def _docstrings(tree: ast.AST) -> Set[int]:
    ids: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _builds_a_path(node: ast.JoinedStr) -> bool:
    first = node.values[0] if node.values else None
    if isinstance(first, ast.FormattedValue):
        return True
    return isinstance(first, ast.Constant) and str(first.value).startswith(("/", "https://"))


def code_fragments() -> Dict[str, List[str]]:
    """``{fragment: ["file:line", ...]}`` of every path-like literal in the Microsoft code."""
    found: Dict[str, List[str]] = {}

    def add(value: str, path: Path, line: int) -> None:
        value = value.split("?")[0]
        if FRAGMENT_RE.match(value):
            found.setdefault(value, []).append(f"{path.relative_to(REPO_ROOT)}:{line}")

    for path in SCANNED:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = _docstrings(tree)
        in_fstring: Set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                parts = [v for v in node.values if isinstance(v, ast.Constant)]
                in_fstring.update(id(v) for v in parts)
                if _builds_a_path(node):
                    for part in parts:
                        add(str(part.value), path, node.lineno)
            elif isinstance(node, ast.Call) and getattr(node.func, "id", None) == "post_action" and len(node.args) >= 3:
                verb = node.args[2]
                if isinstance(verb, ast.Constant) and isinstance(verb.value, str):
                    add(f"/api/machines/{{id}}/{verb.value}", path, node.lineno)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings and id(node) not in in_fstring):
                add(node.value, path, node.lineno)
    return found


def test_the_scan_finds_the_known_endpoints() -> None:
    fragments = code_fragments()
    for expected in ("/v1.0/users", "/revokeSignInSessions", "/api/indicators", "/v1.0/admin/exchange/tracing/messageTraces",
                     "/api/machines/{id}/isolate", "/$value", "/v1/workspaces/", "/oauth2/v2.0/token"):
        assert expected in fragments, f"the scan no longer sees {expected}; fix the scanner, not the page"


def test_every_api_path_in_the_code_is_in_the_matrix() -> None:
    endpoints = documented_endpoints()
    missing = {
        fragment: where for fragment, where in code_fragments().items()
        if not any(fragment in endpoint for endpoint in endpoints)
    }
    assert not missing, (
        "add these Microsoft API paths to section 4 of docs/microsoft-skus.md "
        f"(licence per SKU, permission, Microsoft Learn link, lab evidence): {missing}"
    )


def test_every_documented_endpoint_is_still_called() -> None:
    code = "\n".join(path.read_text(encoding="utf-8") for path in SCANNED)
    stale = []
    for endpoint in documented_endpoints():
        literal = [s for s in endpoint.split("?")[0].split("/") if s and "{" not in s and "(" not in s]
        if not literal or literal[-1] not in code:
            stale.append(endpoint)
    assert not stale, f"no longer called by the code; move to section 5 or delete: {stale}"


def test_every_matrix_row_has_a_learn_source_and_lab_evidence() -> None:
    rows = [line for line in matrix().splitlines() if line.startswith("| `")]
    assert len(rows) >= 25, f"expected the full matrix, found {len(rows)} rows"
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert len(cells) == 9, f"expected 9 columns: {row[:80]}"
        assert LEARN in cells[7], f"no Microsoft Learn link: {row[:80]}"
        assert cells[8] == LAB_EVIDENCE, f"lab evidence must be {LAB_EVIDENCE!r} until verified: {row[:80]}"
        for verdict in cells[3:6]:
            assert re.match(r"^(Yes|No|Unconfirmed|n/a|File: )", verdict), f"unknown verdict {verdict!r}: {row[:80]}"


def test_every_declared_permission_is_on_the_page() -> None:
    text = DOC.read_text(encoding="utf-8")
    roles = {p.role for spec in capabilities().values() for p in spec.permissions}
    missing = sorted(role for role in roles if role not in text)
    assert not missing, f"permissions declared by capabilities but not in docs/microsoft-skus.md: {missing}"


def test_the_page_is_linked() -> None:
    for doc in ("index.md", "microsoft.md"):
        assert "(microsoft-skus.md)" in (REPO_ROOT / "docs" / doc).read_text(encoding="utf-8"), doc
