"""Security documentation stays checkable: code references resolve, control IDs are unique.

``docs/threat-model.md`` and ``docs/hardening.md`` cite the code that enforces each
control as `` `path:line` `` or `` `path:start-end` ``. A reference to a file that was
moved or a line past its end means the document no longer describes the code.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import List, Tuple

import pytest

from tests.deploy._support import REPO_ROOT

DOCS = REPO_ROOT / "docs"
THREAT_MODEL = DOCS / "threat-model.md"
SECURITY = DOCS / "security.md"
INDEX = DOCS / "index.md"

# `path/to/file.ext:12` or `path/to/file:12-34`, alone in its backticks. A path has at least one "/".
REF_RE = re.compile(r"`((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+):(\d+)(?:-(\d+))?`")
THREAT_ROW_RE = re.compile(r"^\| (TM-[A-Z]+-\d+) \|", re.MULTILINE)

Ref = Tuple[str, int, int]


def refs(doc: Path) -> List[Ref]:
    found: List[Ref] = []
    for m in REF_RE.finditer(doc.read_text(encoding="utf-8")):
        start = int(m.group(2))
        found.append((m.group(1), start, int(m.group(3)) if m.group(3) else start))
    return found


@pytest.mark.parametrize("doc", [THREAT_MODEL], ids=lambda p: p.name)
def test_code_references_point_to_existing_files_and_lines(doc: Path) -> None:
    found = refs(doc)
    assert len(found) >= 20, f"{doc.name}: expected code references, found {len(found)}"
    broken: List[str] = []
    for path, start, end in found:
        target = REPO_ROOT / path
        if not target.is_file():
            broken.append(f"{path}:{start}: no such file")
            continue
        lines = len(target.read_text(encoding="utf-8").splitlines())
        if not 1 <= start <= end <= lines:
            broken.append(f"{path}:{start}-{end}: outside the file's {lines} lines")
    assert not broken, f"{doc.name} has stale references:\n" + "\n".join(broken)


def test_threat_model_covers_the_required_surfaces() -> None:
    text = THREAT_MODEL.read_text(encoding="utf-8")
    for heading in ("MCP server", "MSSP delegation", "Evidence tools", "CI/CD and supply chain"):
        assert re.search(rf"^### 2\.\d+ {re.escape(heading)}", text, re.MULTILINE), heading
    for n in range(1, 11):
        assert f"| ASI{n:02d} |" in text, f"OWASP Agentic ASI{n:02d} has no row"
    assert "AML.T0051" in text, "MITRE ATLAS mapping missing"
    assert "## 7. Gate per epic" in text


def test_threat_ids_are_unique() -> None:
    ids = THREAT_ROW_RE.findall(THREAT_MODEL.read_text(encoding="utf-8"))
    assert ids
    duplicates = [i for i, n in Counter(ids).items() if n > 1]
    assert not duplicates, f"duplicate threat ids: {duplicates}"


@pytest.mark.parametrize("doc", [SECURITY, INDEX], ids=lambda p: p.name)
def test_new_security_docs_are_linked(doc: Path) -> None:
    text = doc.read_text(encoding="utf-8")
    assert "(threat-model.md)" in text
