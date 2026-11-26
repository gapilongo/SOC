"""Investigation tools run through the tool registry and nowhere else (AI-E2.1, INV-14).

The registry validates, switches, caps, scopes and traces every call. That only holds while nothing calls
a lookup around it, so this test reads the source:

* the enrichment service's lookups (``lookup``, ``lookup_one``, ``history``) are called only by the tools
  that wrap them (``tools/enrichment/tools.py``) and by the service itself;
* one registry is built, in one place (``enrichment_tools``), and one caller builds it (the analysis agent);
* a Wazuh indexer is searched only by the Wazuh evidence tools (``tools/wazuh/tools.py``), and its client
  is built only by the resolver that reads the calling run's own source (``ingestion/wazuh_indexer.py``);
* the evidence tools are registered on that one registry by the analysis agent, which alone builds the
  investigation executor that calls them (``agents/investigation/executor.py``, through ``ToolRegistry.call``).

A new tool family adds its own line here, in the pull request that registers it.
"""

from __future__ import annotations

import ast
from typing import List

import pytest

from tests.unit.architecture._support import source_files

pytestmark = pytest.mark.unit

LOOKUPS = frozenset({"lookup", "lookup_one", "history"})
SERVICE_MODULES = ("tools/enrichment/",)
# Who may build what: a registry, a tool family, the client of a tenant's indexer.
REGISTRY_BUILDERS = {
    "ToolRegistry": {"tools/enrichment/tools.py"},
    "enrichment_tools": {"agents/analysis/base.py"},
    "wazuh_tools": {"tools/wazuh/tools.py"},
    "IndexerClient": {"ingestion/wazuh_indexer.py"},
    # AI-E3.3: the Wazuh evidence tools join the one registry, in the agent that owns it; the resolver of the
    # tenants' indexers is built where the workflow's services are, and the executor by that agent alone.
    "register_wazuh_tools": {"agents/analysis/base.py"},
    "WazuhIndexers": {"core/workflow.py"},
    "SkillInvestigator": {"agents/analysis/base.py"},
}
SEARCHERS = {"tools/wazuh/tools.py"}


def _receiver(call: ast.Call) -> str:
    return ast.unparse(call.func.value) if isinstance(call.func, ast.Attribute) else ""


def test_enrichment_lookups_are_called_only_through_the_registry() -> None:
    direct: List[str] = []
    for src in source_files():
        if src.rel.startswith(SERVICE_MODULES):
            continue
        for node in ast.walk(src.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in LOOKUPS:
                if "enrichment" in _receiver(node).lower():
                    direct.append(f"{src.rel}:{node.lineno}: {ast.unparse(node.func)}")
    assert direct == [], "call the lookup through the tool registry (ToolRegistry.call), not the enrichment service"


def _searches_a_backend(node: ast.AST) -> bool:
    """``<backend or indexer>.search(...)``: a search sent to an evidence backend."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "search"):
        return False
    receiver = _receiver(node).lower()
    return "backend" in receiver or "indexer" in receiver


def test_the_wazuh_indexer_is_searched_only_by_its_tools() -> None:
    direct = [
        f"{src.rel}:{getattr(node, 'lineno', 0)}"
        for src in source_files()
        if src.rel not in SEARCHERS
        for node in ast.walk(src.tree)
        if _searches_a_backend(node)
    ]
    assert direct == [], "search a tenant's indexer through the Wazuh evidence tools (ToolRegistry.call)"
    found = [src.rel for src in source_files() for node in ast.walk(src.tree) if _searches_a_backend(node)]
    assert set(found) == SEARCHERS, "the scan sees the searches it guards"


def test_one_tool_registry_is_built_in_one_place() -> None:
    built: List[str] = []
    for src in source_files():
        for node in ast.walk(src.tree):
            name = node.func.id if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) else None
            if name in REGISTRY_BUILDERS and src.rel not in REGISTRY_BUILDERS[name]:
                built.append(f"{src.rel}:{node.lineno}: {name}(...)")
    assert built == [], "a second tool registry would run tools outside the one whose rules are tested"
    # The scan sees the calls it guards: every allowed call site exists.
    seen = {
        (src.rel, node.func.id)
        for src in source_files()
        for node in ast.walk(src.tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in REGISTRY_BUILDERS
    }
    assert seen == {(rel, name) for name, allowed in REGISTRY_BUILDERS.items() for rel in allowed}


def test_the_scan_catches_a_direct_lookup() -> None:
    tree = ast.parse("async def f(self):\n    return await self.enrichment.history('t1', 'ip', '198.51.100.7', repos=None)")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
    assert [n.func.attr in LOOKUPS and "enrichment" in _receiver(n).lower() for n in calls] == [True]
    search = ast.parse("async def f(self, body):\n    return await self.indexer.search(body), re.search('a', 'b')")
    found = {ast.unparse(n.func): _searches_a_backend(n) for n in ast.walk(search) if isinstance(n, ast.Call)}
    assert found == {"self.indexer.search": True, "re.search": False}
