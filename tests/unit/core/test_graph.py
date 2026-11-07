"""State capping, reducers, lazy package import and graph wiring."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from typing import Any, Dict

import pytest

from lg_sotf.core.graph import (
    GRAPH_BUILDERS,
    GRAPH_VERSION,
    MAX_ALERT_JSON_CHARS,
    MAX_NOTES,
    NODE_NAMES,
    build_graph,
    cap_alert,
    capped_notes,
)
from lg_sotf.domain.routing import RoutingThresholds


def test_importing_core_has_no_side_effects() -> None:
    code = (
        "import sys, lg_sotf.core as c;"
        "bad=[m for m in sys.modules if m.startswith(('lg_sotf.core.workflow','lg_sotf.agents','langgraph'))];"
        "assert not bad, bad"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_capped_notes_keeps_newest() -> None:
    notes = capped_notes([f"n{i}" for i in range(MAX_NOTES)], ["x" * 1000])
    assert len(notes) == MAX_NOTES and notes[-1] == "x" * 300 and notes[0] == "n1"


def test_cap_alert_bounds_size_and_keeps_identity() -> None:
    alert: Dict[str, Any] = {
        "id": "a1",
        "title": "t" * 10_000,
        "severity": "high",
        "entities": {"ips": [f"10.0.0.{i}" for i in range(500)]},
        "raw": {f"r{i}": "x" * 1_900 for i in range(20)},
        "extra": {f"k{i}": "y" * 1_900 for i in range(60)},
    }
    capped = cap_alert(alert)
    assert len(json.dumps(capped)) <= MAX_ALERT_JSON_CHARS
    assert capped["id"] == "a1" and capped["severity"] == "high"
    assert len(capped["title"]) <= 2_000 and len(capped["entities"]["ips"]) == 50
    assert capped["raw"] == {"_omitted": "raw event too large for workflow state"}


def _near_limit_alert() -> Dict[str, Any]:
    """An alert at the ingestion caps: 50 items per entity kind, long URLs and command lines."""
    return {
        "id": "a1",
        "title": "Suspicious command lines " + "t" * 480,
        "severity": "high",
        "category": "execution",
        "source_id": "edr-prod",
        "occurred_at": "2026-09-01T00:00:00+00:00",
        "fingerprint": "f" * 64,
        "description": "d" * 8_000,
        "entities": {
            "urls": [f"https://example{i}.com/" + "u" * 2_000 for i in range(50)],
            "command_lines": [f"powershell -enc {i} " + "c" * 4_000 for i in range(50)],
            "ips": [f"203.0.113.{i}" for i in range(50)],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "hosts": [f"ws-{i:03d}" for i in range(50)],
        },
        "raw": {"k": "x" * 11_000},
    }


@pytest.mark.parametrize(
    "entities",
    [
        {"urls": [f"https://e{i}.example.com/" + "u" * 700 for i in range(50)]},
        _near_limit_alert()["entities"],
        {f"kind{k}": [f"v{k}-{i}-" + "z" * 1_000 for i in range(50)] for k in range(40)},
        {"nested": {f"k{i}": {f"j{j}": ["q" * 900] * 20 for j in range(20)} for i in range(20)}},
    ],
)
def test_cap_alert_terminates_and_keeps_indicators_at_ingestion_limits(entities: Dict[str, Any]) -> None:
    alert = {**_near_limit_alert(), "entities": entities}
    started = time.perf_counter()
    capped = cap_alert(alert)
    assert time.perf_counter() - started < 2.0
    assert len(json.dumps(capped, default=str)) <= MAX_ALERT_JSON_CHARS
    assert capped["id"] == "a1" and capped["fingerprint"] == "f" * 64
    assert capped["_entities_truncated"] is True
    assert "_omitted_keys" in capped and "_omitted_keys" not in capped["_omitted_keys"]
    kept = capped.get("entities") or {}
    assert kept, "entities must survive in shrunk form"
    if "ips" in entities:
        assert kept["ips"][:3] == ["203.0.113.0", "203.0.113.1", "203.0.113.2"]
        assert kept["hashes"] == ["44d88612fea8a8f36de82e1278abb02f"]


def test_cap_alert_ignores_a_forged_omitted_keys_field() -> None:
    capped = cap_alert({"id": "a1", "title": "t", "severity": "low", "_omitted_keys": ["x"] * 10})
    assert "_omitted_keys" not in capped


class Nodes:
    def node(self, name: str):
        async def fn(state: Dict[str, Any]) -> Dict[str, Any]:
            return {}

        return fn


def test_graph_has_the_contract_nodes() -> None:
    compiled = build_graph(Nodes(), RoutingThresholds()).compile()
    assert set(NODE_NAMES) <= set(compiled.get_graph().nodes)


def test_every_kept_graph_builds_and_the_newest_is_the_current_version() -> None:
    assert max(GRAPH_BUILDERS) == GRAPH_VERSION
    for build in GRAPH_BUILDERS.values():
        build(Nodes(), RoutingThresholds()).compile()
