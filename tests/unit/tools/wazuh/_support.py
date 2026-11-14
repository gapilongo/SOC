"""Shared by the Wazuh evidence tool tests: the corpus telemetry, a registry over a backend, small readers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import cache
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from lg_sotf.eval.dataset import EvalItem, load_dataset
from lg_sotf.eval.tool_fixtures import EventStore, event_time, field_values
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.models.evidence_fact import EvidenceFact
from lg_sotf.tools.registry import ToolRegistry, ToolResult
from lg_sotf.tools.wazuh.indexer import Backend
from lg_sotf.tools.wazuh.tools import Evidence, wazuh_tools
from tests.unit.tools._support import Ctx, Settings, registry

EVAL = Path(__file__).resolve().parents[3] / "fixtures" / "eval"
ED = "data.win.eventdata."
FILES = {
    "corpus_v1": ("corpus_v1.jsonl.gz", "corpus_v1_events.jsonl.gz", "corpus_v1_gold.json"),
    "corpus_skills_v1": ("corpus_skills_v1.jsonl.gz", "corpus_skills_v1_events.jsonl.gz", "corpus_skills_v1_gold.json"),
}


@dataclass(frozen=True)
class Corpus:
    """A dataset, its context events in one store, and its gold evidence."""

    store: EventStore
    items: Dict[str, EvalItem]
    gold: Dict[str, Dict[str, Any]]

    def scenario(self, *names: str) -> List[EvalItem]:
        return [item for item in self.items.values() if any(f"scenario:{name}" in item.tags for name in names)]


@cache
def corpus(name: str) -> Corpus:
    dataset, events, gold = FILES[name]
    return Corpus(
        EventStore.load(EVAL / dataset, EVAL / events),
        {item.id: item for item in load_dataset(EVAL / dataset).items},
        json.loads((EVAL / gold).read_text(encoding="utf-8"))["items"],
    )


def _no_terms() -> Dict[str, Any]:
    return {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0, "buckets": []}


def _no_outcome() -> Dict[str, Any]:
    return {"doc_count": 0, "users": _no_terms(), "first": {"value": None}}


def nothing_found(**overrides: Any) -> Dict[str, Any]:
    """A whole search response that matched nothing, with every aggregation any template asks for."""
    aggs = {
        **{name: {"value": 0} for name in ("total", "users", "sources", "hosts")},
        **{name: {"value": None} for name in ("max_level", "first", "last")},
        **{name: _no_terms() for name in ("groups", "techniques", "source_list", "source_hosts", "logon_types")},
        "outcomes": {"buckets": {name: _no_outcome() for name in ("failure", "success", "lockout", "unknown_user")}},
        "oldest": {"value": 1.7e12},
    }
    answer = {"timed_out": False, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
              "hits": {"hits": []}, "aggregations": aggs}
    return {**answer, **overrides}


def raw(alert: Mapping[str, Any], name: str) -> str:
    """A Windows ``eventdata`` value as Windows wrote it (the doubled backslashes undone); '' when absent."""
    found = field_values(alert, ED + name)
    return found[0].replace("\\\\", "\\") if found else ""


def fake_secret(n: int = 0) -> str:
    """A made-up value for the masking tests: built at run time, so no literal in a test looks like a credential."""
    return "".join(["Fx", hashlib.sha256(f"lg-sotf-masking-fixture-{n}".encode()).hexdigest()[:10], "-Qz", str(7 + n), "!"])


def words(*parts: str) -> str:
    """A command line from its words (a flag and the value after it are never one literal)."""
    return " ".join(parts)


def minutes(count: float) -> timedelta:
    return timedelta(minutes=count)


def over(backend: Backend, settings: Optional[Settings] = None) -> ToolRegistry:
    """A registry with the four tools, every call answered by ``backend``."""

    async def backends(ctx: Any) -> Backend:
        return backend

    return registry(*wazuh_tools(backends), settings=settings)


class Investigation:
    """The four tools on a store, as of one moment (what the indexer held when the alert was investigated)."""

    def __init__(self, store: EventStore, as_of: datetime) -> None:
        self.as_of = as_of
        self.tools = over(EventStoreBackend(store.as_of(as_of)))
        self.ctx = Ctx()

    async def call(self, tool: str, **params: Any) -> ToolResult[Evidence]:
        return await self.tools.call(self.ctx, f"wazuh.{tool}", params, agent="investigation")

    async def fact(self, tool: str, **params: Any) -> Optional[EvidenceFact]:
        """The call's first fact; ``None`` when nothing matched. A failed call fails the test."""
        result = await self.call(tool, **params)
        assert result.outcome != "failed", (tool, result.value.error)
        return result.value[0] if result.value else None

    async def facts(self, tool: str, **params: Any) -> List[EvidenceFact]:
        """Every fact of the call (a lineage by image gives one per matching process)."""
        result = await self.call(tool, **params)
        assert result.outcome != "failed", (tool, result.value.error)
        return list(result.value)


def investigate(corpus_: Corpus, item: EvalItem, settle_min: float = 15) -> Investigation:
    return Investigation(corpus_.store, event_time(item.alert) + minutes(settle_min))
