"""Shared by the Wazuh evidence tool tests: the corpus telemetry, a registry over a backend, small readers."""

from __future__ import annotations

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


def raw(alert: Mapping[str, Any], name: str) -> str:
    """A Windows ``eventdata`` value as Windows wrote it (the doubled backslashes undone); '' when absent."""
    found = field_values(alert, ED + name)
    return found[0].replace("\\\\", "\\") if found else ""


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
        """The call's one fact; ``None`` when nothing matched. A failed call fails the test."""
        result = await self.call(tool, **params)
        assert result.outcome != "failed", (tool, result.value.error)
        return result.value[0] if result.value else None


def investigate(corpus_: Corpus, item: EvalItem, settle_min: float = 15) -> Investigation:
    return Investigation(corpus_.store, event_time(item.alert) + minutes(settle_min))
