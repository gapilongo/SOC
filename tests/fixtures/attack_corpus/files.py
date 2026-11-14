"""The files the generator writes next to ``corpus_v1.jsonl.gz`` (AI-E1.10), and the stores built from them.

``corpus_v1.jsonl.gz`` itself is written by :mod:`.corpus` and never changes
here. Everything else is derived from it or from :mod:`.skills`:

* ``corpus_v1_events.jsonl.gz``: the context events around the corpus alerts;
* ``corpus_v1_gold.json``: gold evidence for its skill-family items;
* ``corpus_skills_v1.jsonl.gz``, ``corpus_skills_v1_events.jsonl.gz`` and
  ``corpus_skills_v1_gold.json``: the skills dataset, its events and its gold.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.eval.tool_fixtures import EventStore
from tests.fixtures.attack_corpus import skills as S
from tests.fixtures.attack_corpus import telemetry as T
from tests.fixtures.attack_corpus.corpus import NAME as CORPUS_NAME
from tests.fixtures.attack_corpus.corpus import Corpus, alerts_json, build_corpus, gzip_bytes, sha256_text
from tests.fixtures.attack_corpus.gold import build_gold, gold_meta, gold_text

EVAL_DIR = Path(__file__).resolve().parents[1] / "eval"
EVENTS_V1 = "corpus_v1_events.jsonl.gz"
GOLD_V1 = "corpus_v1_gold.json"
SKILLS = "corpus_skills_v1.jsonl.gz"
EVENTS_SKILLS = "corpus_skills_v1_events.jsonl.gz"
GOLD_SKILLS = "corpus_skills_v1_gold.json"
DATASETS = (CORPUS_NAME, S.NAME)


def _gold(name: str, dataset: str, dataset_text: str, events: str, events_text: str, store: EventStore,
          rows: Sequence[Any]) -> str:
    items = build_gold(store, rows)
    meta = gold_meta(name=name, dataset=dataset, dataset_sha256=sha256_text(dataset_text), events=events,
                     events_sha256=sha256_text(events_text), items=items)
    return gold_text(meta, items)


def build_files(corpus: Optional[Corpus] = None) -> Dict[str, str]:
    """File name -> text of every derived file (the JSONL text of a ``.gz`` file, before compression)."""
    corpus = corpus or build_corpus()
    corpus_text = corpus.text()
    items = T.corpus_items(corpus)
    docs = T.build_telemetry(items)
    events = T.events_text(docs, T.events_meta(docs, dataset=CORPUS_NAME, dataset_sha256=sha256_text(corpus_text)))
    skills = S.build_skills()
    skills_text = skills.text()
    skills_events = T.events_text(skills.events, T.events_meta(
        skills.events, name=S.EVENTS_NAME, dataset=S.NAME, dataset_sha256=sha256_text(skills_text),
        description=S.EVENTS_DESCRIPTION, module="tests.fixtures.attack_corpus.skills"))
    return {
        EVENTS_V1: events,
        GOLD_V1: _gold("corpus_v1_gold", CORPUS_NAME, corpus_text, T.NAME, events,
                       T.store_of(corpus.alerts, docs), T.gold_rows(items)),
        SKILLS: skills_text,
        EVENTS_SKILLS: skills_events,
        GOLD_SKILLS: _gold("corpus_skills_v1_gold", S.NAME, skills_text, S.EVENTS_NAME, skills_events,
                           T.store_of(skills.alerts, skills.events), skills.gold_rows()),
    }


def file_bytes(name: str, text: str) -> bytes:
    return gzip_bytes(text) if name.endswith(".gz") else text.encode("utf-8")


def telemetry_json(dataset: str) -> str:
    """Everything an investigation of ``dataset`` can read (its alerts and context events) as ``alerts.json`` lines."""
    docs: List[Mapping[str, Any]]
    if dataset == CORPUS_NAME:
        corpus = build_corpus()
        docs = [*corpus.alerts, *T.build_telemetry(T.corpus_items(corpus))]
    elif dataset == S.NAME:
        skills = S.build_skills()
        docs = [*skills.alerts, *skills.events]
    else:
        raise ValueError(f"unknown dataset {dataset!r}; one of {', '.join(DATASETS)}")
    return alerts_json(sorted(docs, key=lambda d: (str(d["timestamp"]), str(d["id"]))))
