"""The verdict cache never closes a malicious corpus_v1 alert, even when analysts decide every escalation correctly.

The review of the cache found four malicious corpus_v1 alerts that a cache
keyed by fingerprint alone (rule plus hosts, users, IPs, hashes, domains)
closed from earlier benign decisions on the same host (the analyst oracle,
``lg-sotf eval --oracle``, closed the same four):

* ``cv1-0113``: the ransomware campaign's ``PSEXESVC`` service, after the Edge
  update service on ``srv-app-02`` (``cv1-0057``) was decided benign;
* ``cv1-0309``: a malicious ``winsvchost`` service, after the Edge update
  service on ``hr-ws-07`` (``cv1-0079``);
* ``cv1-0440``: a malicious ``msupdsvc`` service, after the purple team's
  ``PSEXESVC`` installs on the same host (``cv1-0069``, ``cv1-0080``,
  ``cv1-0187``);
* ``cv1-0494``: ``ps aux`` run by a web shell as uid 33 on ``web-02``, after
  ``ps`` run by monitoring as root (``cv1-0297``, ``cv1-0328``).

New services (T1543) are a never-close class, so the three service alerts get
no verdict key at all; ``ps`` as uid 33 gets a key of its own.

The replay is an analyst oracle: every alert the cache does not close gets
the correct analyst decision at its time (benign: a false-positive decision
by one of two analysts taking turns; malicious: the threat invalidates the
cache), which is the most the cache can ever learn.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import fakeredis.aioredis
import pytest

from lg_sotf.core import verdict_cache
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.domain.verdict_key import verdict_key
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.ingestion.fingerprint import compute_fingerprint
from lg_sotf.ingestion.normalizers import get_normalizer
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.models.vocabulary import SEVERITY_RANK

pytestmark = pytest.mark.unit

DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "corpus_v1.jsonl.gz"
COLLISIONS = {
    "cv1-0113": ["cv1-0057"],
    "cv1-0309": ["cv1-0079"],
    "cv1-0440": ["cv1-0069", "cv1-0080", "cv1-0187"],
    "cv1-0494": ["cv1-0297", "cv1-0328"],
}
ANALYSTS = ("analyst-a", "analyst-b")


@dataclass(frozen=True)
class Item:
    id: str
    malicious: bool
    severity: str
    occurred_at: datetime
    fingerprint: str
    verdict_key: Optional[str]


@lru_cache(maxsize=1)
def corpus() -> Tuple[Item, ...]:
    """corpus_v1 normalized as the eval runner's Wazuh webhook source does, in time order."""
    normalizer = get_normalizer("wazuh")
    ctx = NormalizeContext(source_id="eval-wazuh", source_type="webhook", config={"format": "wazuh"},
                           now=datetime(2026, 11, 1, tzinfo=UTC))
    items = []
    for entry in load_dataset(DATASET).items:
        alert = normalizer.normalize(dict(entry.alert), ctx)
        fingerprint = compute_fingerprint(alert)
        items.append(Item(entry.id, entry.expected.disposition == "malicious", alert.severity, alert.occurred_at,
                          fingerprint, verdict_key(fingerprint, alert.normalized_document(), alert.raw)))
    return tuple(sorted(items, key=lambda i: (i.occurred_at, i.id)))


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


async def replay(items: Tuple[Item, ...] | List[Item]) -> Dict[str, List[str]]:
    """Analyst-oracle replay through the real cache; the ids it closed, by expected disposition."""
    clock = Clock()
    cache = VerdictCache(fakeredis.aioredis.FakeRedis(), "pfx", clock=clock)
    closed: Dict[str, List[str]] = {"benign": [], "malicious": []}
    for turn, item in enumerate(items):
        clock.now = item.occurred_at
        hit = await cache.closing_decision("t1", item.verdict_key, item.severity, fingerprint=item.fingerprint)
        if hit is not None:
            closed["malicious" if item.malicious else "benign"].append(item.id)
        elif item.malicious:
            await cache.invalidate("t1", item.verdict_key, fingerprint=item.fingerprint)
        else:
            await cache.put_analyst_benign("t1", item.verdict_key, decision="false_positive", alert_id=item.id,
                                           escalation_id=f"esc-{item.id}", decided_by=ANALYSTS[turn % 2],
                                           severity=item.severity)
    return closed


def fingerprint_only_closes(items: Tuple[Item, ...], min_decisions: int) -> List[str]:
    """The malicious alerts the old cache (fingerprint key, no threat marks, no expiry within a replay, as in the
    oracle's wall-clock run) closed with ``min_decisions``."""
    seen: Dict[str, List[str]] = {}
    closed: List[str] = []
    for item in items:
        recent = [s for s in seen.get(item.fingerprint, []) if SEVERITY_RANK[s] >= SEVERITY_RANK[item.severity]]
        if item.severity != "critical" and len(recent) >= min_decisions:
            closed += [item.id] if item.malicious else []
        elif item.malicious:
            seen.pop(item.fingerprint, None)
        else:
            seen.setdefault(item.fingerprint, []).append(item.severity)
    return closed


def by_id(ids: List[str]) -> List[Item]:
    items = {i.id: i for i in corpus()}
    return [items[i] for i in ids]


def test_the_corpus_still_has_the_fingerprint_collisions() -> None:
    """Guards the replay below: keyed by fingerprint, the corpus does close these four malicious alerts."""
    items = corpus()
    assert len(items) == 520
    assert set(COLLISIONS) <= set(fingerprint_only_closes(items, 1))
    for malicious, benign in COLLISIONS.items():
        bad, *good = by_id([malicious, *benign])
        assert all(g.fingerprint == bad.fingerprint and g.occurred_at < bad.occurred_at for g in good)
        assert bad.malicious and not any(g.malicious for g in good)


@pytest.mark.parametrize("malicious", sorted(COLLISIONS))
def test_each_collision_has_no_key_or_its_own(malicious: str) -> None:
    bad, *good = by_id([malicious, *COLLISIONS[malicious]])
    assert bad.verdict_key is None or all(g.verdict_key != bad.verdict_key for g in good)
    if malicious == "cv1-0494":  # process discovery is not a never-close class: ps as uid 33 has its own key
        assert bad.verdict_key is not None and all(g.verdict_key is not None for g in good)
    else:  # a new service (T1543) is named persistence: no key, so the cache never closes it
        assert bad.verdict_key is None


@pytest.mark.parametrize("malicious", sorted(COLLISIONS))
async def test_each_collision_no_longer_closes(malicious: str) -> None:
    """After two analysts decided each benign peer: PSEXESVC, winsvchost and msupdsvc next to benign service
    installs; ps as uid 33 next to ps as root."""
    bad, *good = by_id([malicious, *COLLISIONS[malicious]])
    clock = Clock()
    cache = VerdictCache(fakeredis.aioredis.FakeRedis(), "pfx", clock=clock)
    clock.now = bad.occurred_at
    for g in good:
        for analyst in ANALYSTS:
            await cache.put_analyst_benign("t1", g.verdict_key, decision="false_positive", alert_id=g.id,
                                           escalation_id=f"esc-{g.id}", decided_by=analyst, severity=g.severity)
        trusted = await cache.closing_decision("t1", g.verdict_key, g.severity, fingerprint=g.fingerprint)
        assert (trusted is not None) is (g.verdict_key is not None)
    assert await cache.closing_decision("t1", bad.verdict_key, bad.severity, fingerprint=bad.fingerprint) is None


async def test_analyst_oracle_replay_closes_no_malicious_alert() -> None:
    assert verdict_cache.MIN_ANALYSTS == 2
    closed = await replay(corpus())
    assert closed["malicious"] == []


async def test_the_verdict_key_alone_already_closes_no_malicious_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    """With one analyst enough, the finer key still closes none: two analysts are defence in depth."""
    monkeypatch.setattr(verdict_cache, "MIN_ANALYSTS", 1)
    closed = await replay(corpus())
    # 14 since FIX-2: Wazuh authentication-failure rules are a never-close class, so they get no verdict key.
    assert closed["malicious"] == [] and len(closed["benign"]) >= 14
