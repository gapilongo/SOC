"""Blind audit sampling (PRD-10.2): the size rule, a uniform and reproducible seeded draw, agreement, the estimate."""

from __future__ import annotations

import hashlib
import random
from collections import Counter
from typing import Any, Dict, List, Tuple

import pytest

from lg_sotf.domain.blind_audit import (
    HIDDEN,
    MAX_SAMPLE_PER_RUN,
    MAX_SEED,
    LabelCounts,
    Stratum,
    agreement,
    ai_class,
    draw,
    estimate,
    hidden_alert_view,
    hidden_event_data,
    hidden_evidence_pack,
    new_seed,
    run_rate,
    sample_key,
    sample_size,
    total,
    wilson_bounds,
)

pytestmark = pytest.mark.unit

FRAME = [f"alert-{i:03d}" for i in range(40)]


def test_sample_size_rate_minimum_cap_and_fixed() -> None:
    assert sample_size(0, rate=0.02, min_per_week=5) == 0
    assert sample_size(1_000, rate=0.02, min_per_week=5) == 20
    assert sample_size(1_001, rate=0.02, min_per_week=5) == 21  # rounded up: never fewer than the rate
    assert sample_size(100, rate=0.02, min_per_week=5) == 5  # the weekly minimum
    assert sample_size(100, rate=0.02, min_per_week=5, days=14) == 10  # scaled to the window
    assert sample_size(100, rate=0.02, min_per_week=5, days=1) == 2
    assert sample_size(3, rate=0.02, min_per_week=5) == 3  # all of a small frame
    assert sample_size(10**7, rate=0.5) == MAX_SAMPLE_PER_RUN
    assert sample_size(500, rate=0.02, min_per_week=5, fixed=200) == 200
    assert sample_size(50, rate=None, fixed=200) == 50


def test_sample_key_is_md5_of_seed_and_id() -> None:
    assert sample_key(42, "a-1") == hashlib.md5(b"42:a-1", usedforsecurity=False).hexdigest()
    assert 0 <= new_seed() <= MAX_SEED


def test_draw_is_reproducible_and_seed_dependent() -> None:
    first = draw(FRAME, 1234, 8)
    assert first == draw(list(reversed(FRAME)), 1234, 8)  # the frame's order does not matter
    assert len(first) == len(set(first)) == 8 and set(first) <= set(FRAME)
    assert draw(FRAME, 1234, 3) == first[:3]  # a smaller sample is a prefix of the larger one
    assert draw(FRAME, 1235, 8) != first
    assert draw(FRAME, 1, 0) == [] and len(draw(FRAME, 1, 100)) == len(FRAME)


def test_draw_is_uniform() -> None:
    """Over many seeds every alert is drawn about k/N of the time, and the first pick is uniform too.

    Chi-square against the uniform expectation with N-1 = 39 degrees of freedom: the 99.9th percentile
    is 72.1, so a correct draw fails this about once in a thousand seeds sets; the seeds are fixed,
    so the test is deterministic.
    """
    runs, k = 4_000, 10
    picks: Counter[str] = Counter()
    firsts: Counter[str] = Counter()
    for seed in range(runs):
        sample = draw(FRAME, seed, k)
        picks.update(sample)
        firsts[sample[0]] += 1
    expected = runs * k / len(FRAME)
    chi2 = sum((picks[a] - expected) ** 2 / expected for a in FRAME)
    assert chi2 < 72.1, chi2
    expected_first = runs / len(FRAME)
    chi2_first = sum((firsts[a] - expected_first) ** 2 / expected_first for a in FRAME)
    assert chi2_first < 72.1, chi2_first
    # Inclusion is independent of the alert's id (no bias towards low or high ids).
    low = sum(picks[a] for a in FRAME[:20])
    assert abs(low / (runs * k) - 0.5) < 0.02


def test_ai_class_and_agreement() -> None:
    assert ai_class("benign") == "benign" and ai_class(None) == "inconclusive"
    assert ai_class("inconclusive") == "inconclusive" and ai_class("malicious") == "malicious"
    assert agreement("benign", "benign") is True
    assert agreement("malicious", "benign") is False
    assert agreement("benign", "inconclusive") is False  # an inconclusive AI verdict never agrees
    assert agreement("unsure", "benign") is None


def test_estimate_on_a_fixture() -> None:
    """One run: 3 malicious, 57 benign, 5 unsure and 5 pending over a frame of 3,000 auto-closed alerts."""
    counts = LabelCounts(sampled=70, malicious=3, benign=57, unsure=5, agreed=57)
    e = estimate([Stratum(frame_size=3_000, counts=counts)])
    assert (e.status, e.complete, e.method) == ("incomplete", False, "stratified")
    assert (e.labelled, e.pending, e.sampled, e.effective_n) == (65, 5, 70, 60.0)
    fn = e.false_negative_rate
    assert fn.n == 60 and fn.rate == pytest.approx(0.05)
    # With one run the stratified interval is the run's own Wilson interval.
    assert fn.ci_low == pytest.approx(0.017150, abs=1e-6) and fn.ci_high == pytest.approx(0.137005, abs=1e-6)
    assert run_rate(counts) == fn
    assert e.estimated_missed == pytest.approx(150.0)
    assert e.estimated_missed_low == pytest.approx(51.45, abs=0.01)
    assert e.estimated_missed_high == pytest.approx(411.02, abs=0.01)
    assert e.agreement_rate.rate == pytest.approx(0.95)
    assert e.summary == "5.0% (stratified over 1 run(s); n=60; 95% CI 1.7% to 13.7%); incomplete"
    # The worst case counts the 5 unsure and the 5 pending samples as malicious: 13 of 70.
    assert e.worst_case_rate == pytest.approx(13 / 70, abs=1e-6)
    assert e.worst_case_missed == pytest.approx(round(13 / 70 * 3_000, 2))
    assert e.worst_case_rate_high is not None and e.worst_case_rate_high > 13 / 70
    done = estimate([Stratum(frame_size=3_000, counts=LabelCounts(sampled=60, malicious=3, benign=57))])
    assert (done.status, done.complete) == ("ok", True)


def test_runs_are_strata_weighted_by_their_frames() -> None:
    """A proof-of-value run (all 50 of 100 alerts drawn, 5 malicious) next to a weekly run (50 of 10,000, none)."""
    small = Stratum(frame_size=100, counts=LabelCounts(sampled=50, malicious=5, benign=45))
    large = Stratum(frame_size=10_000, counts=LabelCounts(sampled=50, malicious=0, benign=50))
    e = estimate([small, large])
    # Pooled labels would say 5 of 100 = 5%; the frames say about 10 missed among 10,100.
    assert e.false_negative_rate.rate == pytest.approx(10 / 10_100, abs=1e-6)
    assert e.estimated_missed == pytest.approx(10.0)
    assert e.effective_n == pytest.approx(10_100**2 / (100**2 / 50 + 10_000**2 / 50), abs=0.01)
    low, high = wilson_bounds(10 / 10_100, 10_100**2 / (100**2 / 50 + 10_000**2 / 50)) or (0.0, 0.0)
    assert e.false_negative_rate.ci_low == pytest.approx(low, abs=1e-6)
    assert e.false_negative_rate.ci_high == pytest.approx(high, abs=1e-6)
    assert e.false_negative_rate.n == 100 and e.frame_size == e.estimated_frame == 10_100
    # A run without a malicious-or-benign label yet adds no estimate, and the estimate is incomplete.
    waiting = Stratum(frame_size=5_000, counts=LabelCounts(sampled=40))
    partial = estimate([small, large, waiting])
    assert partial.estimated_frame == 10_100 and partial.frame_size == 15_100
    assert partial.false_negative_rate.rate == e.false_negative_rate.rate and partial.complete is False
    assert partial.worst_case_missed is not None and partial.worst_case_missed >= 5_000


def test_estimate_small_sample_wording_and_empty() -> None:
    small = estimate([Stratum(frame_size=400, counts=LabelCounts(sampled=8, malicious=0, benign=4, unsure=1))])
    assert small.status == "insufficient_data"
    assert small.summary == "Not enough data (n=4; at least 30 needed)"
    assert small.false_negative_rate.rate == 0.0 and small.false_negative_rate.ci_high == pytest.approx(0.489891)
    empty = estimate([])
    assert empty.false_negative_rate.rate is None and empty.estimated_missed is None
    assert empty.summary == "Not enough data (n=0; at least 30 needed)"


def _trial(strata: List[Tuple[int, float, Dict[str, Any]]], rng: random.Random) -> Tuple[float, float, float, int]:
    drawn, truth = [], 0
    for frame, share, rule in strata:
        bad = set(rng.sample(range(frame), round(frame * share)))
        k = sample_size(frame, **rule)
        m = sum(1 for i in rng.sample(range(frame), k) if i in bad)
        drawn.append(Stratum(frame_size=frame, counts=LabelCounts(sampled=k, malicious=m, benign=k - m)))
        truth += len(bad)
    e = estimate(drawn)
    assert e.estimated_missed is not None and e.estimated_missed_low is not None and e.estimated_missed_high is not None
    return e.estimated_missed, e.estimated_missed_low, e.estimated_missed_high, truth


WEEKLY: Dict[str, Any] = {"rate": 0.02, "min_per_week": 5, "days": 7}
POOL_BIAS_SCENARIOS = {
    # The reviewer's pool_bias.py: a quiet week with a campaign in a small frame (pooled mean was biased) ...
    "A": ([(5_000, 0.002, WEEKLY)] * 3 + [(50, 0.10, WEEKLY)], 8.0),
    # ... and a proof-of-value size=200 run on a clean small window next to a weekly 2% run.
    "B": ([(200, 0.0, {"rate": None, "fixed": 200}), (10_000, 0.01, WEEKLY)], 15.0),
}


@pytest.mark.parametrize("name", sorted(POOL_BIAS_SCENARIOS))
def test_the_stratified_estimate_is_unbiased_with_about_95_percent_coverage(name: str) -> None:
    """A fast, seeded Monte Carlo of the review's scenarios: the mean estimate is the truth (within about
    3.5 standard errors of the mean) and the 95% interval covers the truth about 95% of the time."""
    strata, tolerance = POOL_BIAS_SCENARIOS[name]
    rng = random.Random(1)
    trials = 300
    results = [_trial(strata, rng) for _ in range(trials)]
    truth = results[0][3]
    mean = sum(r[0] for r in results) / trials
    coverage = sum(1 for r in results if r[1] <= truth <= r[2]) / trials
    assert abs(mean - truth) <= tolerance, (name, mean, truth)
    assert 0.92 <= coverage <= 0.995, (name, coverage)


def test_hidden_views_withhold_the_ai_side() -> None:
    view = hidden_alert_view(
        {"id": "a", "title": "T", "disposition": "benign", "confidence": 90.0, "threat_score": 5.0, "priority": 2,
         "summary": {"verdict": "benign"}, "findings": [{"x": 1}]}
    )
    assert view == {"id": "a", "title": "T", "disposition": None, "confidence": None, "threat_score": None,
                    "priority": None, "summary": HIDDEN, "findings": [], "hidden_for_blind_audit": True}
    assert hidden_event_data("note", {"text": "n"}) == {"text": "n"}
    assert hidden_event_data("node.completed", {"verdict": "benign"}) == HIDDEN
    pack = hidden_evidence_pack({
        "alert": {"disposition": "benign", "summary": {}}, "timeline": [{"event_type": "ingested", "data": {"a": 1}}],
        "agents": {"triage": {}}, "investigation": {}, "human_oversight": {},
        "enrichment": {"observations": [1], "indicator_sightings": [2]}, "correlation": {"digest": {}},
    })
    assert pack["alert"]["disposition"] is None and pack["timeline"][0]["data"] == {"a": 1}
    assert pack["agents"] == pack["investigation"] == pack["correlation"] == HIDDEN
    assert pack["enrichment"] == {**HIDDEN, "indicator_sightings": [2]} and pack["hidden_for_blind_audit"] is True


def test_total_sums_runs() -> None:
    a = LabelCounts(sampled=5, malicious=1, benign=3, unsure=1, agreed=3)
    b = LabelCounts(sampled=7, malicious=0, benign=2, unsure=0, agreed=2)
    assert total([a, b]) == LabelCounts(sampled=12, malicious=1, benign=5, unsure=1, agreed=5)
