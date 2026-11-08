"""Blind audit sampling (PRD-10.2): the size rule, a uniform and reproducible seeded draw, agreement, the estimate."""

from __future__ import annotations

import hashlib
from collections import Counter

import pytest

from lg_sotf.domain.blind_audit import (
    MAX_SAMPLE_PER_RUN,
    MAX_SEED,
    LabelCounts,
    agreement,
    ai_class,
    draw,
    estimate,
    new_seed,
    sample_key,
    sample_size,
    total,
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
    """3 malicious, 57 benign and 5 unsure labels over a frame of 3,000 auto-closed alerts."""
    counts = LabelCounts(sampled=70, malicious=3, benign=57, unsure=5, agreed=57)
    e = estimate(3_000, counts)
    assert e.status == "ok" and (e.labelled, e.pending, e.sampled) == (65, 5, 70)
    fn = e.false_negative_rate
    assert fn.n == 60 and fn.rate == pytest.approx(0.05)
    assert fn.ci_low == pytest.approx(0.017150, abs=1e-6) and fn.ci_high == pytest.approx(0.137005, abs=1e-6)
    assert e.estimated_missed == pytest.approx(150.0)
    assert e.estimated_missed_low == pytest.approx(51.45, abs=0.01)
    assert e.estimated_missed_high == pytest.approx(411.02, abs=0.01)
    assert e.agreement_rate.rate == pytest.approx(0.95)
    assert e.summary == "5.0% (3 of 60; 95% CI 1.7% to 13.7%)"


def test_estimate_small_sample_wording_and_empty() -> None:
    small = estimate(400, LabelCounts(sampled=8, malicious=0, benign=4, unsure=1))
    assert small.status == "insufficient_data"
    assert small.summary == "Not enough data (n=4; at least 30 needed)"
    assert small.false_negative_rate.rate == 0.0 and small.false_negative_rate.ci_high == pytest.approx(0.489891)
    empty = estimate(0, LabelCounts())
    assert empty.false_negative_rate.rate is None and empty.estimated_missed is None
    assert empty.summary == "Not enough data (n=0; at least 30 needed)"


def test_total_sums_runs() -> None:
    a = LabelCounts(sampled=5, malicious=1, benign=3, unsure=1, agreed=3)
    b = LabelCounts(sampled=7, malicious=0, benign=2, unsure=0, agreed=2)
    assert total([a, b]) == LabelCounts(sampled=12, malicious=1, benign=5, unsure=1, agreed=5)
