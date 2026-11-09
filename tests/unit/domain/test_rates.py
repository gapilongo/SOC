"""Rates with n and a 95% Wilson interval: the helper every report shares (AI-E1.7)."""

from __future__ import annotations

import pytest

from lg_sotf.domain.rates import (
    RateInterval,
    format_interval,
    format_rate,
    not_enough_data,
    rate_interval,
    ratio,
    upper_bound,
    wilson_interval,
)

pytestmark = pytest.mark.unit


def test_ratio_is_undefined_for_an_empty_denominator() -> None:
    assert ratio(0, 0) is None and ratio(3, 4) == 0.75


def test_wilson_interval_edges() -> None:
    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(0, 10)  # type: ignore[misc]
    assert lo == 0.0 and 0.25 < hi < 0.35
    lo, hi = wilson_interval(10, 10)  # type: ignore[misc]
    assert 0.65 < lo < 0.75 and hi == 1.0
    lo, hi = wilson_interval(50, 100)  # type: ignore[misc]
    assert lo == pytest.approx(0.4038, abs=1e-3) and hi == pytest.approx(0.5962, abs=1e-3)
    with pytest.raises(ValueError):
        wilson_interval(3, 2)


def test_rate_interval_carries_rate_n_and_rounded_bounds() -> None:
    r = rate_interval(14, 15)
    assert r.model_dump() == {"rate": 14 / 15, "n": 15, "ci_low": 0.701835, "ci_high": 0.988133}
    assert r.successes == 14 and r.bounds == (0.701835, 0.988133)
    empty = rate_interval(0, 0)
    assert empty.model_dump() == {"rate": None, "n": 0, "ci_low": None, "ci_high": None}
    assert empty.successes == 0 and empty.bounds is None


def test_one_wording_for_rates_and_small_samples() -> None:
    assert format_rate(rate_interval(14, 15)) == "93.3% (14 of 15; 95% CI 70.2% to 98.8%)"
    assert format_interval(rate_interval(14, 15)) == "95% CI 70.2% to 98.8%"
    assert format_rate(rate_interval(0, 0)) == "Not enough data (n=0)"
    assert format_interval(rate_interval(0, 0)) == ""
    assert not_enough_data(4, 10) == "Not enough data (n=4; at least 10 needed)"
    assert not_enough_data(0) == "Not enough data (n=0)"


def test_interval_round_trips_through_json() -> None:
    r = rate_interval(3, 7)
    assert RateInterval.model_validate_json(r.model_dump_json()) == r


def test_the_one_sided_upper_bound_is_exact() -> None:
    """Clopper-Pearson: at 0 of n it is 1 - 0.05^(1/n) (about 3/n); known values elsewhere."""
    assert upper_bound(0, 0) is None and upper_bound(5, 5) == 1.0
    assert upper_bound(0, 208) == pytest.approx(1 - 0.05 ** (1 / 208))
    assert upper_bound(0, 300) == pytest.approx(0.00994, abs=1e-5)
    assert upper_bound(3, 10) == pytest.approx(0.6066, abs=1e-4)
    assert upper_bound(1, 208) == pytest.approx(0.0226, abs=1e-4)
    assert upper_bound(10, 40_000) < 0.0005
    with pytest.raises(ValueError):
        upper_bound(3, 2)
