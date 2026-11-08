"""Rates with their sample size and a 95% Wilson score interval (AI-E1.7).

Every rate a report shows (the evaluation reports, the scorecard, the
``/reports/*`` value, accuracy and detection pages, and the PoV report) is a
proportion ``k / n``. On its own a point estimate over a few dozen alerts
says little, so each one travels as a :class:`RateInterval`: the rate, ``n``
and the 95% Wilson interval, and is written the same way everywhere
(:func:`format_rate`, :func:`not_enough_data`).

The Wilson score interval stays inside ``[0, 1]`` and keeps a sensible width
at ``k = 0`` or ``k = n``, where the normal approximation collapses to zero.
Scores that are not proportions (F1, Cohen's kappa, means) get no interval
here.
"""

from __future__ import annotations

import math
from typing import Optional, Tuple

from pydantic import BaseModel, ConfigDict

Z_95 = 1.959963984540054
NOT_ENOUGH_DATA = "Not enough data"


def ratio(numerator: float, denominator: float) -> Optional[float]:
    """``numerator / denominator``; ``None`` (never 0) when the denominator is zero."""
    return None if denominator == 0 else numerator / denominator


def wilson_interval(successes: int, n: int, z: float = Z_95) -> Optional[Tuple[float, float]]:
    """The Wilson score interval of ``successes`` out of ``n`` (``None`` when ``n`` is 0)."""
    if n <= 0:
        return None
    if not 0 <= successes <= n:
        raise ValueError("successes must be between 0 and n")
    p = successes / n
    z2 = z * z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = (z / (1 + z2 / n)) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    # At k = 0 and k = n the bound is exactly 0 or 1; floating point would leave 1e-17 of it.
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == n else min(1.0, centre + half)
    return low, high


def _binomial_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), summed in log space so large ``n`` does not underflow."""
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 1.0 if k >= n else 0.0
    log_p, log_q = math.log(p), math.log1p(-p)
    total = 0.0
    for i in range(k + 1):
        log_term = math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * log_p + (n - i) * log_q
        total += math.exp(log_term)
    return min(1.0, total)


def upper_bound(successes: int, n: int, confidence: float = 0.95) -> Optional[float]:
    """The exact one-sided (Clopper-Pearson) upper confidence bound of ``successes`` out of ``n``.

    The largest rate still consistent with seeing at most ``successes``: at 0 of
    300 it is about 1.0% (the "rule of three", 3/n). ``None`` when ``n`` is 0.
    """
    if n <= 0:
        return None
    if not 0 <= successes <= n:
        raise ValueError("successes must be between 0 and n")
    if successes == n:
        return 1.0
    alpha = 1.0 - confidence
    if successes == 0:
        return 1.0 - float(alpha ** (1.0 / n))
    low, high = successes / n, 1.0
    for _ in range(80):  # bisection: the CDF falls as p grows
        mid = (low + high) / 2
        if _binomial_cdf(successes, n, mid) > alpha:
            low = mid
        else:
            high = mid
    return high


class RateInterval(BaseModel):
    """A rate with its sample size and 95% Wilson interval; ``rate`` and the bounds are ``None`` when ``n`` is 0."""

    model_config = ConfigDict(frozen=True)

    rate: Optional[float]
    n: int
    ci_low: Optional[float]
    ci_high: Optional[float]

    @property
    def successes(self) -> int:
        return 0 if self.rate is None else round(self.rate * self.n)

    @property
    def bounds(self) -> Optional[Tuple[float, float]]:
        return None if self.ci_low is None or self.ci_high is None else (self.ci_low, self.ci_high)


def rate_interval(successes: int, n: int, digits: int = 6) -> RateInterval:
    """``successes`` out of ``n`` as a :class:`RateInterval` (bounds rounded to ``digits``)."""
    interval = wilson_interval(successes, n)
    return RateInterval(
        rate=ratio(successes, n),
        n=n,
        ci_low=None if interval is None else round(interval[0], digits),
        ci_high=None if interval is None else round(interval[1], digits),
    )


def not_enough_data(n: int, needed: Optional[int] = None) -> str:
    """The one wording for a sample too small to read: ``Not enough data (n=4; at least 10 needed)``."""
    return f"{NOT_ENOUGH_DATA} (n={n}{f'; at least {needed} needed' if needed else ''})"


def _pct(value: float) -> str:
    return f"{100 * value:.1f}%"


def format_interval(r: RateInterval) -> str:
    """``95% CI 70.2% to 98.8%``, or an empty string without data."""
    if r.ci_low is None or r.ci_high is None:
        return ""
    return f"95% CI {_pct(r.ci_low)} to {_pct(r.ci_high)}"


def format_rate(r: RateInterval) -> str:
    """``93.3% (14 of 15; 95% CI 70.2% to 98.8%)``; ``Not enough data (n=0)`` without a sample."""
    if r.rate is None:
        return not_enough_data(r.n)
    return f"{_pct(r.rate)} ({r.successes} of {r.n}; {format_interval(r)})"
