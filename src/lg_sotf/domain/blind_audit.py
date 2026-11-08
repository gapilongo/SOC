"""Blind audit of auto-closed alerts (PRD-10.2): sample size, the seeded uniform draw, agreement and the estimate.

Auto-closed alerts are never looked at again, so a threat the AI closed as
benign stays invisible: the accuracy report only sees the alerts the AI sent
to a person. The blind audit puts a uniform random sample of the auto-closed
alerts back in front of an analyst, without the AI verdict, and estimates the
production false-negative rate from their labels.

The sampling frame of a run is every alert closed in the run's window with no
person involved (no analyst decision, no person approving or rejecting one of
its actions) and an AI disposition other than ``malicious``: the alerts the
AI let go. Built-in sample alerts and alerts sampled before are left out.

The draw: every alert of the frame gets the key ``md5("<seed>:<alert id>")``
and the run takes the ``k`` alerts with the smallest keys (ties by id). The
keys are independent of the alerts' content, so every ``k``-subset of the
frame is equally likely; the draw is reproducible from the seed and the frame
(:func:`sample_key`, :func:`draw`, and the same expression in SQL).

``k`` is ``ceil(rate * frame)``, at least ``ceil(min_per_week * days / 7)``,
at most the frame and :data:`MAX_SAMPLE_PER_RUN`; an explicit size replaces
the rate and the minimum (the proof-of-value "label 200 random alerts" run).

The estimate (:func:`estimate`): the false-negative rate among auto-closed
alerts is ``malicious / (malicious + benign)`` over the labelled samples
(``unsure`` labels are counted but left out), with its 95% Wilson interval
(:mod:`lg_sotf.domain.rates`), and scaled to the frame: the estimated number
of missed threats among the alerts the runs drew from.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from typing import Iterable, List, Literal, Optional, Sequence

from pydantic import BaseModel, ConfigDict

from lg_sotf.domain.rates import RateInterval, format_rate, not_enough_data, rate_interval
from lg_sotf.models.vocabulary import Disposition

MAX_SAMPLE_PER_RUN = 2_000
# Seeds stay exact in JSON (a JavaScript number): at most 2^53 - 1.
MAX_SEED = 2**53 - 1
# Below this many malicious-or-benign labels the estimate is shown as "Not enough data".
MIN_ESTIMATE_SAMPLES = 30


def new_seed() -> int:
    """A fresh random seed (a non-negative ``BIGINT``)."""
    return secrets.randbelow(MAX_SEED)


def sample_key(seed: int, alert_id: str) -> str:
    """The draw key of one alert: ``md5("<seed>:<alert id>")`` in hex (SQL: ``md5(seed::text || ':' || id)``)."""
    return hashlib.md5(f"{seed}:{alert_id}".encode(), usedforsecurity=False).hexdigest()


def draw(alert_ids: Iterable[str], seed: int, k: int) -> List[str]:
    """The ``k`` alerts of the frame with the smallest keys (ties by id): the run's sample, in draw order."""
    return sorted(alert_ids, key=lambda a: (sample_key(seed, a), a))[: max(0, k)]


def sample_size(
    frame: int,
    *,
    rate: Optional[float],
    min_per_week: int = 0,
    days: float = 7.0,
    fixed: Optional[int] = None,
) -> int:
    """How many alerts a run draws from a frame of ``frame`` alerts (see the module docstring)."""
    if frame <= 0:
        return 0
    if fixed is not None:
        wanted = fixed
    else:
        minimum = math.ceil(min_per_week * days / 7) if min_per_week > 0 else 0
        wanted = max(math.ceil((rate or 0.0) * frame), minimum)
    return max(0, min(frame, MAX_SAMPLE_PER_RUN, wanted))


def ai_class(disposition: Optional[str]) -> Disposition:
    """The AI's class of an auto-closed alert: its disposition, ``inconclusive`` when it has none."""
    if disposition in ("malicious", "benign"):
        return disposition  # type: ignore[return-value]
    return "inconclusive"


def agreement(label: str, ai: str) -> Optional[bool]:
    """Whether the analyst's label agrees with the AI class; ``None`` for ``unsure`` (no opinion to compare).

    An ``inconclusive`` AI class never agrees, as in the accuracy report.
    """
    if label == "unsure":
        return None
    return label == ai


class LabelCounts(BaseModel):
    """Labels over a set of samples (``pending``: not labelled yet)."""

    model_config = ConfigDict(frozen=True)

    sampled: int = 0
    malicious: int = 0
    benign: int = 0
    unsure: int = 0
    agreed: int = 0

    @property
    def labelled(self) -> int:
        return self.malicious + self.benign + self.unsure

    @property
    def pending(self) -> int:
        return max(0, self.sampled - self.labelled)

    @property
    def decisive(self) -> int:
        return self.malicious + self.benign


class BlindAuditEstimate(BaseModel):
    """The production false-negative estimate over a set of runs."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "insufficient_data"]
    summary: str
    frame_size: int
    sampled: int
    labelled: int
    pending: int
    malicious: int
    benign: int
    unsure: int
    min_samples: int
    false_negative_rate: RateInterval
    agreement_rate: RateInterval
    estimated_missed: Optional[float]
    estimated_missed_low: Optional[float]
    estimated_missed_high: Optional[float]


def _scaled(value: Optional[float], frame: int) -> Optional[float]:
    return None if value is None else round(value * frame, 2)


def estimate(frame_size: int, counts: LabelCounts, *, min_samples: int = MIN_ESTIMATE_SAMPLES) -> BlindAuditEstimate:
    """False-negative rate (malicious among malicious-or-benign labels), its interval, and the frame scaling."""
    fn = rate_interval(counts.malicious, counts.decisive)
    agree = rate_interval(counts.agreed, counts.decisive)
    enough = counts.decisive >= min_samples
    return BlindAuditEstimate(
        status="ok" if enough else "insufficient_data",
        summary=format_rate(fn) if enough else not_enough_data(counts.decisive, min_samples),
        frame_size=frame_size,
        sampled=counts.sampled,
        labelled=counts.labelled,
        pending=counts.pending,
        malicious=counts.malicious,
        benign=counts.benign,
        unsure=counts.unsure,
        min_samples=min_samples,
        false_negative_rate=fn,
        agreement_rate=agree,
        estimated_missed=_scaled(fn.rate, frame_size),
        estimated_missed_low=_scaled(fn.ci_low, frame_size),
        estimated_missed_high=_scaled(fn.ci_high, frame_size),
    )


def total(counts: Sequence[LabelCounts]) -> LabelCounts:
    """The sum of several runs' counts."""
    return LabelCounts(
        sampled=sum(c.sampled for c in counts),
        malicious=sum(c.malicious for c in counts),
        benign=sum(c.benign for c in counts),
        unsure=sum(c.unsure for c in counts),
        agreed=sum(c.agreed for c in counts),
    )
