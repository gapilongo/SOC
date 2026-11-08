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

The estimate (:func:`estimate`) is stratified, each run a stratum weighted
by its frame: runs draw different shares of their frames, so pooled labels
would be biased. Its 95% interval is Wilson's on Kish's effective sample
size; a worst case counts unsure and pending samples as malicious.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict

from lg_sotf.domain.rates import Z_95, RateInterval, format_interval, not_enough_data, rate_interval
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


class Stratum(BaseModel):
    """One run: its frame (``N_h``) and its label counts."""

    model_config = ConfigDict(frozen=True)

    frame_size: int
    counts: LabelCounts


class BlindAuditEstimate(BaseModel):
    """The production false-negative estimate over a set of runs, each run a stratum (see :func:`estimate`)."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "insufficient_data", "incomplete"]
    complete: bool
    summary: str
    method: Literal["stratified"] = "stratified"
    frame_size: int
    estimated_frame: int
    sampled: int
    labelled: int
    pending: int
    malicious: int
    benign: int
    unsure: int
    min_samples: int
    effective_n: Optional[float]
    false_negative_rate: RateInterval
    agreement_rate: RateInterval
    estimated_missed: Optional[float]
    estimated_missed_low: Optional[float]
    estimated_missed_high: Optional[float]
    worst_case_rate: Optional[float]
    worst_case_rate_high: Optional[float]
    worst_case_missed: Optional[float]
    worst_case_missed_high: Optional[float]


def wilson_bounds(p: float, n_eff: float, z: float = Z_95) -> Optional[Tuple[float, float]]:
    """The Wilson score interval of a proportion ``p`` observed over an effective sample of ``n_eff``."""
    if n_eff <= 0:
        return None
    z2 = z * z
    centre = (p + z2 / (2 * n_eff)) / (1 + z2 / n_eff)
    half = (z / (1 + z2 / n_eff)) * math.sqrt(max(0.0, p * (1 - p)) / n_eff + z2 / (4 * n_eff * n_eff))
    low = 0.0 if p <= 0 else max(0.0, centre - half)
    high = 1.0 if p >= 1 else min(1.0, centre + half)
    return low, high


def _stratified(strata: Sequence[Tuple[int, int, int]]) -> Optional[Tuple[float, float, float]]:
    """``(p, variance, Kish effective n)`` over ``(N_h, n_h, k_h)`` strata with ``n_h > 0``; ``None`` without one.

    ``p = sum(N_h p_h) / N``; variance ``sum((N_h/N)^2 p_h (1 - p_h) / n_h * (1 - n_h/N_h))``; Kish's
    effective sample size for the weights ``w_h = N_h / n_h``: ``N^2 / sum(N_h^2 / n_h)``.
    """
    kept = [(big, n, k) for big, n, k in strata if n > 0 and big > 0]
    total_frame = sum(big for big, _, _ in kept)
    if not kept or total_frame <= 0:
        return None
    p = sum(big * k / n for big, n, k in kept) / total_frame
    variance = sum(
        (big / total_frame) ** 2 * (k / n) * (1 - k / n) / n * max(0.0, 1 - n / big) for big, n, k in kept
    )
    n_eff = total_frame**2 / sum(big * big / n for big, n, _ in kept)
    return p, variance, n_eff


def _round(value: Optional[float], digits: int = 6) -> Optional[float]:
    return None if value is None else round(value, digits)


def estimate(strata: Sequence[Stratum], *, min_samples: int = MIN_ESTIMATE_SAMPLES) -> BlindAuditEstimate:
    """The stratified false-negative estimate: each run is a stratum weighted by its frame.

    Runs draw different shares of their frames (the weekly minimum, a proof-of-value size), so pooling
    their labels would weigh small frames too much. Per run ``h`` with frame ``N_h`` and ``n_h``
    malicious-or-benign labels, ``k_h`` of them malicious: ``p = sum(N_h k_h/n_h) / sum(N_h)`` over the
    runs with a label, ``missed = sum(N_h k_h/n_h)``. The 95% interval is Wilson's on Kish's effective
    sample size (exact for one run, and still above zero when no label was malicious). ``unsure`` and
    pending samples are left out of the rate; the worst case counts them as malicious. The estimate is
    ``incomplete`` until every sample of every run is labelled.
    """
    counts = total([s.counts for s in strata])
    rated = [(s.frame_size, s.counts.decisive, s.counts.malicious) for s in strata]
    core = _stratified(rated)
    estimated_frame = sum(big for big, n, _ in rated if n > 0 and big > 0)
    if core is None:
        p: Optional[float] = None
        bounds: Optional[Tuple[float, float]] = None
        n_eff: Optional[float] = None
    else:
        p, _, n_eff = core
        bounds = wilson_bounds(p, n_eff)
    fn = RateInterval(
        rate=_round(p),
        n=counts.decisive,
        ci_low=_round(bounds[0]) if bounds else None,
        ci_high=_round(bounds[1]) if bounds else None,
    )
    worst = _stratified([(s.frame_size, s.counts.sampled, s.counts.sampled - s.counts.benign) for s in strata])
    worst_high = wilson_bounds(worst[0], worst[2])[1] if worst else None  # type: ignore[index]
    worst_frame = sum(s.frame_size for s in strata if s.counts.sampled > 0)
    complete = counts.pending == 0 and all(s.counts.decisive > 0 or s.frame_size == 0 for s in strata)
    enough = counts.decisive >= min_samples
    status: Literal["ok", "insufficient_data", "incomplete"] = (
        "insufficient_data" if not enough else "ok" if complete else "incomplete"
    )
    summary = not_enough_data(counts.decisive, min_samples) if not enough else (
        f"{100 * (p or 0):.1f}% (stratified over {len([r for r in rated if r[1] > 0])} run(s); n={counts.decisive}; "
        f"{format_interval(fn)})" + ("" if complete else "; incomplete")
    )
    return BlindAuditEstimate(
        status=status,
        complete=complete,
        summary=summary,
        frame_size=sum(s.frame_size for s in strata),
        estimated_frame=estimated_frame,
        sampled=counts.sampled,
        labelled=counts.labelled,
        pending=counts.pending,
        malicious=counts.malicious,
        benign=counts.benign,
        unsure=counts.unsure,
        min_samples=min_samples,
        effective_n=_round(n_eff, 2),
        false_negative_rate=fn,
        agreement_rate=rate_interval(counts.agreed, counts.decisive),
        estimated_missed=_scaled(p, estimated_frame),
        estimated_missed_low=_scaled(bounds[0] if bounds else None, estimated_frame),
        estimated_missed_high=_scaled(bounds[1] if bounds else None, estimated_frame),
        worst_case_rate=_round(worst[0]) if worst else None,
        worst_case_rate_high=_round(worst_high),
        worst_case_missed=_scaled(worst[0] if worst else None, worst_frame),
        worst_case_missed_high=_scaled(worst_high, worst_frame),
    )


def _scaled(value: Optional[float], frame: int) -> Optional[float]:
    return None if value is None else round(value * frame, 2)


def run_rate(counts: LabelCounts) -> RateInterval:
    """One run's own rate: malicious over malicious-or-benign labels, with its Wilson interval."""
    return rate_interval(counts.malicious, counts.decisive)


# ------------------------------------------------------------------ redaction

#: What replaces the AI's side of an alert that waits for its blind-audit label.
HIDDEN_KEY = "hidden_for_blind_audit"
HIDDEN: Dict[str, Any] = {HIDDEN_KEY: True}
#: Alert columns that carry the AI's side (``None`` while hidden; the summary becomes :data:`HIDDEN`).
HIDDEN_ALERT_FIELDS = ("disposition", "confidence", "threat_score", "priority")
#: Timeline events whose data is the source's or a person's, never the AI's: kept while hidden.
VISIBLE_EVENT_TYPES = frozenset({"ingested", "note"})


def hidden_alert_view(view: Mapping[str, Any]) -> Dict[str, Any]:
    """An alert (dict) with its AI side replaced by the marker."""
    out = dict(view)
    for key in HIDDEN_ALERT_FIELDS:
        if key in out:
            out[key] = None
    out["summary"] = dict(HIDDEN)
    if "findings" in out:
        out["findings"] = []
    out[HIDDEN_KEY] = True
    return out


def hidden_event_data(event_type: str, data: Any) -> Any:
    """A timeline event's data while the alert is hidden: kept for ingestion and notes, else the marker."""
    return data if event_type in VISIBLE_EVENT_TYPES else dict(HIDDEN)


def hidden_evidence_pack(pack: Mapping[str, Any]) -> Dict[str, Any]:
    """An evidence pack (before sealing) with every section that carries the AI's side replaced."""
    out = dict(pack)
    out["alert"] = hidden_alert_view(_mapping(pack.get("alert")))
    out["timeline"] = [
        {**dict(e), "data": hidden_event_data(str(e.get("event_type")), e.get("data"))}
        for e in pack.get("timeline") or []
        if isinstance(e, Mapping)
    ]
    for key in ("agents", "investigation", "human_oversight"):
        out[key] = dict(HIDDEN)
    enrichment = _mapping(pack.get("enrichment"))
    out["enrichment"] = {**dict(HIDDEN), "indicator_sightings": enrichment.get("indicator_sightings") or []}
    out["correlation"] = dict(HIDDEN)
    out[HIDDEN_KEY] = True
    return out


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def total(counts: Sequence[LabelCounts]) -> LabelCounts:
    """The sum of several runs' counts."""
    return LabelCounts(
        sampled=sum(c.sampled for c in counts),
        malicious=sum(c.malicious for c in counts),
        benign=sum(c.benign for c in counts),
        unsure=sum(c.unsure for c in counts),
        agreed=sum(c.agreed for c in counts),
    )
