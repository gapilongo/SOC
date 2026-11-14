"""Observations, claims and what is not established, from the lookups the analysis recorded.

An observation is one tool call with a typed outcome (ADR-0014 Amendment 2):
``success`` (a source returned data), ``empty`` (the sources answered and
found nothing) or ``failed``. An empty or failed observation backs no claim:
it is listed under "not established" and nothing else reads it.

Claims today come from two places. The fast model's indicators
(``triage.llm_tp`` and ``llm_fp``) are claims in the model's own words; the
model cites nothing yet, so they are ``unsupported``. The rule evidence a
lookup produced (``threat_intel_malicious``, ``prior_malicious_history``) is
``supported`` and names the observations behind it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.domain.digests import ENTITY_KINDS
from lg_sotf.domain.investigation import words
from lg_sotf.domain.investigation.facts import (
    MAX_CLAIM_CHARS,
    MAX_CLAIMS,
    MAX_CODE_CHARS,
    MAX_EXCERPT_LINES,
    MAX_LINE_CHARS,
    MAX_OBSERVATIONS,
    MAX_TARGET_CHARS,
    Lookup,
    TraceRef,
    bounded,
    mapping,
    strings,
)
from lg_sotf.domain.investigation.model import (
    Direction,
    InvestigationClaim,
    InvestigationObservation,
    NotCheckedItem,
    NotEstablished,
    ObservationExcerptLine,
    ObservationOutcome,
    UnavailableItem,
    WrittenBy,
)

#: Provider verdicts, worst first.
VERDICT_ORDER: Tuple[str, ...] = ("malicious", "suspicious", "harmless", "unknown")
NO_CITATION = "The model named no observation for it."
LOOKUP_GONE = "The lookup behind it is no longer stored."
_HISTORY_ENVELOPE = frozenset({"kind", "value", "checked_at"})
#: The fast model's indicators (``triage`` digest keys) and what each points to.
_MODEL_CLAIMS: Tuple[Tuple[str, Direction], ...] = (("llm_tp", "malicious"), ("llm_fp", "benign"))


def _mappings(values: Any) -> List[Mapping[str, Any]]:
    return [v for v in values if isinstance(v, Mapping)] if isinstance(values, (list, tuple)) else []


def lookups_of(summary: Mapping[str, Any]) -> List[Lookup]:
    """The lookups ``alerts.summary.analysis`` records, in the order they ran: history first, then reputation."""
    analysis = mapping(summary.get("analysis"))
    out: List[Lookup] = []
    for entry in _mappings(analysis.get("history")):
        result = {k: v for k, v in entry.items() if k not in _HISTORY_ENVELOPE}
        out.append(
            Lookup("history", str(entry.get("kind") or ""), str(entry.get("value") or ""), [result], result,
                   _text(entry.get("checked_at")))
        )
    for tool in _mappings(analysis.get("tools")):
        results = _mappings(tool.get("results"))
        out.append(
            Lookup(bounded(tool.get("tool") or "reputation", MAX_CODE_CHARS), str(tool.get("kind") or ""),
                   str(tool.get("target") or ""), results, results, _text(tool.get("checked_at")))
        )
    return out[:MAX_OBSERVATIONS]


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _status(result: Mapping[str, Any]) -> str:
    return str(result.get("status") or "")


def lookup_outcome(results: Sequence[Mapping[str, Any]]) -> ObservationOutcome:
    """``success`` when a provider returned data, ``empty`` when one answered and found nothing, else ``failed``."""
    statuses = {_status(r) for r in results}
    if "ok" in statuses:
        return "success"
    return "empty" if "not_found" in statuses else "failed"


def worst_verdict(results: Sequence[Mapping[str, Any]]) -> Optional[str]:
    """The worst verdict among the results that returned data; ``None`` without one."""
    found = {str(r.get("verdict") or "unknown") for r in results if _status(r) == "ok"}
    return next((v for v in VERDICT_ORDER if v in found), None)


def _excerpt(results: Sequence[Mapping[str, Any]]) -> Tuple[List[ObservationExcerptLine], bool]:
    """What the providers returned, one bounded line per result and per data value. Lines are data."""
    lines: List[str] = []
    for result in results:
        head = [str(result.get("provider") or "?"), _status(result) or "?"]
        if _status(result) == "ok":
            head.append(str(result.get("verdict") or "unknown"))
        if result.get("cached"):
            head.append("(cached)")
        lines.append("  ".join(head))
        lines.extend(f"  {key}: {value}" for key, value in mapping(result.get("data")).items())
    kept = [ObservationExcerptLine(text=bounded(line, MAX_LINE_CHARS)) for line in lines[:MAX_EXCERPT_LINES]]
    return kept, len(lines) > MAX_EXCERPT_LINES


def _when(lookup: Lookup) -> Optional[datetime]:
    if lookup.trace is not None:
        return lookup.trace.started_at
    try:
        return datetime.fromisoformat(lookup.checked_at) if lookup.checked_at else None
    except ValueError:
        return None


def _observation(index: int, lookup: Lookup) -> InvestigationObservation:
    excerpt, truncated = _excerpt(lookup.results)
    outcome = lookup_outcome(lookup.results)
    return InvestigationObservation(
        id=f"O-{index:02d}",
        tool=lookup.tool,
        title=words.LOOKUP_TITLES.get(lookup.tool, words.UNKNOWN_LOOKUP_TITLE),
        kind=bounded(lookup.kind, MAX_CODE_CHARS) or None,
        target=bounded(lookup.target, MAX_TARGET_CHARS) or None,
        sources=[bounded(r.get("provider") or "?", MAX_CODE_CHARS) for r in lookup.results],
        at=_when(lookup),
        outcome=outcome,
        verdict=worst_verdict(lookup.results) if outcome == "success" else None,
        cached=bool(lookup.results) and all(bool(r.get("cached")) for r in lookup.results),
        excerpt=excerpt,
        excerpt_truncated=truncated,
        input_sha256=lookup.trace.input_hash if lookup.trace else None,
        output_sha256=lookup.trace.output_hash if lookup.trace else None,
    )


def _failed_call(index: int, call: TraceRef) -> InvestigationObservation:
    """A tool call that raised: the trace store has its hash and time, nothing else."""
    tool = bounded(call.tool, MAX_CODE_CHARS)
    return InvestigationObservation(
        id=f"O-{index:02d}", tool=tool, title=words.LOOKUP_TITLES.get(tool, words.UNKNOWN_LOOKUP_TITLE),
        at=call.started_at, outcome="failed", input_sha256=call.input_hash, output_sha256=call.output_hash,
    )


def observations(lookups: Sequence[Lookup], failed_tools: Sequence[TraceRef]) -> List[InvestigationObservation]:
    """One observation per lookup, then one per tool call that raised, numbered ``O-01`` onward."""
    out = [_observation(i, lookup) for i, lookup in enumerate(lookups[:MAX_OBSERVATIONS], start=1)]
    for call in failed_tools[: MAX_OBSERVATIONS - len(out)]:
        out.append(_failed_call(len(out) + 1, call))
    return out


def _backing(code: str, lookups: Sequence[Lookup], found: Sequence[InvestigationObservation]) -> List[str]:
    """The observations a rule claim rests on: successful lookups of its tool with its verdict."""
    tool, verdict = ("history", "malicious") if code == "prior_malicious_history" else (
        "reputation", code.removeprefix("threat_intel_"))
    return [
        obs.id
        for lookup, obs in zip(lookups, found, strict=False)
        if lookup.tool == tool and obs.outcome == "success"
        and any(_status(r) == "ok" and r.get("verdict") == verdict for r in lookup.results)
    ]


def claims(
    summary: Mapping[str, Any], lookups: Sequence[Lookup], found: Sequence[InvestigationObservation]
) -> List[InvestigationClaim]:
    """The model's claims (unsupported: it cites nothing yet), then the rule claims a lookup backs."""
    triage, analysis = mapping(summary.get("triage")), mapping(summary.get("analysis"))
    drafts: List[Tuple[str, WrittenBy, Direction, List[str]]] = []
    for key, direction in _MODEL_CLAIMS:
        for text in strings(triage.get(key), limit=MAX_CLAIMS, chars=MAX_CLAIM_CHARS):
            drafts.append((text, "model", direction, []))
    indicators = analysis.get("threat_indicators")
    for code, (direction, sentence) in words.LOOKUP_CLAIMS.items():
        if isinstance(indicators, list) and code in indicators:
            drafts.append((sentence, "rules", direction, _backing(code, lookups, found)))
    out: List[InvestigationClaim] = []
    for index, (text, author, direction, ids) in enumerate(drafts[:MAX_CLAIMS], start=1):
        reason = None if ids else (NO_CITATION if author == "model" else LOOKUP_GONE)
        out.append(
            InvestigationClaim(
                id=f"C-{index:02d}", text=text, written_by=author, direction=direction, observation_ids=ids,
                check="supported" if ids else "unsupported", check_reason=reason,
            )
        )
    return out


def _unavailable(
    lookups: Sequence[Lookup], found: Sequence[InvestigationObservation]
) -> List[UnavailableItem]:
    """Lookups a source could not make (once per tool, status and provider), then the tool calls that raised."""
    seen: Dict[Tuple[str, str, str], UnavailableItem] = {}
    for lookup, obs in zip(lookups, found, strict=False):
        for result in lookup.results:
            known = words.LOOKUP_STATUS_SENTENCES.get(_status(result))
            provider = bounded(result.get("provider") or "?", MAX_CODE_CHARS)
            key = (lookup.tool, _status(result), provider)
            if known is None or key in seen:
                continue
            seen[key] = UnavailableItem(
                what=obs.title, why=known[1], kind=known[0], source=provider, observation_id=obs.id
            )
    out = list(seen.values())
    for obs in found[len(lookups):]:
        out.append(
            UnavailableItem(what=obs.title, why=words.TOOL_ERROR_SENTENCE, kind="tool_failed", observation_id=obs.id)
        )
    return out


def _not_checked(summary: Mapping[str, Any], view: Mapping[str, Any], lookups: Sequence[Lookup]) -> List[NotCheckedItem]:
    """What today's analysis could have looked up and did not, and what no tool can look up yet."""
    if summary.get("suppressed_by") is not None:
        return [NotCheckedItem(what=words.NOT_INVESTIGATED[0], why=words.NOT_INVESTIGATED[1])]
    out: List[NotCheckedItem] = []
    if not mapping(summary.get("analysis")):
        out.append(NotCheckedItem(what=words.NO_ANALYSIS[0], why=words.NO_ANALYSIS[1]))
    else:
        entities = mapping(view.get("entities"))
        looked_up = {lookup.kind for lookup in lookups if lookup.tool != "history"}
        for key, kind in ENTITY_KINDS:
            what = words.UNCHECKED_KINDS.get(kind)
            if what is not None and kind not in looked_up and strings(entities.get(key), limit=1, chars=1):
                out.append(NotCheckedItem(what=what, why=words.NO_LOOKUP_WHY))
    out.append(NotCheckedItem(what=words.NO_TELEMETRY[0], why=words.NO_TELEMETRY[1]))
    return out


def not_established(
    summary: Mapping[str, Any], view: Mapping[str, Any], lookups: Sequence[Lookup],
    found: Sequence[InvestigationObservation],
) -> NotEstablished:
    """Three lists: checked and found nothing, not checked, could not be checked for this customer."""
    return NotEstablished(
        empty=[obs.id for obs in found if obs.outcome == "empty"],
        not_checked=_not_checked(summary, view, lookups),
        unavailable=_unavailable(lookups, found),
    )
