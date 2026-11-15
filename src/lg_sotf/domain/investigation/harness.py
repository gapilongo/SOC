"""The evidence lookups of an alert, and the claims the deep model cited them for (AI-E3.3).

Read from ``alerts.summary.analysis.investigation``, which the analysis node wrote
(:class:`lg_sotf.core.state.InvestigationRecord`): what the executor did, what it used of each budget, the
playbook's indicators, and the model's claims with the citation findings code raised on them. Nothing is
computed again here, and nothing is read from a model: a finding is the one stored when the claim was
checked against the ledger of its own run.

An alert without that record had no lookups. :func:`evidence_run` then says why, from what the alert
itself shows: it never reached the deeper analysis, its source has no evidence tools, or the customer
had not switched them on.

Stored values are data. A code a newer release wrote is kept as a code, never formatted into a sentence;
a value outside the vocabulary of this release falls back to the cautious reading (``failed``,
``unknown``).
"""

from __future__ import annotations

import math
from typing import Any, List, Mapping, Optional, Sequence, Tuple, get_args

from lg_sotf.domain.investigation import words
from lg_sotf.domain.investigation.facts import MAX_CLAIM_CHARS, MAX_CODE_CHARS, MAX_TARGET_CHARS, bounded, mapping
from lg_sotf.domain.investigation.model import (
    BudgetKind,
    CitationFindingCode,
    ClaimFinding,
    Direction,
    EvidenceBudget,
    EvidenceIndicator,
    EvidenceLookup,
    EvidenceLookupOutcome,
    EvidenceRun,
    IndicatorState,
    InvestigationReason,
    NotCheckedItem,
)

WAZUH = "wazuh"
MAX_LOOKUPS = 32
MAX_CITED_CLAIMS = 6
MAX_CITES = 10
_OUTCOMES: Tuple[str, ...] = get_args(EvidenceLookupOutcome)
_STATES: Tuple[str, ...] = get_args(IndicatorState)
_KINDS: Tuple[str, ...] = get_args(BudgetKind)
_FINDINGS: Tuple[str, ...] = get_args(CitationFindingCode)

#: A model claim the view lists: text, what it points to, the cited ids the ledger holds, the findings.
CitedClaim = Tuple[str, Direction, List[str], List[ClaimFinding]]


def _record(summary: Mapping[str, Any]) -> Mapping[str, Any]:
    return mapping(mapping(summary.get("analysis")).get("investigation"))


def _items(value: Any, limit: int) -> List[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)][:limit] if isinstance(value, (list, tuple)) else []


def _code(value: Any) -> Optional[str]:
    return bounded(value, MAX_CODE_CHARS) if isinstance(value, str) and value else None


def _reason(code: Optional[str]) -> Optional[InvestigationReason]:
    if code is None:
        return None
    return InvestigationReason(code=code, sentence=words.EVIDENCE_REASONS.get(code, words.UNKNOWN_EVIDENCE_REASON))


def _number(value: Any) -> Optional[float]:
    """A stored number as a finite float; ``None`` for anything else (an integer too large for one included)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _lookup(step: Mapping[str, Any]) -> EvidenceLookup:
    outcome = step.get("outcome")
    ids = step.get("fact_ids")
    return EvidenceLookup(
        evidence_id=bounded(step.get("evidence_id") or "", MAX_CODE_CHARS),
        tool=bounded(step.get("tool") or "", MAX_CODE_CHARS),
        outcome=outcome if outcome in _OUTCOMES else "failed",
        reason=_code(step.get("reason")),
        observation_ids=[bounded(i, MAX_TARGET_CHARS) for i in ids if isinstance(i, str)][:50] if isinstance(ids, list) else [],
        complete=step.get("complete") is True,
        reused=step.get("reused") is True,
    )


def _budgets(record: Mapping[str, Any]) -> List[EvidenceBudget]:
    out: List[EvidenceBudget] = []
    for kind in _KINDS:
        entry = mapping(mapping(record.get("budget")).get(kind))
        used, limit = _number(entry.get("used")), _number(entry.get("limit"))
        if used is not None and limit is not None:
            out.append(EvidenceBudget(kind=kind, used=used, limit=limit))
    return out


def _indicators(record: Mapping[str, Any]) -> List[EvidenceIndicator]:
    return [
        EvidenceIndicator(id=bounded(name, MAX_CODE_CHARS), state=state if state in _STATES else "unknown")
        for name, state in list(mapping(record.get("indicators")).items())[:MAX_LOOKUPS]
        if isinstance(name, str)
    ]


def not_run_reason(summary: Mapping[str, Any], view: Mapping[str, Any]) -> str:
    """Why an alert without a stored investigation had no lookups, from what the alert itself shows."""
    if not mapping(summary.get("analysis")):
        return "not_analysed"
    return "switched_off" if view.get("normalizer") == WAZUH else "no_evidence_tools"


def same_run(summary: Mapping[str, Any], ledger_run_id: Optional[str]) -> bool:
    """Whether the stored record and the ledger the view lists are of one investigation run.

    They differ while an alert is being processed again (the new run's lookups are on the ledger, the
    stored analysis is still the earlier run's), or when the newer run recorded no lookup. Ids such as
    ``host:0`` exist in both runs, so a claim of one run is never put beside an observation of the other.
    """
    recorded = _record(summary).get("run_id")
    return ledger_run_id is None or not isinstance(recorded, str) or recorded == ledger_run_id


def evidence_run(summary: Mapping[str, Any], view: Mapping[str, Any], *, listed: bool = True) -> EvidenceRun:
    """The evidence lookups of the alert's newest analysis, or why there were none. ``listed`` is false when
    the observations the view lists are another run's (:func:`same_run`): the lookups then name none."""
    record = _record(summary)
    if not record:
        return EvidenceRun(status="not_run", reason=_reason(not_run_reason(summary, view)))
    reason = _code(record.get("reason"))
    lookups = [_lookup(step) for step in _items(record.get("steps"), MAX_LOOKUPS)]
    if not listed:
        lookups = [lookup.model_copy(update={"observation_ids": []}) for lookup in lookups]
    return EvidenceRun(
        evidence_truncated=record.get("evidence_truncated") is True,
        status="ran" if record.get("status") == "completed" and reason is None else "degraded",
        reason=_reason(reason or (None if record.get("status") == "completed" else "error")),
        playbook_id=_code(record.get("skill")),
        playbook_version=_code(record.get("skill_version")),
        run_id=_code(record.get("run_id")),
        stop_reason=_code(record.get("stop_reason")),
        lookups=lookups,
        budgets=_budgets(record),
        indicators=_indicators(record),
    )


def _findings(claim: Mapping[str, Any]) -> List[ClaimFinding]:
    out: List[ClaimFinding] = []
    for found in _items(claim.get("findings"), MAX_CITES + 1):
        code = found.get("code")
        if code in _FINDINGS:
            out.append(
                ClaimFinding(
                    code=code, sentence=words.CITATION_FINDINGS[code],
                    cited=bounded(found.get("fact_id") or "", MAX_TARGET_CHARS),
                )
            )
    return out


def cited_claims(summary: Mapping[str, Any]) -> List[CitedClaim]:
    """The deep model's claims, each with the ids it cited that the run's ledger holds and its findings."""
    out: List[CitedClaim] = []
    for claim in _items(_record(summary).get("claims"), MAX_CITED_CLAIMS):
        text = claim.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        findings = _findings(claim)
        unknown = {finding.cited for finding in findings if finding.code == "unknown_fact"}
        cites = claim.get("cites")
        held = [bounded(c, MAX_TARGET_CHARS) for c in (cites if isinstance(cites, list) else [])[:MAX_CITES] if isinstance(c, str)]
        direction: Direction = "benign" if claim.get("supports") == "benign" else "malicious"
        out.append((bounded(text, MAX_CLAIM_CHARS), direction, [c for c in held if c not in unknown], findings))
    return out


def skipped_lookups(run: EvidenceRun) -> Sequence[NotCheckedItem]:
    """The playbook's lookups that made no call: what each would have looked up, and why it was skipped."""
    return [
        NotCheckedItem(
            what=words.EVIDENCE_TOOL_TITLES.get(lookup.tool, words.UNKNOWN_LOOKUP_TITLE),
            why=words.SKIPPED_LOOKUP_REASONS.get(lookup.reason or "", words.UNKNOWN_SKIP_REASON),
        )
        for lookup in run.lookups
        if lookup.outcome == "skipped"
    ]
