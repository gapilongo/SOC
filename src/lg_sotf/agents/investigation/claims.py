"""A verdict's claims held against the run's fact ledger (AI-E3.3): findings, stored with each claim.

The deep model is shown the ledger's view and asked which ids each of its claims rests on. What it
answers is checked here, by code, with :func:`lg_sotf.domain.ledger.check_citations` against the ledger
of the claim's own run, as the executor left it (:attr:`InvestigationRun.ledger`): an id the ledger did
not mint is ``unknown_fact`` whatever the model wrote, and a benign claim that cites an empty, failed or
incomplete observation, or nothing, is a finding too. The check reads no store and calls nothing.

Nothing here changes the verdict. The record says what of the investigation holds a model-led close
(:func:`blocking`): the decision policy reads it (:func:`lg_sotf.domain.closure.evidence_holds`). The
full claim checker is AI-E3.4.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence

from lg_sotf.agents.investigation.executor import InvestigationRun
from lg_sotf.domain.closure import HARD_CITATION_FINDINGS
from lg_sotf.domain.ledger import LedgerEntry, check_citations
from lg_sotf.observability.logging import get_logger, log_failure

__all__ = ["DIGEST_KEYS", "CitedClaim", "blocking", "checked_claims", "evidence_backed", "investigation_digest",
           "investigation_record"]

log = get_logger(__name__)

NO_CLAIMS = "no_claims"
UNCHECKED = "unchecked"
#: What of the record graph state carries: counts and codes, and what holds a close. No step, no claim.
DIGEST_KEYS = (
    "status", "reason", "skill", "skill_version", "stop_reason", "lookups", "facts", "empty", "failed", "skipped",
    "blocking",
)


def investigation_digest(record: Mapping[str, Any]) -> Dict[str, Any]:
    """The stored record made small for graph state and the node's event: :data:`DIGEST_KEYS`, the number
    of claims, and the number of findings (on the claims' citations and on the verdict as a whole)."""
    small = {key: record.get(key) for key in DIGEST_KEYS}
    claims = record.get("claims") or []
    findings = sum(len(claim["findings"]) for claim in claims) + len(record.get("verdict_findings") or [])
    small.update(claim_count=len(claims), citation_findings=findings)
    return small


class CitedClaim(Protocol):
    """A claim as the model returned it (``lg_sotf.agents.analysis.react.Claim``)."""

    @property
    def text(self) -> str: ...

    @property
    def supports(self) -> str: ...

    @property
    def cites(self) -> Sequence[str]: ...


def checked_claims(ledger: Sequence[LedgerEntry], claims: Sequence[CitedClaim]) -> List[Dict[str, Any]]:
    """Each claim with its citations and what is wrong with them (an empty ``findings``: every id holds)."""
    checked: List[Dict[str, Any]] = []
    for claim in claims:
        cites = [str(cited) for cited in claim.cites]
        problems = check_citations(cites, ledger, benign_claim=claim.supports == "benign")
        checked.append({
            "text": claim.text, "supports": claim.supports, "cites": cites,
            "findings": [{"fact_id": problem.fact_id, "code": problem.code} for problem in problems],
        })
    return checked


def investigation_record(
    investigation: Optional[InvestigationRun], final: Any, *, evidence_truncated: bool = False
) -> Optional[Dict[str, Any]]:
    """What ``alerts.summary.analysis.investigation`` stores: what the executor did and, when the model was
    shown the evidence, its claims with their citations checked against the run's ledger. ``None`` without an
    investigation.

    ``evidence_truncated``: the prompt builder cut the evidence to fit its size limit, so the model saw some
    facts in part (the prompt says so, and so does the record). ``claims_checked`` is false when the check
    itself failed: the claims are then left out, and that never fails the analysis.
    """
    if investigation is None:
        return None
    record = investigation.record()
    shown = investigation.context is not None
    record["evidence_truncated"] = shown and evidence_truncated
    try:
        record["claims"] = checked_claims(investigation.ledger, (getattr(final, "claims", None) or []) if shown else [])
        record["claims_checked"] = True
    except Exception as exc:  # noqa: BLE001 - the citation check never fails the alert's run
        log_failure(log, "investigation.citation_check_failed", exc, level="warning", error_type=type(exc).__name__)
        record.update(claims=[], claims_checked=False)
    # A benign verdict that was shown the evidence and rests on no claim at all: a finding, like a claim
    # that cites nothing.
    benign = shown and getattr(final, "verdict", None) == "benign"
    record["verdict_findings"] = [{"code": NO_CLAIMS}] if benign and record["claims_checked"] and not record["claims"] else []
    record["blocking"] = blocking(investigation, record)
    record["evidence_backed"] = evidence_backed(final, record)
    return record


def evidence_backed(final: Any, record: Mapping[str, Any]) -> bool:
    """Whether the benign verdict rests on recorded evidence: it has benign claims, and every one of them
    cites at least one observation and has no finding (so each cited one is a complete fact a tool observed).
    Anything less (a claim on an empty or incomplete lookup, on nothing, or no claim) is the model's word.
    A label only: no decision reads it."""
    benign = [claim for claim in record["claims"] if claim["supports"] == "benign"]
    return (
        getattr(final, "verdict", None) == "benign" and record["claims_checked"] is True and bool(benign)
        and all(claim["cites"] and not claim["findings"] for claim in benign)
    )


def blocking(investigation: InvestigationRun, record: Dict[str, Any]) -> Dict[str, Any]:
    """What of the investigation holds a model-led close (read by :mod:`lg_sotf.domain.closure`): the facts
    with steering text, the malicious indicators that are true with their fact ids, and the hard citation
    findings (an id the ledger did not mint, an altered entry: forgery or corruption). A check that failed
    counts as a hard finding: nothing closes on claims nobody checked."""
    codes = sorted({f["code"] for claim in record["claims"] for f in claim["findings"]} & HARD_CITATION_FINDINGS)
    if not record["claims_checked"]:
        codes.append(UNCHECKED)
    return {"steering": list(investigation.steering), "indicators": dict(investigation.held_indicators), "citations": codes}
