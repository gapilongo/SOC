"""A verdict's claims held against the run's fact ledger (AI-E3.3): findings, stored with each claim.

The deep model is shown the ledger's view and asked which ids each of its claims rests on. What it
answers is checked here, by code, with :func:`lg_sotf.domain.ledger.check_citations` against the ledger
of the claim's own run, as the executor left it (:attr:`InvestigationRun.ledger`): an id the ledger did
not mint is ``unknown_fact`` whatever the model wrote, and a benign claim that cites an empty, failed or
incomplete observation, or nothing, is a finding too. The check reads no store and calls nothing.

Findings only: nothing here changes the verdict or the routing. The checker and the decision policy that
act on them are AI-E3.4 and AI-E3.8a.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, Sequence

from lg_sotf.agents.investigation.executor import InvestigationRun
from lg_sotf.domain.ledger import LedgerEntry, check_citations
from lg_sotf.observability.logging import get_logger, log_failure

__all__ = ["CitedClaim", "checked_claims", "investigation_record"]

log = get_logger(__name__)


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
    return record
