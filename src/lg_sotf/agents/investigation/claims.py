"""A verdict's claims held against the run's fact ledger (AI-E3.3): findings, stored with each claim.

The deep model is shown the ledger's view and asked which ids each of its claims rests on. What it
answers is checked here, by code, with :func:`lg_sotf.domain.ledger.check_citations` against the ledger
of the claim's own run: an id the ledger did not mint is ``unknown_fact`` whatever the model wrote, and a
benign claim that cites an empty, failed or incomplete observation, or nothing, is a finding too.

Findings only: nothing here changes the verdict or the routing. The checker and the decision policy that
act on them are AI-E3.4 and AI-E3.8a.
"""

from __future__ import annotations

from typing import Any, Dict, List, Protocol, Sequence

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.investigation.ledger import FactLedger
from lg_sotf.domain.ledger import check_citations

__all__ = ["CitedClaim", "checked_claims"]


class CitedClaim(Protocol):
    """A claim as the model returned it (``lg_sotf.agents.analysis.react.Claim``)."""

    @property
    def text(self) -> str: ...

    @property
    def supports(self) -> str: ...

    @property
    def cites(self) -> Sequence[str]: ...


async def checked_claims(ctx: AgentContext, claims: Sequence[CitedClaim]) -> List[Dict[str, Any]]:
    """Each claim with its citations and what is wrong with them (an empty ``findings``: every id holds)."""
    if not claims:
        return []
    ledger = await FactLedger.for_run(ctx).facts()
    checked: List[Dict[str, Any]] = []
    for claim in claims:
        cites = [str(cited) for cited in claim.cites]
        problems = check_citations(cites, ledger, benign_claim=claim.supports == "benign")
        checked.append({
            "text": claim.text, "supports": claim.supports, "cites": cites,
            "findings": [{"fact_id": problem.fact_id, "code": problem.code} for problem in problems],
        })
    return checked
