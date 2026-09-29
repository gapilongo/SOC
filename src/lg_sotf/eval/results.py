"""Per-item evaluation outcome: what the platform did with one labelled alert."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional

ItemStatus = Literal[
    "closed",  # automation closed the alert (disposition set, no human involved)
    "waiting_human",  # an escalation asked for analyst review; not reviewed during the eval
    "waiting_approval",  # response actions wait for approval; not approved during the eval
    "error",  # ingestion rejected the event, or the run failed or timed out
]
REVIEW_UNREVIEWED = "unreviewed"


@dataclass
class ItemResult:
    """One dataset item after ingestion and a workflow run.

    ``predicted`` is the disposition the platform arrived at on its own: the
    closing disposition, ``malicious`` for a run waiting on response
    approval, or the analysis verdict (``inconclusive`` without one) for a run
    handed to an analyst. ``review`` is ``unreviewed`` whenever the run
    stopped at an analyst or approval interrupt: the harness records that
    human review was requested and never invents a decision.
    """

    item_id: str
    split: str
    tags: List[str]
    source_type: str
    expected: str
    status: ItemStatus
    predicted: Optional[str] = None
    alert_id: Optional[str] = None
    severity: Optional[str] = None
    disposition: Optional[str] = None
    route: Optional[str] = None
    decision_code: Optional[str] = None
    close_reason: Optional[str] = None
    escalated: bool = False
    approval_requested: bool = False
    review: Optional[str] = None
    model_refused: bool = False
    expected_route: Optional[str] = None
    expected_escalation: Optional[bool] = None
    labels: Dict[str, str] = field(default_factory=dict)
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_s: float = 0.0
    error: Optional[str] = None

    @property
    def scored(self) -> bool:
        return self.status != "error"

    @property
    def auto_closed(self) -> bool:
        """Closed by automation alone (the eval never supplies an analyst decision)."""
        return self.status == "closed"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ItemResult:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)
