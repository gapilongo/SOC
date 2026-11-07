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
PROVENANCE_FIELDS = ("provider", "model", "prompt_name", "prompt_hash")


def llm_provenance(usage: Mapping[str, Any]) -> Dict[str, Dict[str, str]]:
    """``{agent: {provider, model, prompt_name, prompt_hash}}`` from ``summary.llm_usage.by_agent``."""
    by_agent = usage.get("by_agent")
    out: Dict[str, Dict[str, str]] = {}
    for agent, entry in (by_agent.items() if isinstance(by_agent, Mapping) else ()):
        if isinstance(agent, str) and isinstance(entry, Mapping) and entry.get("calls"):
            out[agent] = {k: str(entry[k]) for k in PROVENANCE_FIELDS if isinstance(entry.get(k), str)}
    return out


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
    llm_provenance: Dict[str, Dict[str, str]] = field(default_factory=dict)
    """Per agent: the provider, model, prompt name and prompt hash of its latest LLM call."""

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
