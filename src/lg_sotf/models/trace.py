"""One step of the investigation trace: an LLM call or a tool call, as recorded during a run.

Written by :class:`lg_sotf.llm.trace.TraceRecorder`, stored by
:class:`lg_sotf.db.repos.investigation_steps.InvestigationStepsRepo` (table
``investigation_steps``, migration 0011). Hashes are lowercase hex SHA-256;
``result_digest`` is already redacted and size-capped.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Literal, Optional, Tuple, get_args

from pydantic import BaseModel, ConfigDict

StepKind = Literal["llm", "tool"]
StepOutcome = Literal["success", "refusal", "invalid_output", "error"]
STEP_KINDS: Tuple[str, ...] = get_args(StepKind)
STEP_OUTCOMES: Tuple[str, ...] = get_args(StepOutcome)


class NewTraceStep(BaseModel):
    """What a step records; the store adds the tenant, alert, run and the step's index in the run."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    agent: str
    kind: StepKind
    input_hash: str
    outcome: StepOutcome
    started_at: datetime
    prompt_name: Optional[str] = None
    prompt_hash: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    tool: Optional[str] = None
    output_hash: Optional[str] = None
    result_digest: Optional[Dict[str, Any]] = None
    error_type: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    latency_ms: int = 0


__all__ = ["STEP_KINDS", "STEP_OUTCOMES", "NewTraceStep", "StepKind", "StepOutcome"]
