"""Evaluation-only fields of a dataset line that ``ingest_test_alerts`` accepts and ignores.

The adversarial corpus (``tests/fixtures/eval/adversarial_v2.jsonl``) adds ``family``, ``injection`` and
``tool_fixtures`` to an item. A line still fits ``ingest_test_alerts`` as is, but these fields never reach the
API: canned tool answers apply only to ``lg-sotf eval``, and the platform never simulates intelligence.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import Field

from lg_sotf.mcp.base import _Args

FAMILY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


class EvalOnlyItemFields(_Args):
    family: Optional[str] = Field(default=None, pattern=FAMILY_PATTERN)
    injection: Optional[Dict[str, Any]] = None
    tool_fixtures: Optional[Dict[str, Any]] = None


EVAL_ONLY_ITEM_PROPERTIES: Dict[str, Any] = {
    "family": {"type": "string", "pattern": FAMILY_PATTERN, "maxLength": 128,
               "description": "Adversarial family of an evaluation dataset; ignored."},
    "injection": {"type": "object", "description": "Injection spec of an evaluation dataset; ignored."},
    "tool_fixtures": {"type": "object", "description": "Canned tool answers of an evaluation dataset; ignored "
                      "(they apply only to lg-sotf eval)."},
}
