"""Builders shared by the evaluation unit tests."""

from __future__ import annotations

from typing import Any

from lg_sotf.eval.results import ItemResult


def result(item_id: str, expected: str, status: str = "waiting_human", **kw: Any) -> ItemResult:
    """An item result with sensible defaults for the given outcome."""
    defaults: dict[str, Any] = {"split": "standard", "tags": [], "source_type": "canonical"}
    if status == "closed":
        defaults.update(predicted=kw.get("disposition", "benign"), disposition=kw.get("disposition", "benign"),
                        route="close")
    elif status == "waiting_human":
        defaults.update(predicted="inconclusive", escalated=True, route="escalate", review="unreviewed")
    elif status == "waiting_approval":
        defaults.update(predicted="malicious", approval_requested=True, route="plan_response", review="unreviewed")
    elif status == "error":
        defaults.update(error="boom")
    defaults.update(kw)
    return ItemResult(item_id=item_id, expected=expected, status=status, **defaults)  # type: ignore[arg-type]
