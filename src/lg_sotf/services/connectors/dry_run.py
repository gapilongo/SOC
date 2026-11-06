"""Dry-run connector: records what would have been executed and changes nothing outside the ledger."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lg_sotf.domain.connectors import ConnectorResult

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

DRY_RUN_NOTE = "dry-run connector: no external system was called"


class DryRunConnector:
    """The default connector (contract section 11). Naturally idempotent: it has no side effects."""

    name = "dry_run"

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        return ConnectorResult(
            "dry_run",
            {
                "would_execute": action.action_type,
                "target": action.target,
                "risk_level": action.risk_level,
                "params": dict(action.params),
                "note": DRY_RUN_NOTE,
            },
        )
