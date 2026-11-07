"""The public surface of ``lg_sotf.services.response`` survives the package split (S2).

The module became a package; its importers were not rewritten. Every name of
the pre-split ``__all__`` is still exported, and every name any module in
``src``, ``tests``, ``examples`` or ``scripts`` imports from the package (or
one of its submodules) resolves.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from lg_sotf.services import response

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
SCANNED = ("src", "tests", "examples", "scripts")

PRE_SPLIT_ALL = frozenset({
    "ACTION_CATALOG", "ACTION_TARGET_KINDS", "APPROVAL_EXPIRED_REASON", "APPROVAL_SUPERSEDED_REASON",
    "ActionRequestError", "ActionSpec", "AutoBudget", "BLAST_RADIUS_REASON", "Connector", "ConnectorResult",
    "DEFAULT_BLAST_RADIUS", "Disposition", "DryRunConnector", "FORWARD_OF", "GUARDRAIL_REASONS", "GuardrailBlock",
    "HOURLY_CAP_REASON", "POLICY_INVALID_REASON", "PROTECTED_INVALID_REASON", "PlanContext", "PlanResult",
    "ProtectedAssets", "ProtectedAssetsSettings", "ResponsePolicy", "ResponsePolicyError", "ResponsePolicySettings",
    "ResponseService", "TargetKind", "approval_allowed", "bounded_detail", "candidate_targets", "check_guardrails",
    "dispose", "plan_entities", "preapproval_allowed", "protected_lookup", "resolve_autonomy",
    "validate_response_settings", "validate_target",
})


def imported_names() -> dict[tuple[str, str], str]:
    """``(module, name) -> first importer`` for every ``from lg_sotf.services.response[...] import name``."""
    found: dict[tuple[str, str], str] = {}
    for root in SCANNED:
        for path in sorted((ROOT / root).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None and (
                    node.module == "lg_sotf.services.response" or node.module.startswith("lg_sotf.services.response.")
                ):
                    for alias in node.names:
                        found.setdefault((node.module, alias.name), str(path.relative_to(ROOT)))
    return found


def test_the_pre_split_all_is_still_exported() -> None:
    assert PRE_SPLIT_ALL <= set(response.__all__)
    assert all(hasattr(response, name) for name in PRE_SPLIT_ALL)


def test_every_imported_name_resolves() -> None:
    found = imported_names()
    assert ("lg_sotf.services.response", "ResponseService") in found  # the scan sees the importers
    missing = [
        f"{module}:{name} ({where})"
        for (module, name), where in sorted(found.items())
        if not hasattr(importlib.import_module(module), name)
    ]
    assert not missing, missing
