"""Declared tenant context (fatigue step 1): the ``_meta.tenant_context`` schema and what it matches."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict

import pytest
from pydantic import ValidationError

from lg_sotf.eval.closure import context_coverage
from lg_sotf.eval.context import CONTEXT_KINDS, PatchWindow, TenantContext, context_matches
from lg_sotf.eval.dataset import DatasetError, load_dataset, parse_dataset

pytestmark = pytest.mark.unit

CORPUS = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "corpus_v1.jsonl.gz"
ITEM = {"id": "x-1", "source_type": "canonical", "alert": {"title": "t", "severity": "low"},
        "expected": {"disposition": "benign"}}


def _dataset(meta: Dict[str, Any]) -> str:
    return json.dumps({"_meta": meta}) + "\n" + json.dumps(ITEM)


def test_a_full_declaration_validates_and_reports_what_it_declares() -> None:
    context = TenantContext.model_validate({
        "admin_accounts": ["adm.ksmith"], "admin_groups": ["IT-Admins"], "helpdesk_accounts": ["hd.ochen"],
        "automation_accounts": ["ansible"], "automation_hosts": ["build-01"],
        "jump_hosts": [{"host": "IT-WS-01", "ips": ["10.20.1.120"], "tools": ["psexec"]}],
        "patch_windows": [{"name": "servers", "start": "23:00", "end": "02:00", "days": ["sat"], "hosts": ["db-01"]}],
        "scanners": ["10.20.5.0/24"],
    })
    assert set(context.declared()) == set(CONTEXT_KINDS)


@pytest.mark.parametrize(
    "bad",
    [
        {"admin_acounts": ["typo"]},
        {"patch_windows": [{"name": "w", "start": "25:00", "end": "02:00", "hosts": ["h"]}]},
        {"patch_windows": [{"name": "w", "start": "01:00", "end": "01:00", "hosts": ["h"]}]},
        {"patch_windows": [{"name": "w", "start": "01:00", "end": "02:00", "hosts": []}]},
        {"patch_windows": [{"name": "w", "start": "01:00", "end": "02:00", "hosts": ["h"], "days": ["someday"]}]},
        {"scanners": ["10.0.0.0/33"]},
        {"admin_accounts": ["CORP\\ksmith"], "helpdesk_accounts": ["ksmith"]},
        {"jump_hosts": [{"ips": ["10.0.0.1"]}]},
    ],
)
def test_a_malformed_declaration_is_refused(bad: Dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TenantContext.model_validate(bad)
    with pytest.raises(DatasetError, match="invalid _meta.tenant_context"):
        parse_dataset(_dataset({"tenant_context": bad}))


def test_a_configured_scanner_must_be_a_declared_one() -> None:
    meta = {"tenant_settings": {"triage": {"known_scanners": ["10.20.5.10"]}}, "tenant_context": {"scanners": []}}
    with pytest.raises(DatasetError, match="does not declare"):
        parse_dataset(_dataset(meta))
    meta["tenant_context"] = {"scanners": ["10.20.5.10"]}
    dataset = parse_dataset(_dataset(meta))
    assert dataset.tenant_context is not None and dataset.tenant_context.scanners == ["10.20.5.10"]
    assert parse_dataset(json.dumps(ITEM)).tenant_context is None


def _alert(**fields: Any) -> Dict[str, Any]:
    return {"occurred_at": "2026-10-21T03:00:00+00:00", "entities": {}, "raw": {}, **fields}


def test_matches_read_entities_acting_users_and_time() -> None:
    context = TenantContext(
        admin_accounts=["adm.ksmith"], helpdesk_accounts=["hd.ochen"], automation_hosts=["build-01"],
        jump_hosts=[{"host": "IT-WS-01", "ips": ["10.20.1.120"]}],  # type: ignore[list-item]
        patch_windows=[PatchWindow(name="n", start="01:00", end="05:00", hosts=["db-01"])],
        scanners=["10.20.5.0/24", "scan-02"],
    )
    assert context_matches(context, _alert(entities={"users": ["CORP\\ADM.KSMITH"]})) == ["admin_account"]
    sysmon = {"data": {"win": {"eventdata": {"user": "CORP\\hd.ochen"}}}}
    assert context_matches(context, _alert(raw=sysmon)) == ["helpdesk_account"]
    assert context_matches(context, _alert(entities={"ips": ["10.20.1.120"]})) == ["jump_host"]
    assert context_matches(context, _alert(entities={"hosts": ["BUILD-01"]})) == ["automation_host"]
    assert context_matches(context, _alert(entities={"hosts": ["db-01"]})) == ["patch_window"]
    assert context_matches(context, _alert(entities={"hosts": ["db-01"]}, occurred_at="2026-10-21T06:00:00Z")) == []
    assert context_matches(context, _alert(entities={"hosts": ["db-02"]})) == []
    assert context_matches(context, _alert(entities={"ips": ["10.20.5.77", "not-an-ip"]})) == ["scanner"]
    assert context_matches(context, _alert(entities={"hosts": ["scan-02"]})) == ["scanner"]
    assert context_matches(context, {"occurred_at": "garbage", "entities": "x"}) == []


def test_a_window_across_midnight_belongs_to_the_day_it_opened() -> None:
    window = PatchWindow(name="sat-night", start="23:00", end="02:00", days=["sat"], hosts=["db-01"])
    saturday_late = datetime(2026, 10, 24, 23, 30, tzinfo=UTC)  # a Saturday
    sunday_early = datetime(2026, 10, 25, 1, 30, tzinfo=UTC)
    sunday_late = datetime(2026, 10, 25, 23, 30, tzinfo=UTC)
    monday_early = datetime(2026, 10, 26, 1, 30, tzinfo=UTC)
    assert window.covers(saturday_late, ["db-01"]) and window.covers(sunday_early, ["DB-01"])
    assert not window.covers(sunday_late, ["db-01"]) and not window.covers(monday_early, ["db-01"])
    assert not window.covers(saturday_late, ["web-01"])


def test_corpus_v1_declares_its_estate_and_the_context_covers_attacks_too() -> None:
    """The artifact behind docs/evaluation.md#declared-tenant-context: closable with context against not closable."""
    dataset = load_dataset(CORPUS)
    context = dataset.tenant_context
    assert context is not None and context.scanners == ["10.20.5.10"]
    assert set(context.declared()) == set(CONTEXT_KINDS)
    coverage = context_coverage(dataset)
    benign = [i for i in dataset.items if i.expected.disposition == "benign"]
    lookalikes = [i for i in benign if "kind:lookalike" in i.tags]
    malicious = [i for i in dataset.items if i.expected.disposition == "malicious"]
    covered = Counter(bool(coverage[i.id]) for i in lookalikes)
    assert (covered[True], len(lookalikes)) == (75, 126)
    assert sum(bool(coverage[i.id]) for i in benign) == 168
    # Context is a fact, not a verdict: 47 of the 208 attacks touch it as well.
    assert sum(bool(coverage[i.id]) for i in malicious) == 47
    scan = [i for i in lookalikes if "scenario:lookalike:vulnerability-scan" in i.tags]
    assert all("scanner" in coverage[i.id] for i in scan)
