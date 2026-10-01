"""The tester and verdict tools (design Phase 0.5): whoami, get_verdict, list_actions, get_action,
ingest_test_alerts, wait_for_verdict and get_test_run.

Every tool is composed client-side from REST endpoints that exist today,
called with the configured API key, so the API enforces scopes, RBAC,
tenancy and audit as for any client:

* ``GET /auth/me`` (any key), ``GET /alerts``, ``GET /alerts/{id}``,
  ``GET /alerts/{id}/events``, ``GET /escalations``, ``GET /escalations/{id}``,
  ``GET /actions`` and ``GET /actions/{id}`` (``read`` scope);
* ``POST /ingest/alerts`` (``ingest`` scope), for ``ingest_test_alerts`` only.

None of these tools approves, rejects, rolls back, retries, decides or
configures anything: those REST routes refuse API keys, and no tool calls
them. Results separate ``trusted`` LG-SOTF data (ids, enums, numbers,
timestamps) from ``untrusted`` alert-derived text, and fields the REST API
does not expose to an API key are listed under ``unavailable`` rather than
guessed (see :mod:`lg_sotf.mcp.shaping` and :mod:`lg_sotf.mcp.runs`).
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from typing import Annotated, Any, Dict, List, Literal, Mapping, Optional, Tuple
from urllib.parse import quote

from pydantic import Field, field_validator, model_validator

from lg_sotf import __version__
from lg_sotf.mcp.base import (
    _CURSOR_SCHEMA,
    _RUN_HANDLE_SCHEMA,
    CATALOG_VERSION,
    ID_PATTERN,
    MAX_CURSOR,
    RUN_HANDLE_PATTERN,
    SUPPORTED_PROTOCOL_VERSIONS,
    UUID_PATTERN,
    Tool,
    ToolContext,
    ToolError,
    _Args,
    _enum_list,
    _id_schema,
    _limit_schema,
    _object,
    _seg,
)
from lg_sotf.mcp.client import ApiCallError, json_params
from lg_sotf.mcp.runs import (
    DISPOSITIONS,
    MAX_TEST_ITEMS,
    ROUTES,
    Expected,
    Outcome,
    Run,
    RunItem,
    agreement,
    choice,
    code,
    contamination,
    coverage,
    decide_step,
    needs_timeline,
    now_utc,
    number,
    outcome_of,
    score,
)
from lg_sotf.mcp.shaping import RESULT_BUDGET, Shaped, mapping

ACTION_STATUSES = [
    "proposed", "awaiting_approval", "approved", "rejected", "executing", "succeeded", "failed", "dry_run", "blocked"
]
RISKS = ["low", "medium", "high", "critical"]
VERIFICATIONS = ["pending", "verified", "failed", "inconclusive"]
ActionStatus = Literal[
    "proposed", "awaiting_approval", "approved", "rejected", "executing", "succeeded", "failed", "dry_run", "blocked"
]
Risk = Literal["low", "medium", "high", "critical"]
VerificationState = Literal["pending", "verified", "failed", "inconclusive"]
DispositionLabel = Literal["malicious", "benign", "inconclusive"]
RouteLabel = Literal["escalate", "plan_response", "close"]
ACTION_TYPE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
LABEL_PATTERN = r"^[A-Za-z0-9_.:-]{1,32}$"
SPLIT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
"""A dataset split: the rule ``lg-sotf eval`` applies (:mod:`lg_sotf.eval.dataset`), so a dataset line fits as is."""
MAX_ACTION_PAGE = 25
MAX_WAIT_IDS = 20
WAIT_DEFAULT_S = 45
WAIT_MAX_S = 110
WAIT_GRACE_S = 5
MAX_CONCURRENT_WAITS = 2
"""Waits running at once in one session (design §10): the other request slots stay free for fast tools."""
RETRY_AFTER_S = 10
MAX_ALERT_JSON_CHARS = 32_768
MAX_SOURCE_ALERT_ID_CHARS = 200
TIMELINE_PAGE = 200

UNAVAILABLE_WHOAMI = {
    "tenant.name": "GET /tenant/settings is admin-only; API keys cannot read the tenant name",
    "grantable_scopes": "OAuth consent arrives in Phase 2; an API key's scopes are fixed when it is created",
    "flags.install_dry_run": (
        "GET /tenant/response/routes is admin-only. Phase 0.5 relies on the operator: the install must run with "
        "LG_SOTF_RESPONSE__DRY_RUN unset or true (docs/mcp.md, operator runbook)"
    ),
    "flags.tenant_dry_run": "GET /tenant/settings is admin-only",
    "flags.qa_tenant": "the qa_tenant flag arrives with server-side QA runs (Phase 1a)",
    "flags.mcp_enabled": "api.mcp.* settings arrive in Phase 1a; the stdio server needs no server-side switch",
    "limits.budget_headroom": "QA item, LLM-spend and write budgets arrive in Phase 1a",
    "versions.api": "the REST API does not publish its version to clients",
}


# ----------------------------------------------------------------- arguments


class NoArgs(_Args):
    pass


class VerdictArgs(_Args):
    alert_id: str = Field(pattern=ID_PATTERN)


class ListActionsArgs(_Args):
    alert_id: Optional[str] = Field(default=None, pattern=ID_PATTERN)
    run_handle: Optional[str] = Field(default=None, pattern=RUN_HANDLE_PATTERN)
    status: Optional[List[ActionStatus]] = Field(default=None, max_length=9)
    risk_level: Optional[List[Risk]] = Field(default=None, max_length=4)
    verification: Optional[List[VerificationState]] = Field(default=None, max_length=4)
    action_type: Optional[str] = Field(default=None, pattern=ACTION_TYPE_PATTERN)
    limit: int = Field(default=10, ge=1, le=MAX_ACTION_PAGE)
    cursor: Optional[str] = Field(default=None, min_length=1, max_length=MAX_CURSOR)

    @model_validator(mode="after")
    def _cursor_without_run(self) -> ListActionsArgs:
        if self.run_handle is not None and self.cursor is not None:
            raise ValueError("cursor cannot be combined with run_handle")
        return self


class ActionIdArgs(_Args):
    action_id: str = Field(pattern=UUID_PATTERN)


class ExpectedArgs(_Args):
    disposition: Optional[DispositionLabel] = None
    route: Optional[RouteLabel] = None
    escalation: Optional[bool] = None


class TestItemArgs(_Args):
    """One test item: a line of an evaluation dataset (``tests/fixtures/eval/*.jsonl``) fits as is.

    ``tags``, ``notes``, ``source_config`` and ``labels`` (annotators' labels)
    are accepted and ignored.
    """

    id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    source_type: str = Field(default="canonical", pattern=LABEL_PATTERN)
    alert: Dict[str, Any]
    expected: Optional[ExpectedArgs] = None
    split: Optional[str] = Field(default=None, pattern=SPLIT_PATTERN)
    tags: Optional[List[Annotated[str, Field(max_length=64)]]] = Field(default=None, max_length=32)
    notes: Optional[str] = Field(default=None, max_length=4_000)
    source_config: Optional[Dict[str, Any]] = None
    labels: Optional[List[Dict[str, Any]]] = Field(default=None, max_length=32)

    @field_validator("alert")
    @classmethod
    def _bounded(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if len(json.dumps(value, default=str)) > MAX_ALERT_JSON_CHARS:
            raise ValueError(f"an alert may be at most {MAX_ALERT_JSON_CHARS} characters of JSON")
        return value


class IngestTestArgs(_Args):
    items: List[TestItemArgs] = Field(min_length=1, max_length=MAX_TEST_ITEMS)


class WaitArgs(_Args):
    alert_ids: Optional[List[Annotated[str, Field(pattern=ID_PATTERN)]]] = Field(
        default=None, min_length=1, max_length=MAX_WAIT_IDS
    )
    run_handle: Optional[str] = Field(default=None, pattern=RUN_HANDLE_PATTERN)
    timeout_s: int = Field(default=WAIT_DEFAULT_S, ge=0, le=WAIT_MAX_S)

    @model_validator(mode="after")
    def _one_target(self) -> WaitArgs:
        if (self.alert_ids is None) == (self.run_handle is None):
            raise ValueError("give either alert_ids or run_handle")
        return self


class TestRunArgs(_Args):
    run_handle: str = Field(pattern=RUN_HANDLE_PATTERN)
    limit: int = Field(default=10, ge=1, le=MAX_ACTION_PAGE)
    cursor: Optional[str] = Field(default=None, pattern=r"^[0-9]{1,4}$")


# ------------------------------------------------------------------- helpers


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _time(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def alert_url(base_url: str, alert_id: str) -> str:
    """A plain link to the alert in the LG-SOTF UI (served at the API's address). Never pre-authenticated."""
    return f"{base_url}/alerts?alert={quote(alert_id, safe='')}"


async def _page(ctx: ToolContext, path: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
    return mapping(await ctx.api.get(path, json_params(dict(params))))


def _items(page: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    items = page.get("items")
    return [mapping(i) for i in items] if isinstance(items, list) else []


async def read_outcome(ctx: ToolContext, alert_id: str) -> Tuple[Mapping[str, Any], Outcome]:
    """The alert and its outcome; for a terminal alert also its route (timeline) and pending actions."""
    alert = mapping(await ctx.api.get(f"/api/v1/alerts/{_seg(alert_id)}"))
    outcome = outcome_of(alert)
    if outcome.terminal:
        if needs_timeline(alert):
            events = await _page(ctx, f"/api/v1/alerts/{_seg(alert_id)}/events", {"limit": TIMELINE_PAGE})
            outcome = outcome_of(alert, decide_step(_items(events)))
        pending = await _page(
            ctx, "/api/v1/actions", {"alert_id": alert_id, "status": ["awaiting_approval"], "limit": MAX_ACTION_PAGE}
        )
        outcome.pending_actions = len(_items(pending))
    observe(ctx, alert, outcome)
    return alert, outcome


def observe(ctx: ToolContext, alert: Mapping[str, Any], outcome: Outcome) -> None:
    """Remember what was read about an alert that belongs to a test run of this session."""
    ctx.runs.record(outcome, _text(alert.get("title")))


def action_record(base_url: str, action: Mapping[str, Any], *, detail: bool = False) -> Dict[str, Any]:
    """One ledger row as ``{trusted, untrusted}`` (design §6: approval, rehearsal, dispatched vs verified)."""
    status = code(action.get("status"))
    connector = code(action.get("connector"))
    if connector == "dry_run" or status == "dry_run":
        rehearsal: Optional[bool] = True
    elif connector is not None:
        rehearsal = False
    else:
        rehearsal = None  # not routed yet (still waiting for approval, or blocked before routing)
    executed_at = _time(action.get("executed_at"))
    approved_by = code(action.get("approved_by"))
    if status in ("proposed", "awaiting_approval"):
        approval = "pending"
    elif status in ("rejected", "blocked"):
        approval = status
    elif approved_by is not None or action.get("approved_at"):
        approval = "approved"
    else:
        approval = "not_required"
    rollback = mapping(action.get("rollback"))
    alert_id = str(action.get("alert_id") or "")
    blocked = action.get("blocked_reason")
    rollback_reason = rollback.get("reason")
    trusted: Dict[str, Any] = {
        "id": action.get("id"),
        "alert_id": alert_id,
        "action_type": code(action.get("action_type")),
        "status": status,
        "risk_level": code(action.get("risk_level")),
        "approval": {"state": approval, "approved_by": approved_by, "approved_at": _time(action.get("approved_at"))},
        "requested_by": code(action.get("requested_by")),
        "connector": connector,
        "rehearsal": rehearsal,
        "dispatched": bool(executed_at) and rehearsal is False,
        "executed_at": executed_at,
        "attempts": _int(action.get("attempts")),
        "execution_owner": code(action.get("execution_owner")),
        "blocked_reason": code(blocked),
        "verification": {
            "state": choice(action.get("verification"), VERIFICATIONS),
            "verified_at": _time(action.get("verified_at")),
            "deadline": _time(action.get("verify_deadline")),
        },
        "rollback": {
            "available": bool(rollback.get("available")),
            "action_type": code(rollback.get("action_type")),
            "risk": code(rollback.get("risk")),
            "until": _time(rollback.get("until")),
            "reason": code(rollback_reason),
        },
        "rolled_back_by": action.get("rolled_back_by"),
        "rollback_of": action.get("rollback_of"),
        "created_at": _time(action.get("created_at")),
        "updated_at": _time(action.get("updated_at")),
        "approval_url": alert_url(base_url, alert_id) if approval == "pending" and alert_id else None,
    }
    untrusted: Dict[str, Any] = {"target": action.get("target"), "params": action.get("params") or {}}
    if blocked and code(blocked) is None:
        untrusted["blocked_reason"] = blocked
    if rollback_reason and code(rollback_reason) is None:
        untrusted["rollback_reason"] = rollback_reason
    result = mapping(action.get("result"))
    if detail:
        untrusted["result"] = dict(result)
        untrusted["verification_detail"] = dict(mapping(action.get("verification_detail")))
    elif result.get("summary") is not None:
        untrusted["result_summary"] = result.get("summary")
    return {"trusted": trusted, "untrusted": untrusted}


# ------------------------------------------------------------------- handlers


async def _whoami(ctx: ToolContext, _args: NoArgs) -> Shaped:
    me = mapping(await ctx.api.get("/api/v1/auth/me"))
    scopes = sorted(s for s in (me.get("scopes") or []) if isinstance(s, str))
    is_key = me.get("kind") == "api_key"
    warnings: List[str] = []
    if is_key and "ingest" not in scopes:
        warnings.append("the key lacks the 'ingest' scope: ingest_test_alerts will be refused")
    if is_key and "read" not in scopes:
        warnings.append("the key lacks the 'read' scope: every read tool will be refused")
    if "write" in scopes:
        warnings.append("the key has the 'write' scope (add_note); a tester key needs only 'ingest' and 'read'")
    if me.get("tenant_id") != me.get("home_tenant_id"):
        warnings.append("acting on a tenant other than the credential's home tenant")
    trusted = {
        "principal": {
            "kind": code(me.get("kind")),
            "api_key_id": me.get("api_key_id"),
            "user_id": me.get("user_id"),
            "role": code(me.get("role")),
            "auth_method": code(me.get("auth_method")),
            "is_platform_admin": bool(me.get("is_platform_admin")),
        },
        "tenant": {"tenant_id": me.get("tenant_id"), "home_tenant_id": me.get("home_tenant_id")},
        "scopes": scopes,
        "flags": {
            "can_send_test_alerts": is_key and {"ingest", "read"} <= set(scopes),
            "can_add_notes": "write" in scopes,
            "can_approve_or_decide": False,
        },
        "limits": {
            "max_test_items": MAX_TEST_ITEMS,
            "max_wait_alert_ids": MAX_WAIT_IDS,
            "max_concurrent_waits": MAX_CONCURRENT_WAITS,
            "wait_timeout_s": {"default": WAIT_DEFAULT_S, "max": WAIT_MAX_S},
            "poll_interval_s": ctx.poll_interval_s,
            "max_output_chars": ctx.max_output_chars,
            "result_budget_chars": min(ctx.max_output_chars, RESULT_BUDGET),
            "runs_in_memory": len(ctx.runs),
            "max_runs_in_memory": ctx.runs.max_runs,
        },
        "versions": {
            "server": __version__,
            "catalog": CATALOG_VERSION,
            "protocol": ctx.protocol_version,
            "supported_protocols": list(SUPPORTED_PROTOCOL_VERSIONS),
        },
        "api_url": ctx.api.base_url,
        "warnings": warnings,
    }
    return Shaped("whoami", {"trusted": trusted, "untrusted": {"email": me.get("email")},
                             "unavailable": dict(UNAVAILABLE_WHOAMI)}, drops=("unavailable",))


async def _get_verdict(ctx: ToolContext, a: VerdictArgs) -> Shaped:
    alert = mapping(await ctx.api.get(f"/api/v1/alerts/{_seg(a.alert_id)}"))
    summary = mapping(alert.get("summary"))
    decision = mapping(summary.get("decision"))
    decide: Mapping[str, Any] = {}
    if needs_timeline(alert):
        events = await _page(ctx, f"/api/v1/alerts/{_seg(a.alert_id)}/events", {"limit": TIMELINE_PAGE})
        decide = mapping(decide_step(_items(events)))
    outcome = outcome_of(alert, decide)
    actions = _items(await _page(ctx, "/api/v1/actions", {"alert_id": a.alert_id, "limit": MAX_ACTION_PAGE}))
    if outcome.terminal:
        outcome.pending_actions = sum(1 for x in actions if x.get("status") == "awaiting_approval")
    observe(ctx, alert, outcome)
    escalations = _items(await _page(ctx, "/api/v1/escalations", {"alert_id": a.alert_id, "limit": 10}))
    escalation_ids = [e for e in [outcome.escalation_id] if e]
    for escalation in escalations:
        if isinstance(escalation.get("id"), str) and escalation["id"] not in escalation_ids:
            escalation_ids.append(escalation["id"])
    analysis = mapping(summary.get("analysis"))
    triage = mapping(summary.get("triage"))
    usage = mapping(summary.get("llm_usage"))
    reasoning = [r for r in (analysis.get("reasoning") or []) if isinstance(r, str)][:10]
    parts = []
    if _text(analysis.get("conclusion")):
        parts.append(f"Conclusion: {analysis['conclusion']}")
    if reasoning:
        parts.append("Reasoning: " + " | ".join(reasoning))
    if _text(triage.get("reasoning")):
        parts.append(f"Triage: {triage['reasoning']}")
    trusted = {
        "alert_id": outcome.alert_id,
        "status": code(alert.get("status")),
        "severity": outcome.severity,
        "disposition": outcome.disposition,
        "predicted": outcome.predicted,
        "verdict": outcome.verdict,
        "confidence": outcome.confidence,
        "threat_score": number(alert.get("threat_score")),
        "priority": _int(alert.get("priority")),
        "route": outcome.route,
        "decision_code": outcome.decision_code,
        "close_reason": outcome.close_reason,
        "escalated": outcome.escalated,
        "escalation_ids": escalation_ids,
        "approval_requested": outcome.approval_requested,
        "actions": [
            {"id": x.get("id"), "action_type": code(x.get("action_type")), "status": code(x.get("status")),
             "risk_level": code(x.get("risk_level"))}
            for x in actions
        ],
        "pending_actions": sum(1 for x in actions if x.get("status") == "awaiting_approval"),
        "models": outcome.models,
        "llm_usage": {k: number(usage.get(k)) for k in ("calls", "input_tokens", "output_tokens", "total_tokens",
                                                         "cost_usd")},
        "llm_budget_exceeded": bool(summary.get("llm_budget_exceeded")),
        "analysis": {"threat_score": number(analysis.get("threat_score")), "certainty": number(analysis.get("certainty")),
                     "stop_reason": code(analysis.get("stop_reason")), "llm_used": analysis.get("llm_used") is True},
        "source_id": code(alert.get("source_id")),
        "ingested_at": _time(alert.get("ingested_at")),
        "updated_at": _time(alert.get("updated_at")),
        "closed_at": _time(alert.get("closed_at")),
        "alert_url": alert_url(ctx.api.base_url, outcome.alert_id),
    }
    untrusted = {
        "title": alert.get("title"),
        "source_alert_id": alert.get("source_alert_id"),
        "category": alert.get("category"),
        "decision_reason": decision.get("reason") or decide.get("reason"),
        "reasoning_summary": "\n".join(parts),
        "recommended_actions": [r for r in (analysis.get("recommended_actions") or []) if isinstance(r, str)][:10],
    }
    return Shaped(
        "get_verdict",
        {"trusted": trusted, "untrusted": untrusted},
        drops=("untrusted.recommended_actions", "untrusted.reasoning_summary", "trusted.actions"),
    )


async def _list_actions(ctx: ToolContext, a: ListActionsArgs) -> Shaped:
    filters = {"status": a.status, "risk_level": a.risk_level, "verification": a.verification,
               "action_type": a.action_type, "limit": a.limit}
    omitted: List[str] = []
    next_cursor: Optional[str] = None
    if a.run_handle is not None:
        run = ctx.runs.get(a.run_handle)
        alert_ids = run.alert_ids()
        if a.alert_id is not None:
            if a.alert_id not in alert_ids:
                raise ToolError("alert_id is not an alert of this run")
            alert_ids = [a.alert_id]
        rows: List[Mapping[str, Any]] = []
        more: List[str] = []  # alerts with more matching actions than the page read for them
        for alert_id in alert_ids:
            page = await _page(ctx, "/api/v1/actions", {**filters, "alert_id": alert_id})
            rows.extend(_items(page))
            if _text(page.get("next_cursor")):
                more.append(alert_id)
        rows.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
        if len(rows) > a.limit:
            omitted.append(f"items[{a.limit}:{len(rows)}]")
            rows = rows[: a.limit]
        for alert_id in more:
            omitted.append(
                f"more actions of alert {alert_id} than the {a.limit} read: list_actions(alert_id='{alert_id}') "
                "without run_handle pages through them"
            )
    else:
        page = await _page(ctx, "/api/v1/actions", {**filters, "alert_id": a.alert_id, "cursor": a.cursor})
        rows = _items(page)
        next_cursor = page.get("next_cursor") if isinstance(page.get("next_cursor"), str) else None
    body = {"items": [action_record(ctx.api.base_url, r) for r in rows], "next_cursor": next_cursor}
    return Shaped(
        "list_actions",
        body,
        drops=("items[*].untrusted.params", "items[*].untrusted.result_summary", "items[*].untrusted.target"),
        pageable="items",
        omitted=omitted,
        cursor=None if a.run_handle is not None else "keyset",
    )


async def _get_action(ctx: ToolContext, a: ActionIdArgs) -> Shaped:
    action = mapping(await ctx.api.get(f"/api/v1/actions/{_seg(a.action_id)}"))
    return Shaped(
        "get_action",
        action_record(ctx.api.base_url, action, detail=True),
        drops=("untrusted.verification_detail", "untrusted.result", "untrusted.params"),
    )


def _source_alert_id(item: TestItemArgs, index: int) -> str:
    original = item.alert.get("source_alert_id", item.alert.get("id"))
    if isinstance(original, bool) or not isinstance(original, (str, int)) or str(original).strip() == "":
        original = item.id or f"item-{index + 1}"
    text = str(original).strip()
    if len(text) > MAX_SOURCE_ALERT_ID_CHARS:
        raise ToolError(f"items[{index}]: the alert id is longer than {MAX_SOURCE_ALERT_ID_CHARS} characters")
    return text


def _ingested_item(item: RunItem, duplicate_of: Dict[int, Optional[str]]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"index": item.index, "status": item.status, "alert_id": item.alert_id}
    if item.index in duplicate_of:
        entry["duplicate_of"] = duplicate_of[item.index]
    return entry


async def _ingest_test_alerts(ctx: ToolContext, a: IngestTestArgs) -> Shaped:
    foreign = Counter(item.source_type for item in a.items if item.source_type != "canonical")
    if foreign:
        counts = ", ".join(f"{name}: {n}" for name, n in sorted(foreign.items()))
        raise ToolError(
            f"refused: {sum(foreign.values())} of {len(a.items)} items are not canonical ({counts}). Phase 0.5 sends "
            "canonical items only (source_type 'canonical'); nothing was sent."
        )
    me = mapping(await ctx.api.get("/api/v1/auth/me"))
    scopes = {s for s in (me.get("scopes") or []) if isinstance(s, str)}
    if me.get("kind") != "api_key" or not {"ingest", "read"} <= scopes:
        raise ToolError(
            "the configured credential must be an API key with the 'ingest' and 'read' scopes (a tester key in a "
            "QA tenant; see docs/mcp.md); nothing was sent"
        )
    prior = _items(await _page(ctx, "/api/v1/alerts", {"limit": 1}))
    handle = ctx.runs.new_handle()
    events = []
    items: List[RunItem] = []
    for index, item in enumerate(a.items):
        source_alert_id = f"{_source_alert_id(item, index)}:{handle}"
        events.append({**item.alert, "source_alert_id": source_alert_id})
        expected = item.expected or ExpectedArgs()
        items.append(
            RunItem(
                index=index,
                source_alert_id=source_alert_id,
                status="rejected",
                item_id=item.id,
                split=item.split,
                expected=Expected(expected.disposition, expected.route, expected.escalation),
            )
        )
    created_at = now_utc()
    result = mapping(await ctx.api.post("/api/v1/ingest/alerts", {"alerts": events}))
    reasons: List[Dict[str, Any]] = []
    duplicate_of: Dict[int, Optional[str]] = {}
    for entry in _items(result):
        position = _int(entry.get("index"))
        if position is None or not 0 <= position < len(items):
            continue
        run_item = items[position]
        run_item.status = choice(entry.get("status"), ("inserted", "duplicate", "rejected")) or "rejected"
        alert_id = entry.get("alert_id")
        known = alert_id if isinstance(alert_id, str) and code(alert_id) else None
        # Only an inserted item has an alert of its own: a duplicate's alert was triaged for another item (or
        # an earlier send), so it is an error of this run, as in `lg-sotf eval`, never scored on that triage.
        run_item.alert_id = known if run_item.status == "inserted" else None
        if run_item.status == "duplicate":
            duplicate_of[position] = known
        run_item.reason = _text(entry.get("reason"))
    run = Run(
        handle=handle,
        tenant_id=str(me.get("tenant_id") or ""),
        created_at=created_at,
        prior_alerts=bool(prior),
        items=items,
        source_id=code(result.get("source_id")),
    )
    ctx.runs.add(run)
    warnings = []
    if prior:
        warnings.append(
            "the tenant already held alerts before this run, so get_test_run reports contaminated: true; use a "
            "fresh QA tenant for each run (docs/mcp.md)"
        )
    not_inserted = sum(1 for i in items if i.ingest_failed)
    if not_inserted:
        warnings.append(
            f"{not_inserted} items were not inserted (rejected, or a duplicate of an earlier item's source alert "
            "id) and are not scored: get_test_run counts them as errors. To send a line more than once, give each "
            "copy its own id"
        )
    if "write" in scopes:
        warnings.append("the key also has the 'write' scope; a tester key needs only 'ingest' and 'read'")
    for run_item in items:
        reasons.append({"index": run_item.index, "item_id": run_item.item_id,
                        "source_alert_id": run_item.source_alert_id, "reason": run_item.reason})
    trusted = {
        "run_handle": handle,
        "tenants": [run.tenant_id],
        "source_id": run.source_id,
        "received": _int(result.get("received")),
        "inserted": _int(result.get("inserted")),
        "duplicates": _int(result.get("duplicates")),
        "rejected": _int(result.get("rejected")),
        "enqueued": _int(result.get("enqueued")),
        "items": [_ingested_item(i, duplicate_of) for i in items],
        "prior_alerts": bool(prior),
        "warnings": warnings,
        "next": "wait_for_verdict(run_handle) until nothing is pending, then get_test_run(run_handle)",
    }
    return Shaped("ingest_test_alerts", {"trusted": trusted, "untrusted": {"items": reasons}},
                  drops=("untrusted.items",))


async def _wait_for_verdict(ctx: ToolContext, a: WaitArgs) -> Shaped:
    if ctx.active_waits >= MAX_CONCURRENT_WAITS:
        raise ToolError(
            f"{ctx.active_waits} waits are already running in this session (at most {MAX_CONCURRENT_WAITS}); "
            f"wait for one to return or retry later. retry_after_s: {RETRY_AFTER_S}"
        )
    ctx.active_waits += 1
    try:
        return await _wait(ctx, a)
    finally:
        ctx.active_waits -= 1


async def _wait(ctx: ToolContext, a: WaitArgs) -> Shaped:
    if a.run_handle is not None:
        run = ctx.runs.get(a.run_handle)
        ids = run.alert_ids()
        # A failed item is polled again: the worker may retry its run (runs.RETRIED_STATUSES).
        known = {i.alert_id: i.outcome for i in run.items if i.alert_id and i.outcome is not None and i.settled}
    else:
        ids = list(dict.fromkeys(a.alert_ids or []))
        known = {}
    done: Dict[str, Outcome] = {k: v for k, v in known.items() if k in ids}
    errors: Dict[str, str] = {}
    transient: Dict[str, str] = {}
    pending = [i for i in ids if i not in done]
    started = ctx.clock()
    deadline = started + a.timeout_s

    async def poll() -> None:
        first_round = True
        while pending:
            for alert_id in list(pending):
                if not first_round and ctx.clock() >= deadline:
                    break
                try:
                    _alert, outcome = await read_outcome(ctx, alert_id)
                except ApiCallError as exc:
                    if exc.status in (401, 403):
                        raise
                    if exc.status == 404:
                        errors[alert_id] = "not found in this tenant"
                        pending.remove(alert_id)
                    else:
                        transient[alert_id] = str(exc)
                    continue
                transient.pop(alert_id, None)
                if outcome.terminal:
                    done[alert_id] = outcome
                    pending.remove(alert_id)
            first_round = False
            remaining = deadline - ctx.clock()
            if not pending or remaining <= 0:
                return
            # About every poll_interval_s; slower for many alerts, so a wait stays well inside the API rate limit.
            await ctx.sleep(min(max(ctx.poll_interval_s, 0.2 * len(pending)), remaining))

    try:
        # A hard bound in real time as well, so slow API answers cannot stretch a wait past WAIT_MAX_S.
        async with asyncio.timeout(min(a.timeout_s + WAIT_GRACE_S, WAIT_MAX_S)):
            await poll()
    except TimeoutError:
        pass  # what finished so far is reported; the rest stays pending
    trusted = {
        "done": [done[i].digest() for i in ids if i in done],
        "pending": [i for i in ids if i in pending],
        "errors": [{"alert_id": k, "error": v} for k, v in errors.items()],
        "last_errors": [{"alert_id": k, "error": v} for k, v in transient.items() if k in pending],
        "retry_after_s": RETRY_AFTER_S if pending else None,
        "waited_s": round(max(ctx.clock() - started, 0.0), 1),
    }
    return Shaped("wait_for_verdict", {"trusted": trusted, "untrusted": {}}, pageable="trusted.done")


async def _get_test_run(ctx: ToolContext, a: TestRunArgs) -> Shaped:
    run = ctx.runs.get(a.run_handle)
    for alert_id in run.alert_ids():
        if any(not i.settled for i in run.items if i.alert_id == alert_id):
            try:
                await read_outcome(ctx, alert_id)
            except ApiCallError as exc:
                if exc.status != 404:
                    raise
                for item in run.items:
                    if item.alert_id == alert_id and not item.settled:
                        item.outcome = Outcome(alert_id=alert_id, status="missing")
    escalation_times: Dict[str, Optional[str]] = {}
    for item in run.items:
        escalation_id = item.outcome.escalation_id if item.outcome else None
        if escalation_id and item.escalation_created_at is None:
            if escalation_id not in escalation_times:
                try:
                    escalation = mapping(await ctx.api.get(f"/api/v1/escalations/{_seg(escalation_id)}"))
                except ApiCallError as exc:
                    if exc.status != 404:
                        raise
                    escalation = {}
                escalation_times[escalation_id] = _time(escalation.get("created_at"))
            item.escalation_created_at = escalation_times[escalation_id]
    mismatches = []
    for item in run.items:
        if item.outcome is None or item.outcome.error:
            continue
        agrees, fields = agreement(item)
        if agrees is False:
            outcome = item.outcome
            mismatches.append({
                "trusted": {
                    "index": item.index,
                    "alert_id": item.alert_id,
                    "split": item.split,
                    "status": outcome.status,
                    "expected": item.expected.as_dict(),
                    "got": {"disposition": outcome.predicted, "route": outcome.route,
                            "escalation": outcome.escalated or outcome.approval_requested},
                    "fields": fields,
                    "confidence": outcome.confidence,
                    "decision_code": outcome.decision_code,
                },
                "untrusted": {"item_id": item.item_id, "title": item.title},
            })
    offset = int(a.cursor or 0)
    page = mismatches[offset : offset + a.limit]
    next_cursor = str(offset + a.limit) if offset + a.limit < len(mismatches) else None
    models = sorted({m for i in run.items if i.outcome for m in i.outcome.models})
    state = contamination(run)
    trusted = {
        "run_handle": run.handle,
        "tenants": [run.tenant_id],
        "created_at": run.created_at.isoformat(),
        "started_at": state.pop("started_at"),
        "metrics": score(run),
        "coverage": coverage(run),
        "model_snapshot": models,
        "contaminated": state.pop("contaminated"),
        "contamination": state,
        "pending": [i.alert_id for i in run.items if i.alert_id and i.outcome is None],
        "error_items": [
            {"index": i.index, "alert_id": i.alert_id, "status": i.outcome.status if i.outcome else i.status}
            for i in run.items
            if i.ingest_failed or (i.outcome is not None and i.outcome.error)
        ],
    }
    unavailable = {
        "gate": "the deployed-path gate (pass, fail or not_applicable) needs server-side runs (Phase 1a)",
        "coverage.vendor_formats": "Phase 0.5 sends canonical items only",
        "latency": "queue-to-terminal latency needs the node.completed events of server-side runs (Phase 1a)",
    }
    return Shaped(
        "get_test_run",
        {"trusted": trusted, "mismatches": page, "next_cursor": next_cursor, "unavailable": unavailable},
        drops=("mismatches[*].untrusted",),
        pageable="mismatches",
        cursor="offset",
        cursor_offset=offset,
    )


# --------------------------------------------------------------------- tools

_ACTION_FILTERS = {
    "status": _enum_list(ACTION_STATUSES, "Action statuses to include."),
    "risk_level": _enum_list(RISKS, "Risk levels to include."),
    "verification": _enum_list(VERIFICATIONS, "Verification states to include."),
    "action_type": {"type": "string", "pattern": ACTION_TYPE_PATTERN, "maxLength": 64,
                    "description": "Only this action type (for example isolate_host)."},
}

_TEST_ITEM_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["alert"],
    "properties": {
        "id": {"type": "string", "maxLength": 128, "description": "Dataset item id, kept for the report."},
        "source_type": {"type": "string", "pattern": LABEL_PATTERN, "maxLength": 32, "default": "canonical",
                        "description": "Must be 'canonical'."},
        "alert": {"type": "object", "description": "A canonical alert as POST /ingest/alerts takes it "
                  "(title, severity, description, entities, ...)."},
        "expected": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "disposition": {"type": "string", "enum": list(DISPOSITIONS)},
                "route": {"type": "string", "enum": list(ROUTES)},
                "escalation": {"type": "boolean"},
            },
            "description": "Expected labels, used by get_test_run.",
        },
        "split": {"type": "string", "pattern": SPLIT_PATTERN, "maxLength": 128,
                  "description": "Dataset split (standard, adversarial)."},
        "tags": {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 32},
        "notes": {"type": "string", "maxLength": 4000},
        "source_config": {"type": "object", "description": "Ignored for canonical items."},
        "labels": {"type": "array", "items": {"type": "object"}, "maxItems": 32,
                   "description": "Annotators' labels of an evaluation dataset; ignored."},
    },
}

TESTER_TOOLS = (
    Tool(
        name="whoami",
        title="Who am I",
        description=(
            "Who the configured API key is: tenant, scopes, whether it can send test alerts, and this server's "
            "limits and versions. Facts the REST API does not expose to API keys (install and tenant dry-run state, "
            "QA flags, budgets) are listed under 'unavailable' instead of guessed. Call it first to confirm you are "
            "connected to the intended non-production install and tenant."
        ),
        args=NoArgs,
        input_schema=_object({}),
        handler=_whoami,
    ),
    Tool(
        name="get_verdict",
        title="Get verdict",
        description=(
            "Compact triage digest of one alert: status, disposition, predicted disposition, confidence, route "
            "(escalate, plan_response or close), decision code, escalation and action ids, models and token use, "
            "and a reasoning summary of at most 2,000 characters (untrusted: derived from alert content). Use "
            "get_alert for the full record."
        ),
        args=VerdictArgs,
        input_schema=_object({"alert_id": _id_schema("Alert id.")}, ["alert_id"]),
        handler=_get_verdict,
    ),
    Tool(
        name="list_actions",
        title="List response actions",
        description=(
            "The response-action ledger, newest first: type, risk, approval state, rehearsal (dry-run) flag, "
            "whether a live connector dispatched it, verification and rollback state, and approval_url, a plain "
            "link to the alert in the LG-SOTF UI. Filter by alert_id, status, risk_level, verification or "
            "action_type, or pass a test run's run_handle to list the actions of its alerts (omitted names an "
            "alert with more actions than limit). This tool cannot approve, reject, roll back or retry anything: "
            "a person does that in LG-SOTF."
        ),
        args=ListActionsArgs,
        input_schema=_object(
            {
                "alert_id": _id_schema("Only actions of this alert."),
                "run_handle": _RUN_HANDLE_SCHEMA,
                **_ACTION_FILTERS,
                "limit": _limit_schema(10, MAX_ACTION_PAGE),
                "cursor": {**_CURSOR_SCHEMA, "description": f"{_CURSOR_SCHEMA['description']} Not with run_handle."},
            }
        ),
        handler=_list_actions,
    ),
    Tool(
        name="get_action",
        title="Get response action",
        description=(
            "One response action from the ledger: the list_actions fields plus the connector result and the "
            "verification detail. Read-only: approvals happen only in LG-SOTF."
        ),
        args=ActionIdArgs,
        input_schema=_object(
            {"action_id": {"type": "string", "pattern": UUID_PATTERN, "maxLength": 36, "description": "Action id."}},
            ["action_id"],
        ),
        handler=_get_action,
    ),
    Tool(
        name="ingest_test_alerts",
        title="Send test alerts",
        description=(
            "Send up to 25 canonical test alerts, each optionally with expected labels, and start a test run. "
            "Each item is {\"alert\": <canonical alert>, \"expected\": {\"disposition\", \"route\", \"escalation\"}, "
            "\"id\", \"split\"}: a line of tests/fixtures/eval/*.jsonl fits as is. Only source_type 'canonical' is "
            "accepted; any other item refuses the whole call with a count per source_type. Source alert ids get the suffix "
            "':<run_handle>'. Needs an API key with the 'ingest' and 'read' scopes. Call it only when the user "
            "asked to send test alerts, and only against a dry-run dev or UAT install (check whoami): the alerts "
            "are triaged like real ones. Returns a run_handle for wait_for_verdict, list_actions and get_test_run; "
            "it lives in this server's memory only."
        ),
        args=IngestTestArgs,
        input_schema=_object(
            {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_TEST_ITEMS,
                    "items": _TEST_ITEM_SCHEMA,
                    "description": "Test items (at most 25).",
                }
            },
            ["items"],
        ),
        handler=_ingest_test_alerts,
        read_only=False,
    ),
    Tool(
        name="wait_for_verdict",
        title="Wait for verdicts",
        description=(
            "Wait until alerts reach a terminal state (closed, waiting_human, waiting_approval or failed). Pass up "
            "to 20 alert_ids, or the run_handle of a test run (not both). Polls about every 2 s for at most "
            "timeout_s seconds (default 45, max 110; keep it at most 50 for clients with a 60 s tool timeout). "
            "Returns done (status, disposition, predicted disposition, route, confidence, pending actions, models), "
            "the ids still pending and retry_after_s; call again for the pending ones. Put every id in one call: at "
            "most 2 waits run at once."
        ),
        args=WaitArgs,
        input_schema=_object(
            {
                "alert_ids": {
                    "type": "array",
                    "items": {"type": "string", "pattern": ID_PATTERN, "maxLength": 256},
                    "minItems": 1,
                    "maxItems": MAX_WAIT_IDS,
                    "uniqueItems": True,
                    "description": "Alert ids (at most 20).",
                },
                "run_handle": _RUN_HANDLE_SCHEMA,
                "timeout_s": {"type": "integer", "minimum": 0, "maximum": WAIT_MAX_S, "default": WAIT_DEFAULT_S,
                              "description": "Longest wait in seconds."},
            }
        ),
        handler=_wait_for_verdict,
    ),
    Tool(
        name="get_test_run",
        title="Get test run",
        description=(
            "Score a test run against its expected labels, client-side from what LG-SOTF did: disposition accuracy, "
            "route and escalation accuracy, agreement rate (disposition and, where labelled, route), confusion "
            "matrix, coverage per split, models seen, a contaminated flag (the tenant held alerts before the run, or "
            "an item joined an escalation created before it: use a fresh tenant per run) and paged mismatches. "
            "Items still processing are listed as pending. There is no pass/fail gate before server-side runs."
        ),
        args=TestRunArgs,
        input_schema=_object(
            {
                "run_handle": _RUN_HANDLE_SCHEMA,
                "limit": _limit_schema(10, MAX_ACTION_PAGE),
                "cursor": {"type": "string", "pattern": r"^[0-9]{1,4}$", "maxLength": 4,
                           "description": "next_cursor from a previous page of mismatches."},
            },
            ["run_handle"],
        ),
        handler=_get_test_run,
    ),
)


__all__ = ["TESTER_TOOLS", "action_record", "alert_url", "read_outcome"]
