"""MCP tools: definitions, argument validation, API calls and result wrapping.

Each tool is composed of calls to the LG-SOTF REST API made with the
configured API key. Arguments are validated with Pydantic (unknown keys
refused, lengths capped) before anything is sent. The JSON Schemas
advertised in ``tools/list`` are written by hand so they stay small and
readable; ``tests/unit/mcp`` checks they match the models.

The eight original tools below each make one API call and return the API's
JSON. The tester and verdict tools (:mod:`lg_sotf.mcp.tester`) build
results that separate trusted LG-SOTF data from untrusted alert text.

Everything the API returns is derived from security alerts (titles,
descriptions, command lines, analyst notes) and may contain text written to
steer a language model. Every result is therefore wrapped between
``<untrusted_alert_data>`` delimiters under a header telling the model not
to follow instructions inside; every ``<`` and ``>`` in the JSON is escaped
as ``\\u003c`` / ``\\u003e`` and every invisible, bidi-control or control
character as a visible ``\\uXXXX`` escape (still valid JSON), so the data
cannot close the delimiter, open a tag of its own or hide text
(:mod:`lg_sotf.mcp.shaping`). The original tools' JSON parses back to
exactly what the API returned: an evidence pack still matches its
``bundle_sha256`` and signature. Results are capped at
``settings.mcp.max_output_chars``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple, Union

from pydantic import Field, ValidationError

from lg_sotf.mcp.base import (
    _CURSOR_SCHEMA,
    ID_PATTERN,
    MAX_CURSOR,
    MAX_LIMIT,
    Tool,
    ToolArgumentError,
    ToolContext,
    ToolError,
    _Args,
    _enum_list,
    _id_schema,
    _limit_schema,
    _object,
    _seg,
)
from lg_sotf.mcp.client import ApiCallError, LgSotfApiClient, json_params
from lg_sotf.mcp.runs import RunStore
from lg_sotf.mcp.shaping import (
    CLOSE_TAG,
    OPEN_TAG,
    TRUNCATION_NOTE,
    UNTRUSTED_HEADER,
    Shaped,
    escape_data,
    render,
    strip_invisible,
    wrap_untrusted,
)
from lg_sotf.mcp.tester import TESTER_TOOLS

AlertStatus = Literal["new", "queued", "processing", "waiting_human", "waiting_approval", "closed", "failed"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Disposition = Literal["malicious", "benign", "inconclusive"]
EscalationStatus = Literal["open", "claimed", "decided", "expired", "cancelled"]
Level = Literal["L1", "L2", "L3"]

ALERT_STATUSES = ["new", "queued", "processing", "waiting_human", "waiting_approval", "closed", "failed"]
SEVERITIES = ["info", "low", "medium", "high", "critical"]
DISPOSITIONS = ["malicious", "benign", "inconclusive"]
ESCALATION_STATUSES = ["open", "claimed", "decided", "expired", "cancelled"]
LEVELS = ["L1", "L2", "L3"]


class SearchAlertsArgs(_Args):
    status: Optional[List[AlertStatus]] = Field(default=None, max_length=7)
    severity: Optional[List[Severity]] = Field(default=None, max_length=5)
    disposition: Optional[List[Disposition]] = Field(default=None, max_length=3)
    source_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    q: Optional[str] = Field(default=None, min_length=1, max_length=200)
    since: Optional[datetime] = Field(default=None, alias="from")
    until: Optional[datetime] = Field(default=None, alias="to")
    limit: int = Field(default=20, ge=1, le=MAX_LIMIT)
    cursor: Optional[str] = Field(default=None, min_length=1, max_length=MAX_CURSOR)


class AlertIdArgs(_Args):
    alert_id: str = Field(pattern=ID_PATTERN)


class TimelineArgs(AlertIdArgs):
    limit: int = Field(default=50, ge=1, le=MAX_LIMIT)
    cursor: Optional[str] = Field(default=None, min_length=1, max_length=MAX_CURSOR)


class ListEscalationsArgs(_Args):
    status: Optional[List[EscalationStatus]] = Field(default=None, max_length=5)
    level: Optional[List[Level]] = Field(default=None, max_length=3)
    alert_id: Optional[str] = Field(default=None, pattern=ID_PATTERN)
    limit: int = Field(default=20, ge=1, le=MAX_LIMIT)
    cursor: Optional[str] = Field(default=None, min_length=1, max_length=MAX_CURSOR)


class EscalationIdArgs(_Args):
    escalation_id: str = Field(pattern=ID_PATTERN)


class DashboardArgs(_Args):
    window_hours: int = Field(default=24, ge=1, le=24 * 90)


class AddNoteArgs(AlertIdArgs):
    text: str = Field(min_length=1, max_length=4_000)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


async def _search_alerts(ctx: ToolContext, a: SearchAlertsArgs) -> Any:
    params = json_params(
        {
            "status": a.status,
            "severity": a.severity,
            "disposition": a.disposition,
            "source_id": a.source_id,
            "q": a.q,
            "from": _iso(a.since),
            "to": _iso(a.until),
            "limit": a.limit,
            "cursor": a.cursor,
        }
    )
    return await ctx.api.get("/api/v1/alerts", params)


async def _get_alert(ctx: ToolContext, a: AlertIdArgs) -> Any:
    return await ctx.api.get(f"/api/v1/alerts/{_seg(a.alert_id)}")


async def _get_alert_timeline(ctx: ToolContext, a: TimelineArgs) -> Any:
    return await ctx.api.get(
        f"/api/v1/alerts/{_seg(a.alert_id)}/events", json_params({"limit": a.limit, "cursor": a.cursor})
    )


async def _list_escalations(ctx: ToolContext, a: ListEscalationsArgs) -> Any:
    params = json_params(
        {"status": a.status, "level": a.level, "alert_id": a.alert_id, "limit": a.limit, "cursor": a.cursor}
    )
    return await ctx.api.get("/api/v1/escalations", params)


async def _get_escalation(ctx: ToolContext, a: EscalationIdArgs) -> Any:
    return await ctx.api.get(f"/api/v1/escalations/{_seg(a.escalation_id)}")


async def _dashboard_summary(ctx: ToolContext, a: DashboardArgs) -> Any:
    return await ctx.api.get("/api/v1/dashboard/summary", {"window_hours": a.window_hours})


async def _add_note(ctx: ToolContext, a: AddNoteArgs) -> Any:
    return await ctx.api.post(f"/api/v1/alerts/{_seg(a.alert_id)}/notes", {"text": a.text})


async def _get_evidence_pack(ctx: ToolContext, a: AlertIdArgs) -> Any:
    pack = await ctx.api.get(f"/api/v1/alerts/{_seg(a.alert_id)}/evidence", {"format": "json"})
    if isinstance(pack, dict) and "integrity" in pack:
        # Integrity first, so it survives output truncation.
        return {"integrity": pack["integrity"], **{k: v for k, v in pack.items() if k != "integrity"}}
    return pack


ORIGINAL_TOOLS: Tuple[Tool, ...] = (
    Tool(
        name="search_alerts",
        title="Search alerts",
        description=(
            "List the tenant's alerts, newest first, with optional filters. 'q' searches titles within a "
            "time window of at most 93 days (default: the 30 days before 'to'). Returns items and next_cursor."
        ),
        args=SearchAlertsArgs,
        input_schema=_object(
            {
                "status": _enum_list(ALERT_STATUSES, "Alert statuses to include."),
                "severity": _enum_list(SEVERITIES, "Severities to include."),
                "disposition": _enum_list(DISPOSITIONS, "Dispositions to include."),
                "source_id": {"type": "string", "maxLength": 128, "description": "Only alerts from this source."},
                "q": {"type": "string", "maxLength": 200, "description": "Title substring search."},
                "from": {
                    "type": "string",
                    "format": "date-time",
                    "description": "Ingested at or after (ISO 8601).",
                },
                "to": {"type": "string", "format": "date-time", "description": "Ingested before (ISO 8601)."},
                "limit": _limit_schema(20),
                "cursor": _CURSOR_SCHEMA,
            }
        ),
        handler=_search_alerts,
    ),
    Tool(
        name="get_alert",
        title="Get alert",
        description="One alert in full: normalized fields, redacted raw event, verdict summary and agent reasoning.",
        args=AlertIdArgs,
        input_schema=_object({"alert_id": _id_schema("Alert id.")}, ["alert_id"]),
        handler=_get_alert,
    ),
    Tool(
        name="get_alert_timeline",
        title="Get alert timeline",
        description="The alert's timeline events (workflow steps, decisions, notes), oldest first.",
        args=TimelineArgs,
        input_schema=_object(
            {"alert_id": _id_schema("Alert id."), "limit": _limit_schema(50), "cursor": _CURSOR_SCHEMA},
            ["alert_id"],
        ),
        handler=_get_alert_timeline,
    ),
    Tool(
        name="list_escalations",
        title="List escalations",
        description="Escalations waiting for or decided by analysts, newest first, with optional filters.",
        args=ListEscalationsArgs,
        input_schema=_object(
            {
                "status": _enum_list(ESCALATION_STATUSES, "Escalation statuses to include."),
                "level": _enum_list(LEVELS, "Escalation levels to include."),
                "alert_id": _id_schema("Only escalations of this alert."),
                "limit": _limit_schema(20),
                "cursor": _CURSOR_SCHEMA,
            }
        ),
        handler=_list_escalations,
    ),
    Tool(
        name="get_escalation",
        title="Get escalation",
        description="One escalation: reason, level, SLA, summary, related alerts and the analyst decision.",
        args=EscalationIdArgs,
        input_schema=_object({"escalation_id": _id_schema("Escalation id.")}, ["escalation_id"]),
        handler=_get_escalation,
    ),
    Tool(
        name="dashboard_summary",
        title="Dashboard summary",
        description="Alert counts by status, severity and disposition, MTTA/MTTR, open escalations and LLM cost.",
        args=DashboardArgs,
        input_schema=_object(
            {
                "window_hours": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 24 * 90,
                    "default": 24,
                    "description": "Look-back window in hours.",
                }
            }
        ),
        handler=_dashboard_summary,
    ),
    Tool(
        name="add_note",
        title="Add note to alert",
        description=(
            "Append an analyst note to the alert's timeline (audited). Needs an API key with the 'write' scope. "
            "Only add notes the user asked for."
        ),
        args=AddNoteArgs,
        input_schema=_object(
            {
                "alert_id": _id_schema("Alert id."),
                "text": {"type": "string", "minLength": 1, "maxLength": 4000, "description": "Note text."},
            },
            ["alert_id", "text"],
        ),
        handler=_add_note,
        read_only=False,
    ),
    Tool(
        name="get_evidence_pack",
        title="Get evidence pack",
        description=(
            "The alert's evidence pack: alert, timeline, agent reasoning and models, escalations, feedback, "
            "response ledger, human-oversight record, related audit entries with hash-chain verification, "
            "and the bundle's SHA-256 and signature. Exporting it is audited."
        ),
        args=AlertIdArgs,
        input_schema=_object({"alert_id": _id_schema("Alert id.")}, ["alert_id"]),
        handler=_get_evidence_pack,
    ),
)
"""The eight tools of LG-SOTF 1.0-1.1: names, arguments and behaviour unchanged."""

TOOLS: Dict[str, Tool] = {t.name: t for t in (*ORIGINAL_TOOLS, *TESTER_TOOLS)}


def tool_definitions() -> List[Dict[str, Any]]:
    return [t.definition() for t in TOOLS.values()]


def parse_arguments(tool: Tool, arguments: Any) -> _Args:
    """Validated arguments; raises :class:`ToolArgumentError` with a short, value-free message."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        raise ToolArgumentError("arguments must be an object")
    try:
        return tool.args.model_validate(dict(arguments))
    except ValidationError as exc:
        problems = []
        for error in exc.errors()[:10]:
            loc = ".".join(str(p) for p in error.get("loc", ())) or "arguments"
            problems.append(f"{loc}: {error.get('msg', 'invalid')}")
        raise ToolArgumentError("; ".join(problems)) from exc


def text_result(text: str, *, is_error: bool = False) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


async def call_tool(
    target: Union[ToolContext, LgSotfApiClient], tool: Tool, args: _Args, *, max_chars: int
) -> Dict[str, Any]:
    """Run a validated tool call; API and tool failures become ``isError`` results with a safe message."""
    ctx = target if isinstance(target, ToolContext) else ToolContext(target, RunStore(), max_output_chars=max_chars)
    try:
        data = await tool.handler(ctx, args)
    except (ApiCallError, ToolArgumentError, ToolError) as exc:
        return text_result(strip_invisible(f"{tool.name} failed: {exc}"), is_error=True)
    if isinstance(data, Shaped):
        return text_result(render(data, max_chars))
    # Not stripped: the data can be sealed (an evidence pack); wrap_untrusted writes invisible characters as escapes.
    return text_result(wrap_untrusted(data, max_chars))


__all__ = [
    "CLOSE_TAG",
    "OPEN_TAG",
    "ORIGINAL_TOOLS",
    "TOOLS",
    "TRUNCATION_NOTE",
    "Tool",
    "ToolArgumentError",
    "ToolContext",
    "ToolError",
    "UNTRUSTED_HEADER",
    "call_tool",
    "escape_data",
    "parse_arguments",
    "text_result",
    "tool_definitions",
    "wrap_untrusted",
]
