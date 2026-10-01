"""Building blocks shared by every MCP tool: the tool record, argument models, schema helpers and the call context.

Annotations follow the design's lint (§6): every tool has a ``title`` and
``openWorldHint: false``; a read tool has ``readOnlyHint: true``; a write
tool has ``readOnlyHint: false, destructiveHint: true, idempotentHint:
false`` so clients that decide confirmation from these hints (claude.ai,
Claude Desktop, Codex) ask before calling it. No tool claims
``idempotentHint: true``. Annotations are hints for the client; every
permission is enforced by the LG-SOTF API.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Type
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict

from lg_sotf.mcp.client import LgSotfApiClient

if TYPE_CHECKING:
    from lg_sotf.mcp.runs import RunStore

CATALOG_VERSION = "1.0.0"
"""Semver of the tool catalog (design §14): minor versions only add tools or optional fields."""
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

ID_PATTERN = r"^[A-Za-z0-9._:-]{1,256}$"
_ID_RE = re.compile(ID_PATTERN)
UUID_PATTERN = r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"
RUN_HANDLE_PATTERN = r"^run_[0-9a-f]{32}$"
MAX_LIMIT = 50
MAX_CURSOR = 512

Sleep = Callable[[float], Awaitable[None]]


class ToolArgumentError(ValueError):
    """The arguments of a ``tools/call`` do not match the tool's input schema."""


class ToolError(Exception):
    """A failure the model should read (an ``isError`` result). ``str()`` must be safe to show."""


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)


def _id_schema(description: str) -> Dict[str, Any]:
    return {"type": "string", "pattern": ID_PATTERN, "maxLength": 256, "description": description}


def _enum_list(values: List[str], description: str) -> Dict[str, Any]:
    return {
        "type": "array",
        "items": {"type": "string", "enum": values},
        "maxItems": len(values),
        "uniqueItems": True,
        "description": description,
    }


def _limit_schema(default: int, maximum: int = MAX_LIMIT) -> Dict[str, Any]:
    return {"type": "integer", "minimum": 1, "maximum": maximum, "default": default, "description": "Page size."}


_CURSOR_SCHEMA = {
    "type": "string",
    "maxLength": MAX_CURSOR,
    "description": "Opaque next_cursor from a previous page of the same query.",
}

_RUN_HANDLE_SCHEMA = {
    "type": "string",
    "pattern": RUN_HANDLE_PATTERN,
    "maxLength": 36,
    "description": "run_handle returned by ingest_test_alerts in this MCP server session.",
}


def _object(properties: Dict[str, Any], required: Optional[List[str]] = None) -> Dict[str, Any]:
    schema: Dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


@dataclass
class ToolContext:
    """What a tool handler may use: the API client, this session's test runs, and (for tests) time."""

    api: LgSotfApiClient
    runs: RunStore
    max_output_chars: int = 60_000
    sleep: Sleep = asyncio.sleep
    clock: Callable[[], float] = time.monotonic
    poll_interval_s: float = 2.0
    protocol_version: Optional[str] = None
    active_waits: int = 0


Handler = Callable[[ToolContext, Any], Awaitable[Any]]


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    args: Type[_Args]
    input_schema: Dict[str, Any]
    handler: Handler
    read_only: bool = True

    def annotations(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "title": self.title,
            "readOnlyHint": self.read_only,
            "destructiveHint": not self.read_only,
            "openWorldHint": False,
        }
        if not self.read_only:
            out["idempotentHint"] = False
        return out

    def definition(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations(),
        }


def _seg(value: str) -> str:
    """A validated, URL-quoted path segment."""
    if not _ID_RE.fullmatch(value):
        raise ToolArgumentError("invalid identifier")
    return quote(value, safe="")


__all__ = [
    "CATALOG_VERSION",
    "ID_PATTERN",
    "MAX_CURSOR",
    "MAX_LIMIT",
    "PROTOCOL_VERSION",
    "RUN_HANDLE_PATTERN",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "UUID_PATTERN",
    "Handler",
    "Tool",
    "ToolArgumentError",
    "ToolContext",
    "ToolError",
]
