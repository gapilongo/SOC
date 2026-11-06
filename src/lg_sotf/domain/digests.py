"""Small read-side digests the console lists show: an entity line, a one-line reason, per-finding sources.

Everything here is computed from what the platform already stores (an
alert's normalized ``entities``, an escalation's ``summary``, the analysis
digest in ``alerts.summary.analysis``); nothing is inferred or invented. A
digest that has no data to work from is ``None`` or empty, never a guess.

Pure values: standard library only, no I/O (docs/adr/0001-layering.md).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "ENTITY_KINDS",
    "MAX_FINDINGS",
    "MAX_PREVIEW_ITEMS",
    "MAX_PREVIEW_VALUE_CHARS",
    "MAX_REASON_CHARS",
    "entities_preview",
    "findings",
    "one_line",
]

# (normalized ``entities`` key, the kind shown), in the order an analyst reads them: who, where, what.
ENTITY_KINDS: Tuple[Tuple[str, str], ...] = (
    ("users", "user"),
    ("hosts", "host"),
    ("ips", "ip"),
    ("emails", "email"),
    ("domains", "domain"),
    ("urls", "url"),
    ("processes", "process"),
    ("hashes", "hash"),
)
MAX_PREVIEW_ITEMS = 3
MAX_PREVIEW_VALUE_CHARS = 128
MAX_REASON_CHARS = 200
MAX_FINDINGS = 50
_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


def _strings(values: Any) -> List[str]:
    if not isinstance(values, (list, tuple)):
        return []
    return [v.strip() for v in values if isinstance(v, str) and v.strip()]


def entities_preview(entities: Any) -> Optional[Dict[str, Any]]:
    """The first value of up to :data:`MAX_PREVIEW_ITEMS` entity kinds, and how many values each kind has.

    ``{"items": [{"kind": "user", "value": "j.doe@example.com"}, {"kind": "ip", "value": "203.0.113.4"}],
    "counts": {"user": 1, "ip": 1}}``. ``counts`` covers every kind present (the normalizers keep at most
    50 values per kind). ``None`` when the alert has no entities.
    """
    if not isinstance(entities, Mapping):
        return None
    items: List[Dict[str, str]] = []
    counts: Dict[str, int] = {}
    for key, kind in ENTITY_KINDS:
        values = _strings(entities.get(key))
        if not values:
            continue
        counts[kind] = len(values)
        if len(items) < MAX_PREVIEW_ITEMS:
            items.append({"kind": kind, "value": values[0][:MAX_PREVIEW_VALUE_CHARS]})
    return {"items": items, "counts": counts} if items else None


def one_line(text: Any, limit: int = MAX_REASON_CHARS) -> Optional[str]:
    """The first sentence of ``text`` on one line, at most ``limit`` characters (``...`` when cut)."""
    if not isinstance(text, str):
        return None
    flat = " ".join(text.split())
    if not flat:
        return None
    first = _SENTENCE_END.split(flat, maxsplit=1)[0]
    return first if len(first) <= limit else first[: limit - 3].rstrip() + "..."


def _finding(origin: str, kind: Any, target: Any, result: Mapping[str, Any], checked_at: Any) -> Dict[str, Any]:
    data = result.get("data")
    return {
        "origin": origin,
        "kind": str(kind or ""),
        "target": str(target or ""),
        "source": str(result.get("provider") or ""),
        "status": str(result.get("status") or ""),
        "verdict": str(result.get("verdict") or "unknown"),
        "checked_at": checked_at if isinstance(checked_at, str) and checked_at else None,
        "cached": bool(result.get("cached")),
        "data": dict(data) if isinstance(data, Mapping) else {},
    }


def _mappings(values: Any) -> Sequence[Mapping[str, Any]]:
    return [v for v in values if isinstance(v, Mapping)] if isinstance(values, (list, tuple)) else []


def findings(summary: Any) -> List[Dict[str, Any]]:
    """The analysis agent's evidence lookups, one entry per provider result, each with its source.

    From ``summary.analysis.tools`` (threat-intelligence lookups the model chose, ``origin``
    ``threat_intel``) and ``summary.analysis.history`` (the tenant's own earlier alerts for the
    same entity, ``origin`` ``history``). ``checked_at`` is when the platform received the
    result (``cached`` results were fetched earlier); it is ``None`` for analyses recorded
    before the timestamp was stored. At most :data:`MAX_FINDINGS` entries.
    """
    analysis = summary.get("analysis") if isinstance(summary, Mapping) else None
    if not isinstance(analysis, Mapping):
        return []
    out: List[Dict[str, Any]] = []
    for tool in _mappings(analysis.get("tools")):
        for result in _mappings(tool.get("results")):
            out.append(_finding("threat_intel", tool.get("kind"), tool.get("target"), result, tool.get("checked_at")))
    for entry in _mappings(analysis.get("history")):
        out.append(_finding("history", entry.get("kind"), entry.get("value"), entry, entry.get("checked_at")))
    return out[:MAX_FINDINGS]
