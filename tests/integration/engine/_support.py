"""Helpers shared by the engine tests."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Union, get_args, get_origin, get_type_hints, is_typeddict


class RecordingEvents:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    async def publish(self, tenant_id: str, event: Dict[str, Any]) -> None:
        assert event["tenant_id"] == tenant_id
        self.events.append(event)

    def of_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["type"] == event_type]


def undeclared_keys(value: Any, schema: Any, path: str = "summary") -> List[str]:
    """Keys of ``value`` its TypedDict ``schema`` does not declare, nested TypedDicts (in lists too) included."""
    if get_origin(schema) is Union:
        return [p for arg in get_args(schema) if arg is not type(None) for p in undeclared_keys(value, arg, path)]
    if get_origin(schema) in (list, List) and isinstance(value, list):
        (item,) = get_args(schema)
        return [p for i, v in enumerate(value) for p in undeclared_keys(v, item, f"{path}[{i}]")]
    if not is_typeddict(schema) or not isinstance(value, Mapping):
        return []
    hints = get_type_hints(schema)
    out = [f"{path}.{key}" for key in value if key not in hints]
    for key, child in value.items():
        if key in hints:
            out.extend(undeclared_keys(child, hints[key], f"{path}.{key}"))
    return out
