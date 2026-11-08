"""Minimal valid JSON request bodies built from the OpenAPI contract (the cross-tenant leak suites).

An empty ``{}`` body is refused with 422 before a route reaches its tenant
lookup, which would hide a missing authorisation check behind a validation
error. These bodies carry every required field with a plausible value, so an
operation that passes authorisation reaches its handler.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional
from uuid import uuid4

Spec = Dict[str, Any]


def request_body(spec: Spec, path: str, method: str) -> Optional[Any]:
    """The minimal JSON body of ``method path``, or ``None`` when it takes no JSON body."""
    body = spec["paths"][path][method].get("requestBody")
    schema = (body or {}).get("content", {}).get("application/json", {}).get("schema")
    return None if schema is None else example(spec, schema)


def example(spec: Spec, schema: Spec) -> Any:
    if "$ref" in schema:
        _, _, _, name = schema["$ref"].split("/")
        return example(spec, spec["components"]["schemas"][name])
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            options = [s for s in schema[key] if s.get("type") != "null"]
            return example(spec, options[0]) if options else None
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    if schema.get("default") is not None:
        return schema["default"]
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        props = schema.get("properties", {})
        return {name: example(spec, props.get(name, {})) for name in schema.get("required", [])}
    if kind == "array":
        return [example(spec, schema.get("items", {})) for _ in range(schema.get("minItems", 0))]
    if kind == "integer":
        return max(int(schema.get("minimum", 1)), 1)
    if kind == "number":
        return max(float(schema.get("minimum", 1.0)), 1.0)
    if kind == "boolean":
        return False
    if kind == "string":
        return _string(schema)
    return {}


def _string(schema: Spec) -> str:
    fmt = schema.get("format")
    if fmt == "date-time":
        return (datetime.now(UTC) + timedelta(days=1)).isoformat()
    if fmt == "uuid":
        return str(uuid4())
    if fmt == "email":
        return "probe@example.com"
    if fmt in ("uri", "url"):
        return "https://example.com/probe"
    return "probe" + "x" * max(0, int(schema.get("minLength", 0)) - 5)
