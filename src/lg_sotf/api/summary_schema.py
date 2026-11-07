"""JSON Schema of the ``summary`` documents the API returns, derived from their TypedDicts (roadmap T3.4).

``AlertOut.summary`` stays a plain ``Dict[str, Any]`` at runtime (no
validation: rows written by older releases may hold other shapes); the
annotation only advertises the keys the workflow writes, from
:class:`lg_sotf.core.state.AlertSummary`. Every object stays open (no
``additionalProperties: false``), so a key added later never breaks a client
(tolerant reader).

Pydantic cannot build a schema from ``typing.TypedDict`` before Python 3.12,
and ``core/state.py`` imports only ``typing``, so the schema is derived here
from the type hints. Only the shapes the summary types use are supported.
"""

from __future__ import annotations

import inspect
import types
from typing import Annotated, Any, Dict, Literal, Union, get_args, get_origin, get_type_hints, is_typeddict

from pydantic import WithJsonSchema

from lg_sotf.core.state import AlertSummary

__all__ = ["ALERT_SUMMARY_SCHEMA", "AlertSummaryJson", "json_schema_of"]

JsonSchema = Dict[str, Any]
_SCALARS: Dict[Any, JsonSchema] = {
    str: {"type": "string"},
    int: {"type": "integer"},
    float: {"type": "number"},
    bool: {"type": "boolean"},
}


def _typed_dict_schema(td: Any) -> JsonSchema:
    hints = get_type_hints(td)
    schema: JsonSchema = {
        "type": "object",
        "properties": {name: json_schema_of(hint) for name, hint in hints.items()},
    }
    required = sorted(getattr(td, "__required_keys__", ()))
    if required:
        schema["required"] = required
    if td.__doc__:
        # The first paragraph of the TypedDict's own docstring.
        schema["description"] = " ".join(inspect.cleandoc(td.__doc__).split("\n\n", 1)[0].split())
    return schema


def json_schema_of(hint: Any) -> JsonSchema:
    """The JSON Schema of one type hint of a summary TypedDict."""
    if hint is Any:
        return {}
    if hint in _SCALARS:
        return dict(_SCALARS[hint])
    if is_typeddict(hint):
        return _typed_dict_schema(hint)
    origin, args = get_origin(hint), get_args(hint)
    if origin is Literal:
        return {"type": "string", "enum": list(args)}
    if origin in (Union, types.UnionType):
        return {"anyOf": [{"type": "null"} if a is type(None) else json_schema_of(a) for a in args]}
    if origin is list:
        return {"type": "array", "items": json_schema_of(args[0])}
    if origin is dict:
        value = json_schema_of(args[1])
        return {"type": "object", "additionalProperties": value or True}
    raise TypeError(f"no JSON Schema for {hint!r}")


ALERT_SUMMARY_SCHEMA: JsonSchema = {
    **json_schema_of(AlertSummary),
    "title": "Summary",
    "description": (
        "What the workflow recorded about the alert. Every key is optional: a key appears once the step that "
        "writes it has run, and alerts processed by an older release may lack keys or hold other shapes."
    ),
}

#: ``AlertOut.summary``: a free-form document at runtime, advertised with the AlertSummary keys.
AlertSummaryJson = Annotated[Dict[str, Any], WithJsonSchema(ALERT_SUMMARY_SCHEMA)]
