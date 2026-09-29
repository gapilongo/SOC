"""Field types for LLM output schemas that tolerate over-long text instead of discarding the answer.

With Anthropic structured outputs (``output_config.format``) the API
enforces the JSON schema's types, required keys and enums, but not length
or range constraints: ``anthropic.transform_schema`` moves ``maxLength``,
``maxItems``, ``minimum`` and ``maximum`` into the field description, where
they are a hint only. A model that writes a 1,500-character thought for a
1,000-character field would then fail validation after the call, and the
whole paid answer would be thrown away as ``LLMOutputError``.

The types here keep the limit in the schema (so the model still sees it)
and truncate text and lists to it *before* validation:

* :func:`clipped_str` - a string cut to ``max_chars`` (with an ellipsis);
* :func:`clipped_list` - a list cut to ``max_items`` whose string items are
  cut to ``item_chars``;
* :func:`lenient_literal` - a ``Literal`` that accepts case and surrounding
  whitespace variants (``"Malicious "`` -> ``"malicious"``).

Numbers are never clamped: a threat score of 150 is a wrong answer, not a
long one, and still fails validation.
"""

from __future__ import annotations

from typing import Any, Callable, List, Literal, Optional

from pydantic import BeforeValidator, Field
from typing_extensions import Annotated

ELLIPSIS = "..."


def clip_text(value: Any, max_chars: int) -> Any:
    """``value`` cut to ``max_chars`` characters (ending in ``...``) when it is a longer string."""
    if isinstance(value, str) and len(value) > max_chars:
        if max_chars <= len(ELLIPSIS):
            return value[:max_chars]
        return value[: max_chars - len(ELLIPSIS)].rstrip() + ELLIPSIS
    return value


def _text_clipper(max_chars: int) -> Callable[[Any], Any]:
    def clip(value: Any) -> Any:
        return clip_text(value, max_chars)

    return clip


def _list_clipper(max_items: int, item_chars: Optional[int]) -> Callable[[Any], Any]:
    def clip(value: Any) -> Any:
        if not isinstance(value, (list, tuple)):
            return value
        items = list(value)[:max_items]
        if item_chars is not None:
            items = [clip_text(item, item_chars) for item in items]
        return items

    return clip


def clipped_str(max_chars: int, *, default: Any = ..., description: Optional[str] = None) -> Any:
    """A ``str`` field type limited to ``max_chars``; longer model output is truncated, not rejected."""
    if max_chars < 1:
        raise ValueError("max_chars must be >= 1")
    field = Field(default=default, max_length=max_chars, description=description)
    return Annotated[str, BeforeValidator(_text_clipper(max_chars)), field]


def clipped_list(
    max_items: int, *, item_chars: Optional[int] = None, description: Optional[str] = None
) -> Any:
    """A ``List[str]`` field type limited to ``max_items`` (and ``item_chars`` per item), truncated not rejected."""
    if max_items < 0:
        raise ValueError("max_items must be >= 0")
    item: Any = str if item_chars is None else Annotated[str, Field(max_length=item_chars)]
    field: Any = Field(default_factory=list, max_length=max_items, description=description)
    return Annotated[List[item], BeforeValidator(_list_clipper(max_items, item_chars)), field]


def _literal_normaliser(choices: tuple[str, ...]) -> Callable[[Any], Any]:
    by_folded = {c.casefold(): c for c in choices}

    def normalise(value: Any) -> Any:
        if isinstance(value, str):
            return by_folded.get(value.strip().casefold(), value)
        return value

    return normalise


def lenient_literal(*choices: str) -> Any:
    """``Literal[choices]`` that also accepts case/whitespace variants of the choices."""
    if not choices:
        raise ValueError("lenient_literal needs at least one choice")
    return Annotated[Literal[choices], BeforeValidator(_literal_normaliser(tuple(choices)))]
