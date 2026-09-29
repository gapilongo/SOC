"""Tolerant structured-output field types: text and lists are clipped, numbers and enums still validated."""

from __future__ import annotations

from typing import Any

import pytest
from anthropic import transform_schema
from pydantic import BaseModel, Field, ValidationError

from lg_sotf.llm.fake import analyse_text, synthesize
from lg_sotf.llm.schema import clip_text, clipped_list, clipped_str, lenient_literal


class Answer(BaseModel):
    thought: clipped_str(10)  # type: ignore[valid-type]
    target: clipped_str(5, default="")  # type: ignore[valid-type]
    verdict: lenient_literal("malicious", "benign")  # type: ignore[valid-type]
    score: int = Field(ge=0, le=100)
    actions: clipped_list(2, item_chars=6)  # type: ignore[valid-type]


def test_over_long_text_and_lists_are_clipped() -> None:
    a = Answer.model_validate(
        {"thought": "x" * 50, "verdict": " Malicious", "score": 5, "actions": ["abcdefghij", "b", "c"]}
    )
    assert a.thought == "xxxxxxx..." and len(a.thought) == 10
    assert a.verdict == "malicious" and a.target == ""
    assert a.actions == ["abc...", "b"]


@pytest.mark.parametrize(
    "bad",
    [
        {"thought": "x", "verdict": "malicious", "score": 150},
        {"thought": "x", "verdict": "harmless", "score": 5},
        {"thought": 5, "verdict": "benign", "score": 5},
        {"verdict": "benign", "score": 5},
    ],
)
def test_numbers_enums_and_types_are_still_validated(bad: Any) -> None:
    with pytest.raises(ValidationError):
        Answer.model_validate(bad)


def test_limits_stay_visible_to_the_model_in_the_anthropic_schema() -> None:
    """transform_schema moves maxLength/maxItems into descriptions: the model still sees the limits."""
    schema = transform_schema(Answer)
    props = schema["properties"]
    assert "maxLength: 10" in props["thought"]["description"]
    assert "maxItems: 2" in props["actions"]["description"]
    assert props["verdict"]["enum"] == ["malicious", "benign"]
    assert schema["required"] == ["thought", "verdict", "score"]


def test_the_fake_model_synthesises_clipped_types() -> None:
    value = synthesize(Answer, analyse_text("malware beacon"))
    assert isinstance(value, Answer) and len(value.thought) <= 10


def test_clip_text_edges() -> None:
    assert clip_text("abc", 3) == "abc"
    assert clip_text("abcdef", 2) == "ab"
    assert clip_text(7, 2) == 7
    with pytest.raises(ValueError):
        clipped_str(0)
    with pytest.raises(ValueError):
        lenient_literal()
