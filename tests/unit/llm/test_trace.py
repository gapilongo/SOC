"""Trace helpers: stable hashes, redacted and size-capped result digests, tool steps."""

from __future__ import annotations

import hashlib
from typing import Any, Dict

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from lg_sotf.llm.trace import (
    MAX_DIGEST_BYTES,
    TraceRecorder,
    content_hash,
    messages_hash,
    result_digest,
)


def _fake_token() -> str:
    return "test-only-" + "x7Kq2" * 8


def test_content_hash_is_canonical_sha256() -> None:
    assert content_hash({"b": 1, "a": [1, "é"]}) == content_hash({"a": [1, "é"], "b": 1})
    assert content_hash("x") == hashlib.sha256(b'"x"').hexdigest()
    assert len(content_hash(None)) == 64


def test_messages_hash_covers_role_and_content() -> None:
    a = [SystemMessage("rules"), HumanMessage("alert")]
    assert messages_hash(a) == messages_hash([SystemMessage("rules"), HumanMessage("alert")])
    assert messages_hash(a) != messages_hash([HumanMessage("rules"), HumanMessage("alert")])
    assert messages_hash(a) != messages_hash([SystemMessage("rules"), HumanMessage("alert!")])


def test_result_digest_redacts_secrets_and_caps_size() -> None:
    token = _fake_token()
    digest = result_digest({"api_key": token, "note": f"Authorization: Bearer {token}", "items": list(range(50))})
    text = str(digest)
    assert token not in text
    assert len(digest["value"]["items"]) == 20
    long = result_digest({"text": "a" * 5_000})
    assert len(long["value"]["text"]) == 1_000 and long["value"]["text"].endswith("...")
    huge = result_digest({f"k{i}": "b" * 900 for i in range(40)})
    assert huge["omitted"] == "too large" and huge["bytes"] > MAX_DIGEST_BYTES


class _Lookup:
    def __init__(self, result: Any = None, error: Exception | None = None) -> None:
        self.result, self.error = result, error

    async def __call__(self) -> Any:
        if self.error is not None:
            raise self.error
        return self.result


async def test_tool_step_records_request_hash_and_output() -> None:
    trace = TraceRecorder()
    request: Dict[str, Any] = {"kind": "ip", "value": "203.0.113.7"}
    found = await trace.tool("analysis", "history", request, _Lookup({"verdict": "unknown"})(), lambda r: r)
    assert found == {"verdict": "unknown"}
    [step] = trace.steps
    assert (step.kind, step.tool, step.outcome, step.model, step.prompt_name) == ("tool", "history", "success", None, None)
    assert step.input_hash == content_hash({"tool": "history", **request})
    assert step.output_hash == content_hash({"verdict": "unknown"})
    assert step.result_digest == {"value": {"verdict": "unknown"}}


async def test_tool_step_records_a_failure_and_reraises() -> None:
    trace = TraceRecorder()
    with pytest.raises(TimeoutError):
        await trace.tool("analysis", "reputation", {"kind": "ip"}, _Lookup(error=TimeoutError())(), lambda r: r)
    [step] = trace.steps
    assert (step.outcome, step.error_type, step.output_hash, step.result_digest) == ("error", "TimeoutError", None, None)
