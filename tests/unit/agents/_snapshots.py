"""Prompt snapshots shared by the prompt tests: a call rendered as text, compared with ``snapshots/<name>.txt``.

After an intended prompt change, regenerate them with ``LG_SOTF_UPDATE_SNAPSHOTS=1`` and review the diff.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lg_sotf.llm.fake import ScriptedCall
from tests.unit.agents._support import texts

SNAPSHOTS = Path(__file__).parent / "snapshots"
UPDATE = os.environ.get("LG_SOTF_UPDATE_SNAPSHOTS") == "1"


def render(call: ScriptedCall) -> str:
    parts = []
    for idx, (message, text) in enumerate(zip(call.messages, texts(call.messages), strict=True)):
        cache = ""
        if isinstance(message.content, list) and any(
            isinstance(b, dict) and b.get("cache_control") for b in message.content
        ):
            cache = " [cache_control]"
        parts.append(f"=== {idx}: {message.type}{cache} ===\n{text}")
    return f"schema: {call.schema}\n" + "\n".join(parts) + "\n"


def check_snapshot(name: str, text: str) -> None:
    path = SNAPSHOTS / f"{name}.txt"
    if UPDATE or not path.exists():
        if not UPDATE:
            pytest.fail(f"missing snapshot {path}; run with LG_SOTF_UPDATE_SNAPSHOTS=1 to create it")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8"), f"prompt changed; see {path}"
