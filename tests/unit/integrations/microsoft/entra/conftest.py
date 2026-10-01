"""Entra unit tests run without real pauses between inline re-reads."""

from __future__ import annotations

import pytest

from lg_sotf.integrations.microsoft.entra import users


@pytest.fixture(autouse=True)
def no_reread_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(users, "INLINE_REREAD_DELAY_S", 0.0)
