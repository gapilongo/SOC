"""API integration fixtures; the harness (``make_api``, ``api``) is in tests/integration/conftest.py.

Requests go through ``httpx.AsyncClient`` with ``ASGITransport`` to
``https://testserver`` (so ``Secure`` cookies round-trip and HSTS applies).
Access tokens for most tests are minted with the app's own token service;
the auth tests exercise the real login flow. Helpers are in ``_support.py``.
"""

from __future__ import annotations

import pytest

from lg_sotf.api.auth import mfa as mfa_module
from tests.integration.api._support import IdP, TotpClock


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> TotpClock:
    """The MFA module's TOTP clock, frozen and advanced by ``tick``."""
    c = TotpClock()
    monkeypatch.setattr(mfa_module, "clock", c)
    return c


@pytest.fixture
def idp() -> IdP:
    return IdP()
