"""The reply a Slack approver gets for each interaction outcome."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from lg_sotf.api.routers._slack import OUTCOME_MESSAGES, reply_text

pytestmark = pytest.mark.unit


def _ctx(hours: float) -> Any:
    return SimpleNamespace(settings=SimpleNamespace(integrations=SimpleNamespace(slack_sso_max_age_hours=hours)))


def test_refusals_use_the_fixed_messages() -> None:
    for outcome, text in OUTCOME_MESSAGES.items():
        assert reply_text(_ctx(12), True, outcome, None) == text
    assert set(OUTCOME_MESSAGES) == {"unmapped_user", "denied", "not_pending", "not_found", "slack_api_error", "mfa_required"}


def test_sso_refusal_names_the_configured_window() -> None:
    assert reply_text(_ctx(12), True, "sso_login_required", None) == (
        "LG-SOTF: sign in to the LG-SOTF web app with single sign-on (at least every 12 hours) "
        "before approving or rejecting actions from Slack."
    )
    assert "at least every 1.5 hours" in reply_text(_ctx(1.5), False, "sso_login_required", None)


def test_a_decided_action_reports_its_status() -> None:
    acted = SimpleNamespace(action_type="block_ip", target="203.0.113.7")
    assert reply_text(_ctx(12), True, "approved", acted) == "LG-SOTF: block_ip on 203.0.113.7 approved (approved)."
    assert reply_text(_ctx(12), False, "rejected", None) == "LG-SOTF: action on ? rejected (rejected)."
