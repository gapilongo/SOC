"""The data layer reads no global settings: limits and configuration are explicit parameters (F8)."""

from __future__ import annotations

import inspect
from typing import Callable

import pytest

from lg_sotf.db.pool import Database
from lg_sotf.db.repos.runs import RunsRepo
from lg_sotf.db.repos.users import UsersRepo
from lg_sotf.db.retention import purge_expired

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("function", "name", "kind"),
    [
        (UsersRepo.reserve_login_attempt, "max_attempts", inspect.Parameter.KEYWORD_ONLY),
        (UsersRepo.reserve_login_attempt, "lockout_minutes", inspect.Parameter.KEYWORD_ONLY),
        (UsersRepo.record_login_failure, "max_attempts", inspect.Parameter.KEYWORD_ONLY),
        (UsersRepo.record_login_failure, "lockout_minutes", inspect.Parameter.KEYWORD_ONLY),
        (RunsRepo.requeue_stale_all_tenants, "max_attempts", inspect.Parameter.KEYWORD_ONLY),
        (Database.__init__, "settings", inspect.Parameter.POSITIONAL_OR_KEYWORD),
        (Database.connect, "settings", inspect.Parameter.POSITIONAL_OR_KEYWORD),
        (purge_expired, "retention", inspect.Parameter.POSITIONAL_OR_KEYWORD),
    ],
)
def test_settings_are_required_parameters(function: Callable[..., object], name: str, kind: object) -> None:
    param = inspect.signature(function).parameters[name]
    assert param.default is inspect.Parameter.empty, f"{function.__qualname__}({name}) must not fall back to settings"
    assert param.kind is kind


def test_database_without_settings_is_refused() -> None:
    with pytest.raises(TypeError):
        Database()  # the data layer has no settings fallback
