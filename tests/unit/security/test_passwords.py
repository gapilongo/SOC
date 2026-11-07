"""The local-account password policy shared by the API and the command line."""

from __future__ import annotations

from typing import Callable, Optional

import pytest

from lg_sotf.errors import OperationError
from lg_sotf.runtime import ops
from lg_sotf.security.passwords import MAX_PASSWORD_CHARS, MIN_DISTINCT_CHARS, password_problem
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("password", "min_length", "problem"),
    [
        ("correct horse battery", 12, None),
        ("abcd" * 3, 12, None),
        ("short pw", 12, "password must be at least 12 characters"),
        ("short pw", 8, None),
        ("x" * (MAX_PASSWORD_CHARS - 3) + "abc", 12, None),
        ("abcd" * (MAX_PASSWORD_CHARS // 4) + "e", 12, f"password must be at most {MAX_PASSWORD_CHARS} characters"),
        ("abcabcabcabc", 12, "password is too repetitive"),
        ("a" * 40, 12, "password is too repetitive"),
        # Length is checked before repetition.
        ("aaa", 12, "password must be at least 12 characters"),
    ],
)
def test_password_problem(password: str, min_length: int, problem: Optional[str]) -> None:
    assert password_problem(password, min_length) == problem


def test_distinct_character_floor() -> None:
    assert MIN_DISTINCT_CHARS == 4
    assert password_problem("abc" + "d" * 9, 12) is None
    assert password_problem("abc" + "c" * 9, 12) == "password is too repetitive"


def test_the_command_line_applies_the_same_policy(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(auth={"password_min_length": 12})
    ops.check_password(settings, "correct horse battery")
    for password, problem in (
        ("short pw", "password must be at least 12 characters"),
        ("abcabcabcabc", "password is too repetitive"),
        ("abcd" * (MAX_PASSWORD_CHARS // 4) + "e", f"password must be at most {MAX_PASSWORD_CHARS} characters"),
    ):
        with pytest.raises(OperationError) as refused:
            ops.check_password(settings, password)
        assert str(refused.value) == problem
