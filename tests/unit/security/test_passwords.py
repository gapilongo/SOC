"""The local-account password policy shared by the API and the command line."""

from __future__ import annotations

from typing import Optional

import pytest

from lg_sotf.security.passwords import MAX_PASSWORD_CHARS, MIN_DISTINCT_CHARS, password_problem

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
