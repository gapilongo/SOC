"""The password policy for local accounts: one rule set for the API and the command line.

A password must have at least ``auth.password_min_length`` characters (the
caller passes it), at most :data:`MAX_PASSWORD_CHARS` (a bound on hashing
work) and at least :data:`MIN_DISTINCT_CHARS` distinct characters.
"""

from __future__ import annotations

from typing import Optional

__all__ = ["MAX_PASSWORD_CHARS", "MIN_DISTINCT_CHARS", "password_problem"]

MAX_PASSWORD_CHARS = 1_024
MIN_DISTINCT_CHARS = 4


def password_problem(password: str, min_length: int) -> Optional[str]:
    """Why ``password`` is refused (a message safe to show the person setting it), or ``None``."""
    if len(password) < min_length:
        return f"password must be at least {min_length} characters"
    if len(password) > MAX_PASSWORD_CHARS:
        return f"password must be at most {MAX_PASSWORD_CHARS} characters"
    if len(set(password)) < MIN_DISTINCT_CHARS:
        return "password is too repetitive"
    return None
