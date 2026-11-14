"""Guided source setup: a connection test told as an ordered list of checks.

A guided check runs the same connector the poller uses, once, and reports
each thing a source needs (reachable, certificate trusted, sign-in accepted,
permission on the index, ...) as ``passed``, ``failed`` or ``skipped``. A
failed check carries the exact fix: the permission, index or setting to
change. Checks after the first failure are skipped, because their answer
would only repeat it.

Messages are written for an admin and are safe to return and to store: they
never hold a credential, a user name, a response body or an exception text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal, Mapping, Optional, Sequence, Tuple

CheckStatus = Literal["passed", "failed", "skipped"]

SKIPPED_MESSAGE = "Not checked: fix the failed check above first."


@dataclass(frozen=True)
class SetupCheck:
    id: str
    title: str
    status: CheckStatus
    message: str
    fix: Optional[str] = None


@dataclass(frozen=True)
class Failure:
    """The check that failed, what was found and what to change."""

    check_id: str
    message: str
    fix: str


def ordered_checks(
    order: Sequence[Tuple[str, str]],
    passed: Mapping[str, str],
    failure: Optional[Failure] = None,
    skipped: Optional[Mapping[str, str]] = None,
) -> List[SetupCheck]:
    """The checks of ``order`` (``(id, title)``) as a result list.

    Checks before ``failure`` passed with their ``passed`` text, the failed
    one carries its fix, and the ones after it are skipped. ``skipped``
    names checks that do not apply (with the reason), whatever the outcome.
    """
    not_applicable = skipped or {}
    checks: List[SetupCheck] = []
    failed_seen = False
    for check_id, title in order:
        if failure is not None and check_id == failure.check_id:
            failed_seen = True
            checks.append(SetupCheck(check_id, title, "failed", failure.message, failure.fix))
        elif check_id in not_applicable:
            checks.append(SetupCheck(check_id, title, "skipped", not_applicable[check_id]))
        elif failed_seen:
            checks.append(SetupCheck(check_id, title, "skipped", SKIPPED_MESSAGE))
        else:
            checks.append(SetupCheck(check_id, title, "passed", passed[check_id]))
    return checks


def all_passed(checks: Sequence[SetupCheck]) -> bool:
    """No check failed and at least one passed (a list of skipped checks proves nothing)."""
    return not any(c.status == "failed" for c in checks) and any(c.status == "passed" for c in checks)


__all__ = ["SKIPPED_MESSAGE", "CheckStatus", "Failure", "SetupCheck", "all_passed", "ordered_checks"]
