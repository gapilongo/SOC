"""Every public ``list*`` repository method returns a keyset ``Page`` or is a documented bounded list.

A list method that returns a plain ``List`` reads every matching row at once;
that is only acceptable when the rows are bounded by something other than the
caller's patience. Each such method is listed in ``BOUNDED_LISTS`` with what
bounds it. A new unbounded list method fails this test: page it
(``Page[...]``, keyset over its sort key) or document its bound here.
"""

from __future__ import annotations

import inspect
import typing
from typing import Iterable, List

import pytest

import lg_sotf.db.repos  # noqa: F401 - imports every repository module
from lg_sotf.db.pagination import Page
from lg_sotf.db.repos._base import Repository

pytestmark = pytest.mark.unit

BOUNDED_LISTS = {
    "ApiKeysRepo.list": "a tenant's API keys, created one by one by its admins",
    "FeedbackRepo.list_for_alert": "the feedback given on one alert",
    "GrantsRepo.list_for_organisation": "the live grants of one organisation, each given by hand by a customer admin",
    "GrantsRepo.list_for_tenant": "the grants one customer gave, each by hand by its admins",
    "IntegrationsRepo.list": "at most MAX_INTEGRATIONS_PER_TENANT (50) per tenant",
    "InvestigationStepsRepo.list_for_alert": "its limit (check_limit, MAX_STEPS_LISTED): the trace of one alert",
    "OrganisationsRepo.list_members": "the staff accounts of one organisation (users of its home tenant)",
    "LLMUsageRepo.list_range": "one row per day and model in a date range the callers cap (MAX_USAGE_DAYS)",
    "RunsRepo.list_queued": "its limit (check_limit, MAX_QUEUED_LISTED)",
    "ShadowEffectsRepo.list_for_run": "one shadow run's effects, at most MAX_EFFECTS (the sink keeps no more)",
    "SourcesRepo.list": "a tenant's configured sources (max_sources quota)",
    "SourcesRepo.list_due_sources_all_tenants": "its limit",
    "SuppressionsRepo.list": "a tenant's rules and suggestions; suggestions expire and are reused (find_reusable)",
    "SuppressionsRepo.list_active": "enabled, unexpired rules: the gate evaluates all of them",
    "TenantsRepo.list_all_tenants": "one row per tenant",
    "TicketsRepo.list": "its limit (check_limit, MAX_TICKET_LIST): the tickets of one alert or a page of escalations",
    "UsageRepo.list_range": "one row per day in a date range the callers cap",
}


def _repositories() -> List[type]:
    found: List[type] = []
    pending = list(Repository.__subclasses__())
    while pending:
        cls = pending.pop()
        found.append(cls)
        pending.extend(cls.__subclasses__())
    return sorted(found, key=lambda c: c.__qualname__)


def _returns_page(method: object) -> bool:
    origin = typing.get_origin(typing.get_type_hints(method).get("return"))
    return origin is Page


def list_methods(classes: Iterable[type]) -> dict[str, bool]:
    """``Class.method`` of every public ``list*`` method, and whether it returns a ``Page``."""
    methods: dict[str, bool] = {}
    for cls in classes:
        for name, member in vars(cls).items():
            if name.startswith("list") and inspect.isfunction(member):
                methods[f"{cls.__qualname__}.{name}"] = _returns_page(member)
    return methods


def problems(methods: dict[str, bool], bounded: dict[str, str]) -> List[str]:
    out = [
        f"{name} returns a plain list: return Page[...] (keyset) or document its bound in BOUNDED_LISTS"
        for name, paged in sorted(methods.items())
        if not paged and name not in bounded
    ]
    out += [f"{name} is in BOUNDED_LISTS but does not exist" for name in sorted(bounded) if name not in methods]
    out += [f"{name} returns a Page: delete it from BOUNDED_LISTS" for name in sorted(bounded) if methods.get(name)]
    return out


def test_list_methods_are_paged_or_documented_as_bounded() -> None:
    methods = list_methods(_repositories())
    assert "UsersRepo.list" in methods and "AlertsRepo.list" in methods
    found = problems(methods, BOUNDED_LISTS)
    assert not found, "\n".join(found)


class _Row:
    pass


class _FakeRepo:
    async def list(self) -> List[_Row]:
        return []

    async def list_paged(self) -> Page[_Row]:
        return Page(items=[], next_cursor=None)

    async def _list_private(self) -> List[_Row]:
        return []


def test_problems_reports_unpaged_stale_and_paged_entries() -> None:
    methods = list_methods([_FakeRepo])
    assert methods == {"_FakeRepo.list": False, "_FakeRepo.list_paged": True}
    assert problems(methods, {"_FakeRepo.list_paged": "x", "Gone.list": "x"}) == [
        "_FakeRepo.list returns a plain list: return Page[...] (keyset) or document its bound in BOUNDED_LISTS",
        "Gone.list is in BOUNDED_LISTS but does not exist",
        "_FakeRepo.list_paged returns a Page: delete it from BOUNDED_LISTS",
    ]
