"""Machine resolution: exact name, short-name fallback, 404 as empty, ambiguity, Active wins, wire bytes."""

from __future__ import annotations

import pytest

from lg_sotf.integrations.microsoft.defender import DEFENDER_ISOLATION
from lg_sotf.integrations.microsoft.defender._common import Refused
from lg_sotf.integrations.microsoft.defender.machines import resolve_machine, same_host
from lg_sotf.integrations.microsoft.odata import InvalidTarget
from tests.fixtures.microsoft import make_context
from tests.unit.integrations.microsoft.defender._support import FakeDefender


async def resolve(defender: FakeDefender, host: str):  # type: ignore[no-untyped-def]
    ctx, _ = make_context(defender.fake, DEFENDER_ISOLATION, read_only=True)
    return await resolve_machine(ctx, host)


def queries(defender: FakeDefender) -> list[str]:
    return [r.url.query.decode("ascii") for r in defender.fake.api_requests() if r.url.path == "/api/machines"]


async def test_exact_match_by_computer_dns_name() -> None:
    defender = FakeDefender()
    wanted = defender.machine("ws-042.corp.contoso.example")
    defender.machine("ws-0420.corp.contoso.example")
    machine = await resolve(defender, "WS-042.corp.contoso.example.")
    assert machine.id == wanted and machine.computer_dns_name == "ws-042.corp.contoso.example"
    assert machine.health_status == "Active" and machine.os_platform == "Windows11" and machine.last_seen is not None
    assert queries(defender) == ["$filter=computerDnsName%20eq%20%27ws-042.corp.contoso.example%27"]


async def test_short_name_falls_back_to_the_first_label() -> None:
    defender = FakeDefender()
    wanted = defender.machine("ws-042.corp.contoso.example")
    defender.machine("ws-0421.corp.contoso.example")
    machine = await resolve(defender, "ws-042")
    assert machine.id == wanted
    assert queries(defender) == [
        "$filter=computerDnsName%20eq%20%27ws-042%27",
        "$filter=startswith%28computerDnsName%2C%27ws-042%27%29&$top=100",
    ]


async def test_fqdn_target_matches_a_bare_machine_name() -> None:
    defender = FakeDefender()
    wanted = defender.machine("ws-042")
    assert (await resolve(defender, "ws-042.corp.contoso.example")).id == wanted


async def test_a_machine_in_another_domain_is_not_the_target() -> None:
    defender = FakeDefender()
    defender.machine("ws-042.lab.contoso.example")
    with pytest.raises(Refused) as exc:
        await resolve(defender, "ws-042.corp.contoso.example")
    assert exc.value.error == "not_found"
    assert not same_host("ws-042.corp.example", "ws-042.lab.example") and same_host("WS-042", "ws-042.corp")


async def test_404_counts_as_no_machines() -> None:
    defender = FakeDefender()  # no machines: Defender answers 404 Not Found
    with pytest.raises(Refused) as exc:
        await resolve(defender, "ws-042")
    assert exc.value.error == "not_found" and len(queries(defender)) == 2


async def test_duplicates_are_ambiguous_unless_exactly_one_is_active() -> None:
    defender = FakeDefender()
    defender.machine("ws-042", health="Inactive")
    active = defender.machine("ws-042", health="Active")
    assert (await resolve(defender, "ws-042")).id == active

    defender.machine("ws-042", health="Active")
    with pytest.raises(Refused) as exc:
        await resolve(defender, "ws-042")
    assert exc.value.error == "ambiguous_target" and exc.value.extra == {"count": 3}


async def test_ambiguous_short_name_matches() -> None:
    defender = FakeDefender()
    defender.machine("ws-042.corp.contoso.example", health="Inactive")
    defender.machine("ws-042.lab.contoso.example", health="NoSensorData")
    with pytest.raises(Refused) as exc:
        await resolve(defender, "ws-042")
    assert exc.value.error == "ambiguous_target" and exc.value.extra == {"count": 2}


@pytest.mark.parametrize(
    ("host", "code"),
    [
        ("ws-042' or computerDnsName ne 'x", "invalid_target"),
        ("ws-042%27", "invalid_target"),
        ("ws-042&$top=1", "invalid_target"),
        ("10.0.0.5", "unsupported_target"),
        ("ws\u0000042", "invalid_target"),
        ("", "invalid_target"),
    ],
)
async def test_untrusted_host_names_never_reach_defender(host: str, code: str) -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    with pytest.raises(InvalidTarget) as exc:
        await resolve(defender, host)
    assert exc.value.code == code and defender.fake.requests == []
