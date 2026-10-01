"""Resolving the target user: object id, UPN (guests, ``$`` names), the 404 fallbacks, ambiguity, encoding."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import httpx
import pytest

from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_ACCOUNT
from lg_sotf.integrations.microsoft.entra.users import (
    USER_SELECT,
    Refused,
    parse_time,
    resolve_user,
)
from lg_sotf.integrations.microsoft.odata import InvalidTarget
from tests.fixtures.microsoft import FakeMicrosoft, make_action, make_context
from tests.unit.integrations.microsoft.entra._support import Directory

SELECT_WIRE = USER_SELECT.replace(",", "%2C").encode()


def setup() -> tuple[FakeMicrosoft, Directory]:
    fake = FakeMicrosoft()
    return fake, Directory(fake)


async def resolve(fake: FakeMicrosoft, target: str):  # type: ignore[no-untyped-def]
    ctx, _ = make_context(fake, ENTRA_ACCOUNT, action=make_action("disable_user", target))
    return await resolve_user(ctx, target)


async def test_object_id_reads_the_user_directly() -> None:
    fake, directory = setup()
    alice = directory.add("alice@contoso.example", synced=True)
    user = await resolve(fake, alice.id.upper())
    assert user.id == alice.id and user.upn == "alice@contoso.example" and user.synced is True
    assert user.account_enabled is True and user.sessions_valid_from is not None
    (request,) = fake.api_requests()
    assert request.url.raw_path == f"/v1.0/users/{alice.id}?$select={SELECT_WIRE.decode()}".encode()


async def test_202_accepted_counts_as_success() -> None:
    fake, directory = setup()
    alice = directory.add()
    directory.override("GET", f"/v1.0/users/{alice.id}", httpx.Response(202, json={"id": alice.id,
                                                                                  "userPrincipalName": alice.upn}))
    assert (await resolve(fake, alice.id)).id == alice.id


async def test_upn_path_and_selected_properties() -> None:
    fake, directory = setup()
    directory.add("Alice@Contoso.example", user_type="Member")
    user = await resolve(fake, "alice@contoso.example")
    assert user.upn == "Alice@Contoso.example" and not user.is_guest
    (request,) = fake.api_requests()
    assert request.url.raw_path.startswith(b"/v1.0/users/alice%40contoso.example?$select=")


async def test_guest_upn_encodes_the_ext_marker() -> None:
    fake, directory = setup()
    guest = directory.add("adele_fabrikam.example#EXT#@contoso.example", user_type="Guest")
    user = await resolve(fake, guest.upn)
    assert user.is_guest and user.id == guest.id
    (request,) = fake.api_requests()
    assert request.url.raw_path.startswith(b"/v1.0/users/adele_fabrikam.example%23EXT%23%40contoso.example?")


async def test_upn_with_a_leading_dollar_uses_the_key_form_with_doubled_quotes() -> None:
    fake, directory = setup()
    odd = directory.add("$o'neil@contoso.example")
    user = await resolve(fake, odd.upn)
    assert user.id == odd.id
    (request,) = fake.api_requests()
    assert request.url.raw_path.startswith(b"/v1.0/users('%24o%27%27neil%40contoso.example')?$select=")


async def test_404_falls_back_to_mail_then_proxy_addresses() -> None:
    fake, directory = setup()
    bob = directory.add("bob.smith@contoso.example", mail="bob@contoso.example")
    user = await resolve(fake, "bob@contoso.example")
    assert user.id == bob.id
    queries = [r.url.params.get("$filter") for r in fake.api_requests()[1:]]
    assert queries == [
        "userPrincipalName eq 'bob@contoso.example'",
        "mail eq 'bob@contoso.example'",
        "proxyAddresses/any(x:x eq 'smtp:bob@contoso.example')",
        "proxyAddresses/any(x:x eq 'SMTP:bob@contoso.example')",
    ]
    for request in fake.api_requests()[1:]:
        assert request.headers.get("ConsistencyLevel") is None and "$count" not in request.url.params

    fake, directory = setup()
    carol = directory.add("carol@contoso.example", proxy_addresses=["smtp:c.jones@fabrikam.example"])
    assert (await resolve(fake, "c.jones@fabrikam.example")).id == carol.id


async def test_ambiguous_and_not_found() -> None:
    fake, directory = setup()
    directory.add("one@contoso.example", mail="team@contoso.example")
    directory.add("two@contoso.example", proxy_addresses=["SMTP:team@contoso.example"])
    with pytest.raises(Refused) as exc:
        await resolve(fake, "team@contoso.example")
    assert exc.value.code == "ambiguous_target" and exc.value.detail == {"matches": 2}

    fake, _ = setup()
    with pytest.raises(Refused) as exc:
        await resolve(fake, "nobody@contoso.example")
    assert exc.value.code == "not_found"
    fake, _ = setup()
    with pytest.raises(Refused) as exc:
        await resolve(fake, str(uuid.uuid4()))
    assert exc.value.code == "not_found" and len(fake.api_requests()) == 1  # no fallback for an object id


@pytest.mark.parametrize("target", ["CONTOSO\\alice", "alice", "", "  ", "a b@contoso.example"])
async def test_unresolvable_names_are_invalid_targets_and_send_nothing(target: str) -> None:
    fake, _ = setup()
    with pytest.raises(InvalidTarget) as exc:
        await resolve(fake, target)
    assert exc.value.code == "invalid_target" and fake.requests == []


async def test_odata_injection_is_encoded_on_the_wire() -> None:
    fake, directory = setup()
    victim = directory.add("o'brien+tag@contoso.example")
    directory.add("admin@contoso.example")
    # The name reaches Graph only as data: the path segment and the filter literal are both escaped.
    user = await resolve(fake, "O'Brien+Tag@contoso.example")
    assert user.id == victim.id
    (request,) = fake.api_requests()
    assert request.url.raw_path.startswith(b"/v1.0/users/O%27Brien%2BTag%40contoso.example?")

    fake, directory = setup()
    directory.add("admin@contoso.example", mail="x@contoso.example")
    with pytest.raises(Refused):
        await resolve(fake, "x'or'1'eq'1@contoso.example")
    filters = [r for r in fake.api_requests() if r.url.path == "/v1.0/users"]
    assert filters[0].url.query == (
        b"$filter=userPrincipalName%20eq%20%27x%27%27or%27%271%27%27eq%27%271%40contoso.example%27&$select="
        + SELECT_WIRE
    )
    assert filters[2].url.query.startswith(
        b"$filter=proxyAddresses%2Fany%28x%3Ax%20eq%20%27smtp%3Ax%27%27or%27%271%27%27eq%27%271%40contoso.example%27%29"
    )


def test_graph_timestamps() -> None:
    assert parse_time("2026-09-30T12:34:56Z") == datetime(2026, 9, 30, 12, 34, 56, tzinfo=UTC)
    assert parse_time("2026-09-30T12:34:56.1234567Z") == datetime(2026, 9, 30, 12, 34, 56, 123456, tzinfo=UTC)
    assert parse_time("2026-09-30T12:34:56") == datetime(2026, 9, 30, 12, 34, 56, tzinfo=UTC)
    for bad in (None, "", "yesterday", 1234, "x" * 50):
        assert parse_time(bad) is None
