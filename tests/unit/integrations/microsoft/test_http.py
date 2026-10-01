"""MicrosoftApi: fixed hosts, encoding, retries and Retry-After within the deadline, paging, errors, secrets."""

from __future__ import annotations

import asyncio
import re
from typing import Any, List

import httpx
import pytest

from lg_sotf.integrations.microsoft.auth import AppCredentials, TokenProvider
from lg_sotf.integrations.microsoft.http import (
    MicrosoftApi,
    MicrosoftApiError,
    MicrosoftHttpFactory,
    ReadOnlyViolation,
    parse_error,
)
from tests.fixtures.microsoft import FakeMicrosoft, defender_error, graph_error, make_credentials, ms_settings


class Harness:
    def __init__(self, fake: FakeMicrosoft, **settings: Any) -> None:
        self.fake = fake
        self.sleeps: List[float] = []

        async def sleep(seconds: float) -> None:
            self.sleeps.append(seconds)

        self.http = MicrosoftHttpFactory(
            ms_settings(**settings), transport=fake.transport(), resolver=fake.resolver(), sleep=sleep,
            rand=lambda: 0.5,
        )
        self.tokens = TokenProvider(self.http)
        self.creds: AppCredentials = make_credentials(fake)

    def api(self, name: str = "graph", *, read_only: bool = False) -> MicrosoftApi:
        return self.http.api(self.creds, name, self.tokens, read_only=read_only)  # type: ignore[arg-type]


def deadline(seconds: float = 60.0) -> float:
    return asyncio.get_running_loop().time() + seconds


async def test_host_is_fixed_and_query_values_are_encoded_once() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/users", httpx.Response(200, json={"value": []}))
    h = Harness(fake)
    await h.api().request("GET", "/v1.0/users", params={"$filter": "mail eq 'a+b#c&d%e''f'", "$top": "5"},
                          deadline=deadline())
    (request,) = fake.api_requests()
    assert request.url.host == "graph.microsoft.com"
    assert request.url.raw_path == b"/v1.0/users?$filter=mail%20eq%20%27a%2Bb%23c%26d%25e%27%27f%27&$top=5"
    assert request.headers["authorization"].startswith("Bearer ")
    assert re.fullmatch(r"[0-9a-f-]{36}", request.headers["client-request-id"])


async def test_paths_must_be_encoded_segments() -> None:
    h = Harness(FakeMicrosoft())
    for bad in ("/v1.0/users?x=1", "/v1.0/users#x", "/v1.0/users/../admin", "/beta/users", "/api/x", "/v1.0/a b",
                "/v1.0//x", "/v1.0/users/%zz"):
        with pytest.raises(ValueError):
            await h.api().request("GET", bad, deadline=deadline())
    with pytest.raises(ValueError):
        await h.api("defender").request("GET", "/v1.0/machines", deadline=deadline())
    with pytest.raises(ValueError):
        await h.api().request("GET", "/v1.0/users", headers={"Authorization": "x"}, deadline=deadline())
    assert h.fake.requests == []


async def test_retry_after_within_the_deadline_is_honoured() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/users/x", graph_error(429, "TooManyRequests", headers={"Retry-After": "2"}),
               times=1)
    fake.route("GET", "graph", "/v1.0/users/x", httpx.Response(200, json={"id": "x"}))
    h = Harness(fake)
    response = await h.api().request("GET", "/v1.0/users/x", deadline=deadline())
    assert response.body == {"id": "x"} and h.sleeps == [2.0] and len(fake.api_requests()) == 2


async def test_retry_after_beyond_the_deadline_raises_throttled_without_sleeping() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "graph", "/v1.0/users/x/revokeSignInSessions",
               graph_error(429, "TooManyRequests", headers={"Retry-After": "120"}))
    h = Harness(fake)
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().request("POST", "/v1.0/users/x/revokeSignInSessions", deadline=deadline(30))
    assert exc.value.kind == "throttled" and exc.value.retry_after_s == 120.0 and exc.value.status == 429
    assert h.sleeps == [] and len(fake.api_requests()) == 1 and exc.value.ledger_error == "throttled"


async def test_503_is_always_retried_then_throttled_or_server() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "graph", "/v1.0/x", httpx.Response(503), times=1)
    fake.route("POST", "graph", "/v1.0/x", httpx.Response(202))
    h = Harness(fake)
    assert (await h.api().request("POST", "/v1.0/x", json={}, deadline=deadline())).status == 202
    always = FakeMicrosoft()
    always.route("GET", "graph", "/v1.0/x", httpx.Response(503))
    h = Harness(always)
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().request("GET", "/v1.0/x", deadline=deadline())
    assert exc.value.kind == "server" and exc.value.retryable and len(always.api_requests()) == 3


async def test_network_errors_retry_only_idempotent_requests() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/x", lambda r: (_ for _ in ()).throw(httpx.ConnectError("boom")), times=1)
    fake.route("GET", "graph", "/v1.0/x", httpx.Response(200, json={}))
    h = Harness(fake)
    assert (await h.api().request("GET", "/v1.0/x", deadline=deadline())).status == 200

    fake = FakeMicrosoft()
    fake.route("POST", "graph", "/v1.0/x", lambda r: (_ for _ in ()).throw(httpx.ReadError("reset")))
    h = Harness(fake)
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().request("POST", "/v1.0/x", json={"a": 1}, deadline=deadline())
    assert exc.value.kind == "network" and exc.value.ambiguous and len(fake.api_requests()) == 1

    fake = FakeMicrosoft()
    fake.route("POST", "graph", "/v1.0/x", lambda r: (_ for _ in ()).throw(httpx.ReadError("reset")), times=1)
    fake.route("POST", "graph", "/v1.0/x", httpx.Response(201, json={}))
    h = Harness(fake)
    assert (await h.api().request("POST", "/v1.0/x", json={}, idempotent=True, deadline=deadline())).status == 201


async def test_gateway_errors_and_concurrency_conflicts() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/x", httpx.Response(502), times=1)
    fake.route("GET", "graph", "/v1.0/x", httpx.Response(200, json={}))
    fake.route("POST", "graph", "/v1.0/x", httpx.Response(504))
    fake.route("PATCH", "graph", "/v1.0/u", graph_error(409, "Directory_ConcurrencyViolation"), times=1)
    fake.route("PATCH", "graph", "/v1.0/u", httpx.Response(204))
    h = Harness(fake)
    assert (await h.api().request("GET", "/v1.0/x", deadline=deadline())).status == 200
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().request("POST", "/v1.0/x", json={}, deadline=deadline())
    assert exc.value.kind == "server" and exc.value.ambiguous
    with pytest.raises(MicrosoftApiError) as conflict:
        await h.api().request("PATCH", "/v1.0/u", json={}, deadline=deadline())
    assert conflict.value.kind == "conflict" and conflict.value.code == "Directory_ConcurrencyViolation"
    assert (await h.api().request("PATCH", "/v1.0/u", json={}, idempotent=True, deadline=deadline())).status == 204


async def test_internal_server_errors_are_retried_when_idempotent_and_ambiguous_otherwise() -> None:
    # Defender documents 500 InternalServerError as "should be retried".
    fake = FakeMicrosoft()
    fake.route("GET", "defender", "/api/machines", defender_error(500, "InternalServerError"), times=1)
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": []}))
    fake.route("POST", "defender", "/api/machines/m1/isolate", defender_error(500, "InternalServerError"))
    h = Harness(fake)
    assert (await h.api("defender").request("GET", "/api/machines", deadline=deadline())).status == 200
    assert len(fake.api_requests()) == 2 and len(h.sleeps) == 1
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api("defender").request("POST", "/api/machines/m1/isolate", json={}, deadline=deadline())
    # A write is never resent on a 500: its outcome is unknown, so the connector defers and the re-run reconciles.
    assert exc.value.kind == "server" and exc.value.ambiguous and exc.value.status == 500
    assert len([r for r in fake.api_requests() if r.method == "POST"]) == 1


async def test_401_invalidates_the_token_and_retries_once() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/x", httpx.Response(401), times=1)
    fake.route("GET", "graph", "/v1.0/x", httpx.Response(200, json={}))
    h = Harness(fake)
    await h.api().request("GET", "/v1.0/x", deadline=deadline())
    assert fake.tokens_issued == 2

    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/x", httpx.Response(401))
    h = Harness(fake)
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().request("GET", "/v1.0/x", deadline=deadline())
    assert exc.value.kind == "auth" and len(fake.api_requests()) == 2


async def test_error_mapping_and_envelopes() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/a", httpx.Response(403, json={"Error": {"Code": "Authorization_RequestDenied",
                                                                              "Message": "secret text",
                                                                              "InnerError": {"Request-Id": "rid-1"}}}))
    fake.route("GET", "graph", "/v1.0/b", graph_error(404, "Request_ResourceNotFound"))
    fake.route("GET", "graph", "/v1.0/c", graph_error(400, "BadRequest"))
    fake.route("GET", "defender", "/api/d", defender_error(403, "DisabledFeature"))
    h = Harness(fake)
    with pytest.raises(MicrosoftApiError) as denied:
        await h.api().request("GET", "/v1.0/a", deadline=deadline())
    assert (denied.value.kind, denied.value.code, denied.value.request_id) == ("forbidden", "Authorization_RequestDenied", "rid-1")
    assert "secret text" not in str(denied.value) and denied.value.ledger_error == "permission_denied"
    with pytest.raises(MicrosoftApiError) as missing:
        await h.api().request("GET", "/v1.0/b", deadline=deadline())
    assert missing.value.kind == "not_found"
    assert (await h.api().request("GET", "/v1.0/b", not_found_ok=True, deadline=deadline())).status == 404
    with pytest.raises(MicrosoftApiError) as bad:
        await h.api().request("GET", "/v1.0/c", deadline=deadline())
    assert bad.value.kind == "bad_request" and not bad.value.retryable
    with pytest.raises(MicrosoftApiError) as disabled:
        await h.api("defender").request("GET", "/api/d", deadline=deadline())
    assert disabled.value.ledger_error == "feature_disabled" and disabled.value.request_id
    assert parse_error({"error": {"code": "X", "target": "t-1"}}, {}) == ("X", "t-1")
    assert parse_error(None, {"request-id": "h-1"}) == ("", "h-1")


async def test_redirects_are_refused_and_bodies_capped() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/r", httpx.Response(302, headers={"Location": "https://evil.example/steal"}))
    fake.route("GET", "graph", "/v1.0/big", httpx.Response(200, content=b"x" * (1024 * 1024 + 10)))
    h = Harness(fake)
    with pytest.raises(MicrosoftApiError) as redirect:
        await h.api().request("GET", "/v1.0/r", deadline=deadline())
    assert redirect.value.kind == "bad_request" and all(r.url.host != "evil.example" for r in fake.requests)
    with pytest.raises(MicrosoftApiError) as big:
        await h.api().request("GET", "/v1.0/big", deadline=deadline())
    assert big.value.kind == "size"


async def test_paging_follows_same_origin_next_links_only() -> None:
    fake = FakeMicrosoft()
    next_link = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc%2Bdef&$top=2"
    fake.route("GET", "graph", "/v1.0/users", lambda r: httpx.Response(200, json=(
        {"value": [{"id": "3"}]} if b"skiptoken" in r.url.raw_path else {"value": [{"id": "1"}, {"id": "2"}],
                                                                          "@odata.nextLink": next_link})))
    h = Harness(fake)
    items = await h.api().pages("/v1.0/users", params={"$top": "2"}, headers={"ConsistencyLevel": "eventual"},
                                max_items=10, deadline=deadline())
    assert [i["id"] for i in items] == ["1", "2", "3"]
    second = fake.api_requests()[1]
    assert second.url.raw_path == b"/v1.0/users?$skiptoken=abc%2Bdef&$top=2"  # verbatim
    assert all(r.headers["consistencylevel"] == "eventual" for r in fake.api_requests())
    assert len(await h.api().pages("/v1.0/users", max_items=2, deadline=deadline())) == 2

    foreign = FakeMicrosoft()
    foreign.route("GET", "graph", "/v1.0/users", httpx.Response(
        200, json={"value": [], "@odata.nextLink": "https://graph.microsoft.com.evil.example/v1.0/users"}))
    h = Harness(foreign)
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().pages("/v1.0/users", max_items=10, deadline=deadline())
    assert exc.value.code == "foreign_next_link" and len(foreign.api_requests()) == 1


async def test_read_only_clients_refuse_writes_before_sending() -> None:
    fake = FakeMicrosoft()
    h = Harness(fake)
    with pytest.raises(ReadOnlyViolation):
        await h.api(read_only=True).request("POST", "/v1.0/x", json={}, deadline=deadline())
    assert fake.requests == []


async def test_defender_client_rate_limit() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": []}))
    h = Harness(fake)
    api = h.api("defender")
    for _ in range(60):
        await api.request("GET", "/api/machines", deadline=deadline())
    assert h.sleeps == []
    await api.request("GET", "/api/machines", deadline=deadline())
    assert len(h.sleeps) == 1 and 0.5 < h.sleeps[0] <= 1.01
    with pytest.raises(MicrosoftApiError) as exc:
        for _ in range(120):
            await api.request("GET", "/api/machines", deadline=deadline(2))
    assert exc.value.kind == "throttled" and exc.value.code == "client_rate_limit"


async def test_deadline_is_never_exceeded() -> None:
    fake = FakeMicrosoft()
    h = Harness(fake)
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().request("GET", "/v1.0/x", deadline=asyncio.get_running_loop().time() + 0.1)
    assert exc.value.kind == "deadline" and fake.requests == []


async def test_no_token_or_secret_in_logs_or_errors(capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "graph", "/v1.0/x", graph_error(403, "Authorization_RequestDenied"))
    h = Harness(fake)
    with pytest.raises(MicrosoftApiError) as exc:
        await h.api().request("GET", "/v1.0/x", deadline=deadline())
    token = fake.api_requests()[0].headers["authorization"].split(" ", 1)[1]
    out = capsys.readouterr()
    text = out.out + out.err + str(exc.value) + repr(exc.value.__dict__)
    assert token not in text and (h.creds.client_secret or "") not in text
    assert "Bearer" not in text
