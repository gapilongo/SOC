"""The tester and verdict tools against a stub LG-SOTF API (httpx.MockTransport)."""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, List

import httpx
import pytest

from lg_sotf.eval.dataset import EvalItem
from lg_sotf.mcp.client import LgSotfApiClient
from lg_sotf.mcp.protocol import INVALID_PARAMS, McpServer
from lg_sotf.mcp.shaping import NOTICE, RESULT_BUDGET
from lg_sotf.mcp.tester import TestItemArgs as ItemArgs
from lg_sotf.mcp.tools import TOOLS, ToolArgumentError, parse_arguments
from tests.unit.mcp import _fakes as f
from tests.unit.mcp._support import (
    API_URL,
    FakeClock,
    StubApi,
    call,
    fake_key,
    initialized,
    make_client,
    make_server,
    payload,
    result_text,
)

RUN_RE = re.compile(r"^run_[0-9a-f]{32}$")


async def _server(stub: StubApi, **kwargs: Any) -> Any:
    return await initialized(make_server(stub, **kwargs))


def _ok(response: Dict[str, Any]) -> Dict[str, Any]:
    assert response["result"]["isError"] is False, result_text(response)
    data = payload(response["result"])
    assert data["notice"] == NOTICE and data["schema"].startswith("lgsotf.") and data["schema"].endswith(".v1")
    assert len(result_text(response)) <= RESULT_BUDGET
    return data


def _error(response: Dict[str, Any]) -> str:
    assert response["result"]["isError"] is True, response
    return result_text(response)


def _paths(stub: StubApi) -> List[str]:
    return [f"{r.method} {r.url.path}" for r in stub.requests]


# ------------------------------------------------------------------ whoami


async def test_whoami_reports_identity_limits_and_what_is_unavailable() -> None:
    stub = StubApi()
    stub.json("GET /api/v1/auth/me", f.me(["ingest", "read", "write"]))
    data = _ok(await call(await _server(stub), "whoami", {}))

    trusted = data["trusted"]
    assert trusted["principal"]["kind"] == "api_key" and trusted["principal"]["api_key_id"] == f.KEY_ID
    assert trusted["tenant"] == {"tenant_id": f.TENANT, "home_tenant_id": f.TENANT}
    assert trusted["scopes"] == ["ingest", "read", "write"]
    assert trusted["flags"] == {"can_send_test_alerts": True, "can_add_notes": True, "can_approve_or_decide": False}
    assert trusted["limits"]["max_test_items"] == 25 and trusted["limits"]["wait_timeout_s"] == {"default": 45, "max": 110}
    assert trusted["versions"]["catalog"] == "1.0.0" and trusted["versions"]["protocol"] == "2025-06-18"
    assert trusted["versions"]["supported_protocols"] == ["2025-06-18", "2025-03-26", "2024-11-05"]
    assert any("'write' scope" in w for w in trusted["warnings"])
    assert {"flags.install_dry_run", "flags.tenant_dry_run", "flags.qa_tenant", "grantable_scopes"} <= set(
        data["unavailable"]
    )
    assert _paths(stub) == ["GET /api/v1/auth/me"]


async def test_whoami_warns_when_the_key_cannot_send_test_alerts() -> None:
    stub = StubApi()
    stub.json("GET /api/v1/auth/me", f.me(["read"]))
    data = _ok(await call(await _server(stub), "whoami", {}))
    assert data["trusted"]["flags"]["can_send_test_alerts"] is False
    assert any("'ingest'" in w for w in data["trusted"]["warnings"])


# ------------------------------------------------------------- get_verdict


async def test_get_verdict_of_a_closed_alert_reads_the_summary() -> None:
    stub = StubApi()
    summary = f.closed_summary()
    summary["analysis"]["conclusion"] = "x" * 5_000
    stub.json("GET /api/v1/alerts/a-1", f.alert("a-1", "closed", disposition="benign", summary=summary))
    stub.json("GET /api/v1/actions", f.page([f.action("a-1", "dry_run", connector="dry_run", executed_at=f.INGESTED_AT)]))
    stub.json("GET /api/v1/escalations", f.page([]))

    data = _ok(await call(await _server(stub), "get_verdict", {"alert_id": "a-1"}))

    trusted, untrusted = data["trusted"], data["untrusted"]
    assert trusted["status"] == "closed" and trusted["disposition"] == "benign" and trusted["predicted"] == "benign"
    assert trusted["route"] == "close" and trusted["decision_code"] == "rule_corroborated_benign"
    assert trusted["close_reason"] == "policy:close" and trusted["escalated"] is False
    assert trusted["models"] == ["fake:fake-deep"] and trusted["llm_usage"]["total_tokens"] == 120
    assert [a["status"] for a in trusted["actions"]] == ["dry_run"] and trusted["pending_actions"] == 0
    assert trusted["alert_url"] == "https://soc.example.com/alerts?alert=a-1"
    assert untrusted["title"].startswith("Mimikatz") and untrusted["decision_reason"].startswith("low threat")
    assert untrusted["reasoning_summary"].startswith("Conclusion: xxx")
    assert len(untrusted["reasoning_summary"]) <= 2_000 and untrusted["reasoning_summary"].endswith("…[truncated]")
    assert "GET /api/v1/alerts/a-1/events" not in _paths(stub)  # the route is in the summary once closed
    actions_query = next(r for r in stub.requests if r.url.path == "/api/v1/actions").url.params
    assert actions_query["alert_id"] == "a-1"


async def test_get_verdict_of_a_waiting_alert_reads_the_route_from_the_timeline() -> None:
    stub = StubApi()
    summary = {"analysis": {"verdict": "malicious"}, "escalation_id": None}
    stub.json("GET /api/v1/alerts/a-2", f.alert("a-2", "waiting_approval", summary=summary))
    stub.json("GET /api/v1/alerts/a-2/events", f.decide_events("plan_response", "high_risk"))
    stub.json("GET /api/v1/actions", f.page([f.action("a-2", "awaiting_approval"), f.action("a-2", "awaiting_approval")]))
    stub.json("GET /api/v1/escalations", f.page([]))

    trusted = _ok(await call(await _server(stub), "get_verdict", {"alert_id": "a-2"}))["trusted"]

    assert trusted["route"] == "plan_response" and trusted["decision_code"] == "high_risk"
    assert trusted["predicted"] == "malicious" and trusted["approval_requested"] is True
    assert trusted["pending_actions"] == 2


async def test_get_verdict_of_an_unknown_alert_is_a_tool_error() -> None:
    text = _error(await call(await _server(StubApi()), "get_verdict", {"alert_id": "nope"}))
    assert text.startswith("get_verdict failed:") and "404" in text


# -------------------------------------------------------- list/get actions


async def test_list_actions_maps_approval_rehearsal_dispatch_and_verification() -> None:
    stub = StubApi()
    rows = [
        f.action("a-1", "awaiting_approval"),
        f.action("a-1", "dry_run", connector="dry_run", executed_at=f.INGESTED_AT, approved_by="policy:auto"),
        f.action("a-1", "succeeded", connector="webhook", executed_at=f.INGESTED_AT, approved_by=str(f.KEY_ID),
                 verification="verified", result={"summary": "host isolated"}),
    ]
    stub.json("GET /api/v1/actions", f.page(rows, next_cursor="c2"))

    data = _ok(await call(await _server(stub), "list_actions",
                          {"alert_id": "a-1", "status": ["awaiting_approval", "dry_run"], "limit": 3}))

    pending, rehearsed, live = (item["trusted"] for item in data["items"])
    assert pending["approval"]["state"] == "pending" and pending["rehearsal"] is None and pending["dispatched"] is False
    assert pending["approval_url"] == "https://soc.example.com/alerts?alert=a-1"
    assert rehearsed["rehearsal"] is True and rehearsed["dispatched"] is False
    assert rehearsed["approval"] == {"state": "approved", "approved_by": "policy:auto", "approved_at": f.INGESTED_AT}
    assert rehearsed["approval_url"] is None
    assert live["rehearsal"] is False and live["dispatched"] is True and live["verification"]["state"] == "verified"
    assert data["items"][2]["untrusted"]["result_summary"] == "host isolated"
    assert data["items"][0]["untrusted"]["target"] == "dc-01"
    assert data["next_cursor"] == "c2"
    sent = stub.requests[0].url.params
    assert sent.get_list("status") == ["awaiting_approval", "dry_run"] and sent["limit"] == "3"
    assert sent["alert_id"] == "a-1"


def _executed_action(index: int) -> Dict[str, Any]:
    """An executed action with every trusted field filled in (about 1,000 characters of trusted data)."""
    row = f.action(f"0e0f6b52-0000-4000-8000-{index:012d}", "succeeded", connector="webhook",
                   executed_at=f.INGESTED_AT, approved_by="u-" + "a" * 30, verification="verified",
                   action_id=f"6f1c2c1e-0000-4000-8000-{index:012d}", result={"summary": "host isolated"})
    row.update(verify_deadline=f.INGESTED_AT, blocked_reason="policy_denied", rolled_back_by="u-" + "b" * 30,
               rollback_of=f"6f1c2c1e-0000-4000-9000-{index:012d}", execution_owner="workflow_engine",
               rollback={"available": True, "action_type": "unisolate_host", "risk": "medium",
                         "until": f.INGESTED_AT, "reason": "within_window"})
    return row


async def _page_through_actions(server: McpServer, limit: int) -> List[str]:
    """Follow list_actions the way a client does: next_cursor, or the omitted note when the page was cut."""
    seen: List[str] = []
    cursor = None
    for _ in range(20):
        arguments: Dict[str, Any] = {"limit": limit, **({"cursor": cursor} if cursor else {})}
        data = _ok(await call(server, "list_actions", arguments))
        seen += [item["trusted"]["id"] for item in data["items"]]
        retry = [re.search(r"limit=(\d+)", note) for note in data["omitted"] if note.startswith("next_cursor")]
        if retry and retry[0]:
            again = _ok(await call(server, "list_actions", {**arguments, "limit": int(retry[0].group(1))}))
            assert [i["trusted"]["id"] for i in again["items"]] == [i["trusted"]["id"] for i in data["items"]]
            cut = [n for n in again["omitted"] if re.fullmatch(r"items\[\d+:\d+\]", n) or n.startswith("next_cursor")]
            assert cut == []  # whole rows fit; at most optional fields were dropped
            data = again
        if data["next_cursor"] is None:
            return seen
        cursor = data["next_cursor"]
    raise AssertionError("never reached the last page")


async def test_list_actions_never_passes_a_cursor_past_rows_it_dropped_to_fit() -> None:
    rows = [_executed_action(i) for i in range(30)]

    def keyset(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("cursor", "0"))
        end = start + int(request.url.params["limit"])
        return httpx.Response(200, json=f.page(rows[start:end], next_cursor=str(end) if end < len(rows) else None))

    stub = StubApi()
    stub.routes["GET /api/v1/actions"] = keyset
    server = await _server(stub)

    first = _ok(await call(server, "list_actions", {"limit": 25}))
    shown = len(first["items"])
    assert 0 < shown < 25 and first["truncated"] is True and f"items[{shown}:25]" in first["omitted"]
    assert first["next_cursor"] is None  # the API's cursor points past row 25, not past the rows shown
    assert any(n.startswith("next_cursor") and f"limit={shown}" in n for n in first["omitted"])

    assert await _page_through_actions(server, 25) == [r["id"] for r in rows]  # every row, in order, once


async def test_list_actions_keeps_the_cursor_of_a_page_that_fits() -> None:
    stub = StubApi()
    stub.json("GET /api/v1/actions", f.page([_executed_action(i) for i in range(5)], next_cursor="c2"))
    data = _ok(await call(await _server(stub), "list_actions", {"limit": 5}))
    assert len(data["items"]) == 5 and data["next_cursor"] == "c2" and data["omitted"] == []


async def test_get_action_includes_the_connector_result() -> None:
    stub = StubApi()
    action_id = "6f1c2c1e-0000-4000-8000-000000000001"
    stub.json(f"GET /api/v1/actions/{action_id}",
              f.action("a-1", "succeeded", connector="webhook", executed_at=f.INGESTED_AT, action_id=action_id,
                       result={"summary": "done", "http_status": 200}, verification="verified"))
    data = _ok(await call(await _server(stub), "get_action", {"action_id": action_id}))
    assert data["trusted"]["id"] == action_id and data["trusted"]["dispatched"] is True
    assert data["untrusted"]["result"] == {"summary": "done", "http_status": 200}
    assert data["untrusted"]["verification_detail"] == {"summary": "checked"}


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("get_action", {"action_id": "not-a-uuid"}),
        ("list_actions", {"limit": 26}),
        ("list_actions", {"status": ["approve"]}),
        ("list_actions", {"run_handle": "run_" + "0" * 32, "cursor": "x"}),
        ("list_actions", {"action_type": "Isolate Host"}),
        ("get_verdict", {}),
        ("whoami", {"tenant_id": "other"}),
    ],
)
async def test_invalid_arguments_of_the_new_tools_are_invalid_params(name: str, arguments: Dict[str, Any]) -> None:
    stub = StubApi()
    response = await call(await _server(stub), name, arguments)
    assert response["error"]["code"] == INVALID_PARAMS and stub.requests == []


# ------------------------------------------------------ ingest_test_alerts


async def test_ingest_test_alerts_suffixes_ids_with_the_run_and_returns_a_handle() -> None:
    stub = StubApi()
    f.standard_routes(stub)
    items = [f.dataset_item(16), f.dataset_item(17, expected={"disposition": "benign", "route": "close"})]
    items[1]["alert"].pop("source_alert_id")

    data = _ok(await call(await _server(stub), "ingest_test_alerts", {"items": items}))

    trusted = data["trusted"]
    handle = trusted["run_handle"]
    assert RUN_RE.fullmatch(handle)
    assert trusted["tenants"] == [f.TENANT] and trusted["inserted"] == 2 and trusted["prior_alerts"] is False
    assert [i["alert_id"] for i in trusted["items"]] == ["alert-0", "alert-1"]
    assert _paths(stub) == ["GET /api/v1/auth/me", "GET /api/v1/alerts", "POST /api/v1/ingest/alerts"]
    sent = json.loads(stub.requests[-1].content)["alerts"]
    assert [e["source_alert_id"] for e in sent] == [f"can-016:{handle}", f"syn-017:{handle}"]
    assert sent[0]["title"] == items[0]["alert"]["title"] and "expected" not in sent[0]
    assert stub.requests[1].url.params["limit"] == "1"
    assert data["untrusted"]["items"][0]["item_id"] == "syn-016"


def test_every_field_of_an_evaluation_item_is_accepted() -> None:
    """A line of an evaluation dataset fits as is (lg_sotf.eval.dataset.EvalItem, docs/evaluation.md)."""
    assert set(EvalItem.model_fields) <= set(ItemArgs.model_fields)


async def test_a_labelled_dataset_line_is_sent_without_its_labels() -> None:
    stub = StubApi()
    f.standard_routes(stub)
    item = f.dataset_item(1)
    item["labels"] = [{"annotator": "a1", "disposition": "malicious"}, {"annotator": "a2", "disposition": "benign"}]
    EvalItem.model_validate(item)  # a valid evaluation line

    data = _ok(await call(await _server(stub), "ingest_test_alerts", {"items": [item]}))

    assert data["trusted"]["inserted"] == 1
    [sent] = json.loads(stub.requests[-1].content)["alerts"]
    assert "labels" not in sent and "annotator" not in json.dumps(sent)


@pytest.mark.parametrize("split", ["adversarial-prompt-injection-unicode", "s" * 128, "v2.1:holdout_A"],
                         ids=["36-chars", "128-chars", "punctuation"])
def test_a_split_lg_sotf_eval_accepts_is_accepted(split: str) -> None:
    """The split follows the dataset's own rule (1-128 characters), not the 32 of a source type."""
    item = f.dataset_item(1, split=split)
    EvalItem.model_validate(item)
    args = parse_arguments(TOOLS["ingest_test_alerts"], {"items": [item]})
    assert args.model_dump()["items"][0]["split"] == split
    schema = TOOLS["ingest_test_alerts"].input_schema["properties"]["items"]["items"]["properties"]["split"]
    assert re.fullmatch(schema["pattern"].strip("^$"), split) and len(split) <= schema["maxLength"]


@pytest.mark.parametrize("split", ["s" * 129, "-adversarial", "a b", ""],
                         ids=["129-chars", "leading-dash", "space", "empty"])
def test_a_split_lg_sotf_eval_refuses_is_refused(split: str) -> None:
    with pytest.raises(ValueError):
        EvalItem.model_validate(f.dataset_item(1, split=split))
    with pytest.raises(ToolArgumentError, match="split"):
        parse_arguments(TOOLS["ingest_test_alerts"], {"items": [f.dataset_item(1, split=split)]})


async def test_ingest_warns_when_the_tenant_already_held_alerts() -> None:
    stub = StubApi()
    f.standard_routes(stub)
    stub.json("GET /api/v1/alerts", f.page([f.alert("old", "closed", disposition="benign")]))
    data = _ok(await call(await _server(stub), "ingest_test_alerts", {"items": [f.dataset_item(1)]}))
    assert data["trusted"]["prior_alerts"] is True
    assert any("contaminated" in w for w in data["trusted"]["warnings"])


async def test_non_canonical_items_are_refused_with_counts_and_nothing_is_sent() -> None:
    stub = StubApi()
    f.standard_routes(stub)
    items = [f.dataset_item(1), f.dataset_item(2, source_type="splunk"), f.dataset_item(3, source_type="splunk"),
             f.dataset_item(4, source_type="wazuh")]
    text = _error(await call(await _server(stub), "ingest_test_alerts", {"items": items}))
    assert "3 of 4 items are not canonical" in text and "splunk: 2" in text and "wazuh: 1" in text
    assert "nothing was sent" in text and stub.requests == []


@pytest.mark.parametrize("scopes", [["read"], ["ingest"], ["read", "write"]])
async def test_ingest_needs_a_key_with_ingest_and_read(scopes: List[str]) -> None:
    stub = StubApi()
    f.standard_routes(stub, scopes)
    text = _error(await call(await _server(stub), "ingest_test_alerts", {"items": [f.dataset_item(1)]}))
    assert "'ingest' and 'read'" in text
    assert "POST /api/v1/ingest/alerts" not in _paths(stub)


@pytest.mark.parametrize(
    "items",
    [
        [],
        [{"alert": {"title": "t", "severity": "low"}, "label": "x"}],
        [{"title": "a bare alert without the item wrapper"}],
        [{"alert": {"title": "t"}, "expected": {"disposition": "evil"}}],
        [{"alert": {"title": "t", "description": "d" * 40_000}}],
    ],
)
async def test_malformed_test_items_are_invalid_params(items: List[Any]) -> None:
    stub = StubApi()
    response = await call(await _server(stub), "ingest_test_alerts", {"items": items})
    assert response["error"]["code"] == INVALID_PARAMS and stub.requests == []


async def test_more_than_25_items_are_invalid_params() -> None:
    stub = StubApi()
    response = await call(await _server(stub), "ingest_test_alerts", {"items": [f.dataset_item(i) for i in range(26)]})
    assert response["error"]["code"] == INVALID_PARAMS and stub.requests == []


async def test_rejected_items_are_reported_with_their_reason() -> None:
    stub = StubApi()
    f.standard_routes(stub)
    stub.routes["POST /api/v1/ingest/alerts"] = lambda r: f.ingest_answer(r, rejected={1})
    data = _ok(await call(await _server(stub), "ingest_test_alerts", {"items": [f.dataset_item(1), f.dataset_item(2)]}))
    assert [i["status"] for i in data["trusted"]["items"]] == ["inserted", "rejected"]
    assert data["untrusted"]["items"][1]["reason"] == "canonical alert requires 'severity'"


async def test_an_ingest_api_failure_is_a_tool_error_and_creates_no_run() -> None:
    stub = StubApi()
    f.standard_routes(stub)
    stub.routes["POST /api/v1/ingest/alerts"] = lambda _r: httpx.Response(
        429, json={"error": {"code": "quota_exceeded", "message": "quota used up", "request_id": "r-1"}}
    )
    server = await _server(stub)
    text = _error(await call(server, "ingest_test_alerts", {"items": [f.dataset_item(1)]}))
    assert "429" in text and "quota_exceeded" in text
    assert len(server.context.runs) == 0
    assert _paths(stub).count("POST /api/v1/ingest/alerts") == 1  # writes are never retried


# -------------------------------------------------------- wait_for_verdict


async def test_wait_for_verdict_polls_until_every_alert_is_terminal() -> None:
    stub = StubApi()
    statuses = {"a-1": ["queued", "processing", "waiting_human"], "a-2": ["closed"]}

    def answer(request: httpx.Request) -> httpx.Response:
        alert_id = request.url.path.rsplit("/", 1)[1]
        status = statuses[alert_id].pop(0) if len(statuses[alert_id]) > 1 else statuses[alert_id][0]
        summary = f.closed_summary() if status == "closed" else {"escalation_id": "esc-1", "analysis": {"verdict": "malicious"}}
        return httpx.Response(200, json=f.alert(alert_id, status, disposition="benign" if status == "closed" else None,
                                                summary=summary))

    for alert_id in ("a-1", "a-2"):
        stub.routes[f"GET /api/v1/alerts/{alert_id}"] = answer
    stub.json("GET /api/v1/alerts/a-1/events", f.decide_events("escalate", "grey_zone"))
    stub.json("GET /api/v1/actions", f.page([]))
    clock = FakeClock()

    data = _ok(await call(await _server(stub, clock=clock), "wait_for_verdict",
                          {"alert_ids": ["a-1", "a-2"], "timeout_s": 30}))

    trusted = data["trusted"]
    assert trusted["pending"] == [] and trusted["retry_after_s"] is None
    done = {d["alert_id"]: d for d in trusted["done"]}
    assert done["a-1"]["status"] == "waiting_human" and done["a-1"]["route"] == "escalate"
    assert done["a-1"]["predicted"] == "malicious" and done["a-1"]["escalated"] is True
    assert done["a-2"]["route"] == "close" and done["a-2"]["model"] == ["fake:fake-deep"]
    assert clock.sleeps == [2.0, 2.0] and trusted["waited_s"] == 4.0


async def test_wait_for_verdict_stops_at_the_timeout_with_pending_ids() -> None:
    stub = StubApi()
    stub.json("GET /api/v1/alerts/a-1", f.alert("a-1", "processing"))
    clock = FakeClock()
    data = _ok(await call(await _server(stub, clock=clock), "wait_for_verdict",
                          {"alert_ids": ["a-1"], "timeout_s": 5}))
    assert data["trusted"]["pending"] == ["a-1"] and data["trusted"]["done"] == []
    assert data["trusted"]["retry_after_s"] == 10
    assert sum(clock.sleeps) == 5.0 and data["trusted"]["waited_s"] == 5.0


async def test_wait_with_timeout_zero_checks_once() -> None:
    stub = StubApi()
    stub.json("GET /api/v1/alerts/a-1", f.alert("a-1", "processing"))
    clock = FakeClock()
    data = _ok(await call(await _server(stub, clock=clock), "wait_for_verdict", {"alert_ids": ["a-1"], "timeout_s": 0}))
    assert data["trusted"]["pending"] == ["a-1"] and clock.sleeps == [] and len(stub.requests) == 1


async def test_a_slow_api_cannot_stretch_a_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lg_sotf.mcp.tester.WAIT_GRACE_S", 0.2)

    async def slow(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json=f.alert("a-1", "closed", disposition="benign", summary=f.closed_summary()))

    api = LgSotfApiClient(API_URL, fake_key(), transport=httpx.MockTransport(slow))
    server = await initialized(McpServer(api))
    started = time.monotonic()
    data = _ok(await call(server, "wait_for_verdict", {"alert_ids": ["a-1"], "timeout_s": 0}))
    await api.aclose()
    assert time.monotonic() - started < 2
    assert data["trusted"]["pending"] == ["a-1"] and data["trusted"]["retry_after_s"] == 10


async def test_at_most_two_waits_run_at_once() -> None:
    """A third wait answers at once (isError, retry_after_s) so it cannot hold a request slot for 110 s."""
    release = asyncio.Event()
    sleeping: List[float] = []

    async def blocked_sleep(seconds: float) -> None:
        sleeping.append(seconds)
        await release.wait()

    def answer(_request: httpx.Request) -> httpx.Response:
        if release.is_set():
            return httpx.Response(200, json=f.alert("a-1", "closed", disposition="benign", summary=f.closed_summary()))
        return httpx.Response(200, json=f.alert("a-1", "processing"))

    stub = StubApi()
    stub.routes["GET /api/v1/alerts/a-1"] = answer
    stub.json("GET /api/v1/actions", f.page([]))
    server = await initialized(McpServer(make_client(stub), sleep=blocked_sleep))
    arguments = {"alert_ids": ["a-1"], "timeout_s": 60}
    waits = [asyncio.create_task(call(server, "wait_for_verdict", arguments, request_id=i)) for i in (1, 2)]
    for _ in range(1_000):
        if len(sleeping) == 2:
            break
        await asyncio.sleep(0)
    assert len(sleeping) == 2  # both waits polled once and are sleeping

    third = _error(await call(server, "wait_for_verdict", arguments, request_id=3))
    assert "2 waits are already running" in third and "retry_after_s: 10" in third

    release.set()
    for wait in waits:
        assert _ok(await asyncio.wait_for(wait, timeout=5))["trusted"]["pending"] == []
    assert server.context.active_waits == 0
    assert _ok(await call(server, "wait_for_verdict", arguments, request_id=4))["trusted"]["pending"] == []


@pytest.mark.parametrize("max_chars", [1_000, 2_000, 3_000])
async def test_a_low_output_limit_drops_whole_done_entries_never_cuts_json(max_chars: int) -> None:
    stub = StubApi()
    ids = [f"alert-{i:02d}" for i in range(20)]
    for alert_id in ids:
        stub.json(f"GET /api/v1/alerts/{alert_id}",
                  f.alert(alert_id, "closed", disposition="benign", summary=f.closed_summary()))
    stub.json("GET /api/v1/actions", f.page([]))
    stub.json("GET /api/v1/auth/me", f.me(["ingest", "read"]))
    server = await _server(stub, max_output_chars=max_chars)

    response = await call(server, "wait_for_verdict", {"alert_ids": ids, "timeout_s": 0})
    waited = _ok(response)
    assert len(result_text(response)) <= max_chars and "[truncated:" not in result_text(response)
    shown = [d["alert_id"] for d in waited["trusted"]["done"]]
    assert shown and shown == ids[: len(shown)] and waited["trusted"]["pending"] == []
    assert waited["truncated"] is True and waited["omitted"] == [f"trusted.done[{len(shown)}:20]"]

    response = await call(server, "whoami", {})
    me = _ok(response)
    assert len(result_text(response)) <= max_chars and "[truncated:" not in result_text(response)
    assert me["truncated"] is ("unavailable" not in me)
    if "trusted" in me:
        assert me["trusted"]["scopes"] == ["ingest", "read"]


async def test_wait_reports_unknown_alerts_and_keeps_transient_errors_pending() -> None:
    stub = StubApi()
    stub.routes["GET /api/v1/alerts/a-2"] = lambda _r: httpx.Response(500, json={"error": {"code": "internal"}})
    clock = FakeClock()
    data = _ok(await call(await _server(stub, clock=clock), "wait_for_verdict",
                          {"alert_ids": ["gone", "a-2"], "timeout_s": 3}))
    assert data["trusted"]["errors"] == [{"alert_id": "gone", "error": "not found in this tenant"}]
    assert data["trusted"]["pending"] == ["a-2"] and "500" in data["trusted"]["last_errors"][0]["error"]


@pytest.mark.parametrize(
    "arguments",
    [{}, {"alert_ids": ["a"], "run_handle": "run_" + "0" * 32}, {"alert_ids": []},
     {"alert_ids": [f"a{i}" for i in range(21)]}, {"alert_ids": ["a"], "timeout_s": 111},
     {"alert_ids": ["../x"]}, {"run_handle": "run_bad"}],
)
async def test_wait_arguments_are_validated(arguments: Dict[str, Any]) -> None:
    stub = StubApi()
    response = await call(await _server(stub), "wait_for_verdict", arguments)
    assert response["error"]["code"] == INVALID_PARAMS and stub.requests == []


async def test_an_unknown_run_handle_is_a_tool_error() -> None:
    server = await _server(StubApi())
    for name in ("wait_for_verdict", "get_test_run", "list_actions"):
        text = _error(await call(server, name, {"run_handle": "run_" + "a" * 32}))
        assert "unknown or expired run_handle" in text


# ------------------------------------------------------------ get_test_run


def _run_api(stub: StubApi, alerts: Dict[str, Dict[str, Any]], *, prior: bool = False) -> None:
    f.standard_routes(stub)
    if prior:
        stub.json("GET /api/v1/alerts", f.page([f.alert("old", "closed", disposition="benign")]))
    for alert_id, body in alerts.items():
        stub.json(f"GET /api/v1/alerts/{alert_id}", body)
    stub.json("GET /api/v1/actions", f.page([]))


async def _ingest(server: Any, items: List[Dict[str, Any]]) -> str:
    data = _ok(await call(server, "ingest_test_alerts", {"items": items}))
    return str(data["trusted"]["run_handle"])


async def test_get_test_run_scores_agreement_and_lists_mismatches() -> None:
    stub = StubApi()
    _run_api(stub, {
        "alert-0": f.alert("alert-0", "waiting_approval", summary={"analysis": {"verdict": "malicious"}}),
        "alert-1": f.alert("alert-1", "closed", disposition="benign", summary=f.closed_summary()),
        "alert-2": f.alert("alert-2", "closed", disposition="benign", summary=f.closed_summary(),
                           title="Ransomware note dropped"),
        "alert-3": f.alert("alert-3", "processing"),
    })
    stub.json("GET /api/v1/alerts/alert-0/events", f.decide_events("plan_response", "high_risk"))
    items = [
        f.dataset_item(0, expected={"disposition": "malicious", "escalation": True}),
        f.dataset_item(1, expected={"disposition": "benign", "escalation": False, "route": "close"}, split="adversarial"),
        f.dataset_item(2, expected={"disposition": "malicious", "escalation": True}),
        f.dataset_item(3),
    ]
    server = await _server(stub)
    handle = await _ingest(server, items)

    data = _ok(await call(server, "get_test_run", {"run_handle": handle}))

    trusted = data["trusted"]
    metrics = trusted["metrics"]
    assert metrics["items"] == 4 and metrics["evaluated"] == 3 and metrics["pending"] == 1
    assert metrics["accuracy"] == pytest.approx(2 / 3, abs=1e-3) and metrics["agreement_rate"] == pytest.approx(2 / 3, abs=1e-3)
    assert metrics["route_accuracy"] == 1.0 and metrics["route_labelled_items"] == 1
    assert metrics["escalation_accuracy"] == pytest.approx(2 / 3, abs=1e-3)
    assert metrics["confusion_matrix"] == {"malicious": {"malicious": 1, "benign": 1}, "benign": {"benign": 1}}
    assert trusted["pending"] == ["alert-3"] and trusted["contaminated"] is False
    assert trusted["coverage"]["by_split"] == {"adversarial": {"items": 1, "evaluated": 1},
                                               "standard": {"items": 3, "evaluated": 2}}
    assert trusted["model_snapshot"] == ["fake:fake-deep"]
    assert "gate" in data["unavailable"]
    [mismatch] = data["mismatches"]
    assert mismatch["trusted"]["alert_id"] == "alert-2" and mismatch["trusted"]["fields"] == ["disposition", "escalation"]
    assert mismatch["trusted"]["expected"] == {"disposition": "malicious", "escalation": True}
    assert mismatch["trusted"]["got"] == {"disposition": "benign", "route": "close", "escalation": False}
    assert mismatch["untrusted"] == {"item_id": "syn-002", "title": "Ransomware note dropped"}
    assert data["next_cursor"] is None


def _dedup_ingest(request: httpx.Request) -> httpx.Response:
    """``POST /ingest/alerts`` as the API answers it: a repeated source alert id is a duplicate of the first."""
    events = json.loads(request.content)["alerts"]
    first: Dict[str, str] = {}
    items = []
    for index, event in enumerate(events):
        source_alert_id = event["source_alert_id"]
        if source_alert_id in first:
            items.append({"index": index, "status": "duplicate", "alert_id": first[source_alert_id], "reason": None})
        else:
            first[source_alert_id] = f"alert-{index}"
            items.append({"index": index, "status": "inserted", "alert_id": f"alert-{index}", "reason": None})
    inserted = len(first)
    return httpx.Response(202, json={"source_id": f"api:{f.KEY_ID}", "received": len(events), "inserted": inserted,
                                     "duplicates": len(events) - inserted, "rejected": 0, "enqueued": inserted,
                                     "items": items})


async def test_duplicate_items_are_errors_not_scored_on_the_first_items_triage() -> None:
    """As ``lg-sotf eval``: an item the API did not insert was never triaged, so it is an error, not evaluated."""
    stub = StubApi()
    _run_api(stub, {"alert-0": f.alert("alert-0", "closed", disposition="benign", summary=f.closed_summary())})
    stub.routes["POST /api/v1/ingest/alerts"] = _dedup_ingest
    same = f.dataset_item(0, expected={"disposition": "benign", "route": "close"})
    relabelled = f.dataset_item(0, expected={"disposition": "malicious"})
    server = await _server(stub, clock=FakeClock())

    sent = _ok(await call(server, "ingest_test_alerts", {"items": [same, same, relabelled]}))

    assert sent["trusted"]["items"] == [
        {"index": 0, "status": "inserted", "alert_id": "alert-0"},
        {"index": 1, "status": "duplicate", "alert_id": None, "duplicate_of": "alert-0"},
        {"index": 2, "status": "duplicate", "alert_id": None, "duplicate_of": "alert-0"},
    ]
    assert any("2 items were not inserted" in w and "not scored" in w for w in sent["trusted"]["warnings"])
    handle = sent["trusted"]["run_handle"]
    waited = _ok(await call(server, "wait_for_verdict", {"run_handle": handle}))["trusted"]
    assert [d["alert_id"] for d in waited["done"]] == ["alert-0"] and waited["pending"] == []
    data = _ok(await call(server, "get_test_run", {"run_handle": handle}))
    metrics = data["trusted"]["metrics"]
    assert metrics["items"] == 3 and metrics["evaluated"] == 1 and metrics["errors"] == 2
    assert metrics["accuracy"] == 1.0 and metrics["mismatches"] == 0 and data["mismatches"] == []
    assert data["trusted"]["error_items"] == [{"index": 1, "alert_id": None, "status": "duplicate"},
                                              {"index": 2, "alert_id": None, "status": "duplicate"}]
    assert data["trusted"]["coverage"]["by_split"] == {"standard": {"items": 3, "evaluated": 1}}
    assert data["trusted"]["pending"] == []


async def test_get_test_run_pages_on_after_the_mismatches_it_dropped_to_fit() -> None:
    count = 12
    stub = StubApi()
    _run_api(stub, {f"alert-{i}": f.alert(f"alert-{i}", "closed", disposition="benign", summary=f.closed_summary())
                    for i in range(count)})
    server = await _server(stub, max_output_chars=3_500)
    handle = await _ingest(server, [f.dataset_item(i, expected={"disposition": "malicious"}) for i in range(count)])

    pages: List[List[int]] = []
    cursor = None
    for _ in range(count):
        data = _ok(await call(server, "get_test_run",
                              {"run_handle": handle, "limit": count, **({"cursor": cursor} if cursor else {})}))
        pages.append([m["trusted"]["index"] for m in data["mismatches"]])
        assert pages[-1], data["omitted"]
        cursor = data["next_cursor"]
        if cursor is None:
            break
    assert len(pages[0]) < count  # the budget cut the first page
    assert sum(pages, []) == list(range(count))  # and its cursor resumed right after what was shown


async def test_the_first_terminal_outcome_of_an_item_is_kept() -> None:
    stub = StubApi()
    _run_api(stub, {"alert-0": f.alert("alert-0", "waiting_human", summary={"analysis": {"verdict": "malicious"}})})
    stub.json("GET /api/v1/alerts/alert-0/events", f.decide_events("escalate", "grey_zone"))
    server = await _server(stub)
    handle = await _ingest(server, [f.dataset_item(0)])
    first = _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]["metrics"]
    # An analyst later closes the alert as benign: the run keeps what triage did on its own.
    stub.json("GET /api/v1/alerts/alert-0", f.alert("alert-0", "closed", disposition="benign", summary=f.closed_summary()))
    second = _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]["metrics"]
    assert first == second and second["accuracy"] == 1.0


async def test_a_failed_run_that_a_retry_completes_is_scored_on_the_retry() -> None:
    """``failed`` is not final: the worker retries the run (failed -> processing -> ...)."""
    stub = StubApi()
    _run_api(stub, {"alert-0": f.alert("alert-0", "failed")})
    stub.json("GET /api/v1/alerts/alert-0/events", f.page([]))
    server = await _server(stub, clock=FakeClock())
    handle = await _ingest(server, [f.dataset_item(0)])

    first = _ok(await call(server, "wait_for_verdict", {"run_handle": handle}))["trusted"]
    assert [d["status"] for d in first["done"]] == ["failed"] and first["pending"] == []
    assert _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]["metrics"]["errors"] == 1

    # The redelivered run is processing again: the item is pending, not an error.
    stub.json("GET /api/v1/alerts/alert-0", f.alert("alert-0", "processing"))
    retrying = _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]
    assert retrying["pending"] == ["alert-0"] and retrying["metrics"]["errors"] == 0 and retrying["error_items"] == []

    # The retry finishes: wait_for_verdict and get_test_run report what it did.
    stub.json("GET /api/v1/alerts/alert-0", f.alert("alert-0", "waiting_human", summary={"analysis": {"verdict": "malicious"}}))
    stub.json("GET /api/v1/alerts/alert-0/events", f.decide_events("escalate", "grey_zone"))
    second = _ok(await call(server, "wait_for_verdict", {"run_handle": handle}))["trusted"]
    assert [d["status"] for d in second["done"]] == ["waiting_human"] and second["done"][0]["predicted"] == "malicious"
    run = _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]
    assert run["metrics"]["evaluated"] == 1 and run["metrics"]["errors"] == 0 and run["metrics"]["accuracy"] == 1.0
    assert run["error_items"] == [] and run["pending"] == []


async def test_a_run_that_stays_failed_is_an_error() -> None:
    stub = StubApi()
    _run_api(stub, {"alert-0": f.alert("alert-0", "failed")})
    stub.json("GET /api/v1/alerts/alert-0/events", f.page([]))
    server = await _server(stub, clock=FakeClock())
    handle = await _ingest(server, [f.dataset_item(0)])
    for _ in range(2):
        assert _ok(await call(server, "wait_for_verdict", {"run_handle": handle}))["trusted"]["done"][0]["status"] == "failed"
    run = _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]
    assert run["metrics"]["errors"] == 1 and run["metrics"]["evaluated"] == 0
    assert run["error_items"] == [{"index": 0, "alert_id": "alert-0", "status": "failed"}]


async def test_a_tenant_with_earlier_alerts_contaminates_the_run() -> None:
    stub = StubApi()
    _run_api(stub, {"alert-0": f.alert("alert-0", "closed", disposition="benign", summary=f.closed_summary())},
             prior=True)
    server = await _server(stub)
    handle = await _ingest(server, [f.dataset_item(0)])
    trusted = _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]
    assert trusted["contaminated"] is True and trusted["contamination"]["prior_alerts"] is True


async def test_joining_an_escalation_created_before_the_run_contaminates_it() -> None:
    stub = StubApi()
    summary = {"analysis": {"verdict": "malicious"}, "escalation_id": "esc-old", "escalation_attached": True}
    _run_api(stub, {"alert-0": f.alert("alert-0", "waiting_human", summary=summary)})
    stub.json("GET /api/v1/alerts/alert-0/events", f.decide_events("escalate", "grey_zone"))
    stub.json("GET /api/v1/escalations/esc-old", f.escalation("esc-old", "other", "2026-09-30T08:00:00+00:00"))
    server = await _server(stub)
    handle = await _ingest(server, [f.dataset_item(0)])
    trusted = _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]
    assert trusted["contaminated"] is True
    assert trusted["contamination"] == {"prior_alerts": False, "preexisting_escalations": ["esc-old"]}
    assert trusted["started_at"] == f.INGESTED_AT


async def test_an_escalation_created_during_the_run_does_not_contaminate_it() -> None:
    stub = StubApi()
    summary = {"analysis": {"verdict": "malicious"}, "escalation_id": "esc-new"}
    _run_api(stub, {"alert-0": f.alert("alert-0", "waiting_human", summary=summary)})
    stub.json("GET /api/v1/alerts/alert-0/events", f.decide_events("escalate", "grey_zone"))
    stub.json("GET /api/v1/escalations/esc-new", f.escalation("esc-new", "alert-0", "2026-10-01T10:00:05+00:00"))
    server = await _server(stub)
    handle = await _ingest(server, [f.dataset_item(0)])
    assert _ok(await call(server, "get_test_run", {"run_handle": handle}))["trusted"]["contaminated"] is False


async def test_mismatches_are_paged() -> None:
    stub = StubApi()
    alerts = {f"alert-{i}": f.alert(f"alert-{i}", "closed", disposition="benign", summary=f.closed_summary())
              for i in range(5)}
    _run_api(stub, alerts)
    server = await _server(stub)
    handle = await _ingest(server, [f.dataset_item(i) for i in range(5)])
    first = _ok(await call(server, "get_test_run", {"run_handle": handle, "limit": 2}))
    assert [m["trusted"]["index"] for m in first["mismatches"]] == [0, 1] and first["next_cursor"] == "2"
    last = _ok(await call(server, "get_test_run", {"run_handle": handle, "limit": 2, "cursor": "4"}))
    assert [m["trusted"]["index"] for m in last["mismatches"]] == [4] and last["next_cursor"] is None


async def test_wait_and_list_actions_by_run_handle() -> None:
    stub = StubApi()
    _run_api(stub, {
        "alert-0": f.alert("alert-0", "waiting_approval", summary={"analysis": {"verdict": "malicious"}}),
        "alert-1": f.alert("alert-1", "closed", disposition="benign", summary=f.closed_summary()),
    })
    stub.json("GET /api/v1/alerts/alert-0/events", f.decide_events("plan_response", "high_risk"))

    def actions(request: httpx.Request) -> httpx.Response:
        alert_id = request.url.params["alert_id"]
        rows = [f.action(alert_id, "awaiting_approval", created_at="2026-10-01T10:00:01+00:00")] if alert_id == "alert-0" else []
        return httpx.Response(200, json=f.page(rows))

    stub.routes["GET /api/v1/actions"] = actions
    server = await _server(stub, clock=FakeClock())
    handle = await _ingest(server, [f.dataset_item(0), f.dataset_item(1)])

    waited = _ok(await call(server, "wait_for_verdict", {"run_handle": handle}))["trusted"]
    assert [d["alert_id"] for d in waited["done"]] == ["alert-0", "alert-1"]
    assert waited["done"][0]["pending_actions"] == 1 and waited["done"][0]["route"] == "plan_response"

    listed = _ok(await call(server, "list_actions", {"run_handle": handle}))
    assert [i["trusted"]["alert_id"] for i in listed["items"]] == ["alert-0"]
    assert listed["items"][0]["trusted"]["approval"]["state"] == "pending"
    text = _error(await call(server, "list_actions", {"run_handle": handle, "alert_id": "elsewhere"}))
    assert "not an alert of this run" in text

    # A second wait answers from the outcomes already observed, without polling again.
    before = len(stub.requests)
    again = _ok(await call(server, "wait_for_verdict", {"run_handle": handle}))["trusted"]
    assert len(again["done"]) == 2 and len(stub.requests) == before


async def test_list_actions_by_run_handle_says_when_an_alert_has_more_actions_than_limit() -> None:
    stub = StubApi()
    _run_api(stub, {})

    def actions(request: httpx.Request) -> httpx.Response:
        alert_id, limit = request.url.params["alert_id"], int(request.url.params["limit"])
        if alert_id == "alert-0":  # 3 actions: one page of `limit`, and a cursor to the rest
            rows = [f.action(alert_id, "awaiting_approval", created_at=f"2026-10-01T10:00:0{i}+00:00") for i in range(3)]
            return httpx.Response(200, json=f.page(rows[:limit], next_cursor="c2" if limit < 3 else None))
        return httpx.Response(200, json=f.page([f.action(alert_id, "dry_run", created_at="2026-10-01T09:00:00+00:00")]))

    stub.routes["GET /api/v1/actions"] = actions
    server = await _server(stub)
    handle = await _ingest(server, [f.dataset_item(0), f.dataset_item(1)])

    listed = _ok(await call(server, "list_actions", {"run_handle": handle, "limit": 2}))

    assert [i["trusted"]["alert_id"] for i in listed["items"]] == ["alert-0", "alert-0"]
    assert listed["truncated"] is True and listed["next_cursor"] is None
    assert listed["omitted"] == [
        "items[2:3]",
        "more actions of alert alert-0 than the 2 read: list_actions(alert_id='alert-0') without run_handle pages "
        "through them",
    ]
    whole = _ok(await call(server, "list_actions", {"run_handle": handle, "limit": 5}))
    assert len(whole["items"]) == 4 and whole["truncated"] is False and whole["omitted"] == []


async def test_runs_are_bounded_and_the_oldest_is_forgotten() -> None:
    stub = StubApi()
    f.standard_routes(stub)
    server = await _server(stub)
    server.context.runs.max_runs = 2
    handles = [await _ingest(server, [f.dataset_item(i)]) for i in range(3)]
    text = _error(await call(server, "get_test_run", {"run_handle": handles[0]}))
    assert "unknown or expired run_handle" in text
    assert len(server.context.runs) == 2
