"""examples/soar/n8n/lg-sotf-response.json: importable n8n workflow for the signed webhook connector.

Structure checks run everywhere. When ``node`` is installed, the workflow's
Code nodes also run (in a small harness standing in for n8n's Code node:
``$input``, ``helpers.getBinaryDataBuffer``, ``$getWorkflowStaticData``,
``$vars``, ``$env``, ``$()``) against requests signed by the connector's own code.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import pytest

from lg_sotf.db.repos.actions import ResponseAction, action_idempotency_key
from lg_sotf.services.connectors import sign
from lg_sotf.services.connectors.webhook import (
    DEFAULT_TOLERANCE_S,
    EVENT,
    IDEMPOTENCY_HEADER,
    SCHEMA,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    build_payload,
    encode_body,
)
from lg_sotf.services.response import ACTION_CATALOG

WORKFLOW_PATH = Path(__file__).resolve().parents[3] / "examples" / "soar" / "n8n" / "lg-sotf-response.json"
SECRET = "-".join(("fake", "n8n", "webhook", "signing", "secret"))
NOW = 1_790_000_000.0
VERIFY = "Verify LG-SOTF signature"
GATE = "Authentic and new?"
ROUTE = "Route by action type"
RESULT = "Build LG-SOTF result"
UNSUPPORTED = "Unsupported action type"
RESPOND = "Respond to LG-SOTF"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")

HARNESS = r"""
const fs = require('fs');
const ctx = JSON.parse(fs.readFileSync(0, 'utf8'));
Date.now = () => ctx.now_ms;
const items = ctx.items.map((json) => ({ json }));
const staticData = ctx.static || {};
const helpers = {
  async getBinaryDataBuffer(index, property) {
    if (index !== 0 || property !== 'data' || ctx.raw_body_b64 === null) throw new Error('no binary data');
    return Buffer.from(ctx.raw_body_b64, 'base64');
  },
};
const $input = { first: () => items[0], all: () => items };
const $getWorkflowStaticData = (type) => {
  if (type !== 'global') throw new Error('unexpected static data type');
  return staticData;
};
const $vars = ctx.vars === null ? undefined : ctx.vars;
const $env = new Proxy({}, {
  get(_, key) {
    if (ctx.env === null) throw new Error('access to env vars denied');
    return ctx.env[key];
  },
});
const $ = (name) => {
  if (!(name in ctx.nodes)) throw new Error('unknown node ' + name);
  return { first: () => ({ json: ctx.nodes[name] }) };
};
const run = new Function(
  'require', 'helpers', '$input', '$getWorkflowStaticData', '$vars', '$env', '$',
  'return (async () => {\n' + ctx.code + '\n})();',
);
run(require, helpers, $input, $getWorkflowStaticData, $vars, $env, $)
  .then((out) => process.stdout.write(JSON.stringify({ items: out, static: staticData })))
  .catch((error) => process.stdout.write(JSON.stringify({ error: String(error && error.message) })));
"""


@pytest.fixture(scope="module")
def workflow() -> Dict[str, Any]:
    return json.loads(WORKFLOW_PATH.read_text(encoding="utf-8"))


def by_name(workflow: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {node["name"]: node for node in workflow["nodes"]}


def targets(workflow: Dict[str, Any], source: str) -> List[List[str]]:
    """Node names on each output of ``source``."""
    return [[link["node"] for link in output] for output in workflow["connections"].get(source, {}).get("main", [])]


# --------------------------------------------------------------------------- structure


def test_is_an_importable_workflow(workflow: Dict[str, Any]) -> None:
    names = [node["name"] for node in workflow["nodes"]]
    assert workflow["name"] and workflow["active"] is False and len(names) == len(set(names))
    ids = [node["id"] for node in workflow["nodes"]]
    assert len(ids) == len(set(ids))
    for node in workflow["nodes"]:
        assert node["type"].startswith("n8n-nodes-base.") and isinstance(node["typeVersion"], (int, float))
        assert len(node["position"]) == 2 and isinstance(node["parameters"], dict)
    for source, outputs in workflow["connections"].items():
        assert source in names
        for output in outputs["main"]:
            for link in output:
                assert link["node"] in names and link["type"] == "main"


def test_committed_json_matches_its_generator() -> None:
    spec = importlib.util.spec_from_file_location("lgsotf_n8n_build", WORKFLOW_PATH.parent / "build_workflow.py")
    assert spec is not None and spec.loader is not None
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert generator.render() == WORKFLOW_PATH.read_text(encoding="utf-8"), (
        "run python3 examples/soar/n8n/build_workflow.py and commit the regenerated workflow"
    )


def test_webhook_keeps_the_raw_body_and_answers_from_the_respond_node(workflow: Dict[str, Any]) -> None:
    (hook,) = [n for n in workflow["nodes"] if n["type"] == "n8n-nodes-base.webhook"]
    assert hook["parameters"]["httpMethod"] == "POST"
    assert hook["parameters"]["responseMode"] == "responseNode"
    assert hook["parameters"]["options"]["rawBody"] is True
    assert targets(workflow, hook["name"]) == [[VERIFY]]


def test_verify_node_uses_the_connector_scheme(workflow: Dict[str, Any]) -> None:
    code = by_name(workflow)[VERIFY]["parameters"]["jsCode"]
    for header in (SIGNATURE_HEADER, TIMESTAMP_HEADER, IDEMPOTENCY_HEADER):
        assert f"'{header.lower()}'" in code  # n8n exposes request headers in lower case
    assert f"'{SCHEMA}'" in code and f"'{EVENT}'" in code
    assert f"TOLERANCE_S = {DEFAULT_TOLERANCE_S}" in code
    assert "createHmac('sha256', secret).update(timestamp + '.').update(raw)" in code
    assert "timingSafeEqual" in code and "getBinaryDataBuffer(0, 'data')" in code
    # The secret is read from n8n variables or the environment, never written into the workflow.
    assert "$vars.LGSOTF_WEBHOOK_SECRET" in code and "$env.LGSOTF_WEBHOOK_SECRET" in code
    assert targets(workflow, VERIFY) == [[GATE]] and targets(workflow, GATE) == [[ROUTE], [RESPOND]]


def test_switch_has_one_branch_per_catalog_action(workflow: Dict[str, Any]) -> None:
    nodes = by_name(workflow)
    route = nodes[ROUTE]
    rules = route["parameters"]["rules"]["values"]
    keys = [rule["outputKey"] for rule in rules]
    missing = sorted(set(ACTION_CATALOG) - set(keys))
    assert not missing, f"add {missing} to ACTIONS in examples/soar/n8n/build_workflow.py and run it"
    assert len(keys) == len(set(keys))
    for rule in rules:
        (cond,) = rule["conditions"]["conditions"]
        assert cond["leftValue"] == "={{ $json.action_type }}" and cond["rightValue"] == rule["outputKey"]
        assert cond["operator"] == {"type": "string", "operation": "equals"}
    assert route["parameters"]["options"]["fallbackOutput"] == "extra"
    assert route["parameters"]["options"]["ignoreCase"] is False

    outputs = targets(workflow, ROUTE)
    assert len(outputs) == len(rules) + 1 and outputs[-1] == [UNSUPPORTED]
    for key, (name,) in zip(keys, outputs[:-1], strict=True):
        node = nodes[name]
        assert name.startswith(f"TODO {key}: ") and node["type"] == "n8n-nodes-base.httpRequest"
        # Placeholders are inert until configured: disabled, and aimed at a reserved, unresolvable name.
        assert node["disabled"] is True and urlsplit(node["parameters"]["url"]).hostname.endswith(".invalid")
        assert node["onError"] == "continueRegularOutput"
        assert node["parameters"]["options"]["response"]["response"] == {"fullResponse": True, "neverError": True}
        assert targets(workflow, name) == [[RESULT]]
    assert targets(workflow, RESULT) == [[RESPOND]] and targets(workflow, UNSUPPORTED) == [[RESPOND]]


def test_respond_node_returns_the_prepared_answer(workflow: Dict[str, Any]) -> None:
    respond = by_name(workflow)[RESPOND]
    assert respond["type"] == "n8n-nodes-base.respondToWebhook"
    assert respond["parameters"]["respondWith"] == "json"
    assert respond["parameters"]["responseBody"] == "={{ JSON.stringify($json.response) }}"
    assert respond["parameters"]["options"]["responseCode"] == "={{ $json.status_code }}"


# --------------------------------------------------------------------------- Code nodes under node


def make_action(**kw: Any) -> ResponseAction:
    now = datetime.now(UTC)
    base: Dict[str, Any] = dict(
        id=uuid.uuid4(), tenant_id="t1", alert_id="a1", action_type="isolate_host", target="ws-042",
        params={"playbook": "malware", "alert": {"severity": "high", "title": "C2 beacon"}}, risk_level="high",
        idempotency_key=action_idempotency_key("t1", "a1", "isolate_host", "ws-042"), status="executing",
        blocked_reason=None, requested_by="agent:workflow", approved_by="u1", approved_at=now, executed_at=now,
        connector="webhook", result=None, rollback_of=None, created_at=now, updated_at=now,
    )
    base.update(kw)
    return ResponseAction(**base)


def delivery(
    action: Optional[ResponseAction] = None, *, secret: str = SECRET, at: float = NOW
) -> Tuple[Dict[str, str], bytes, ResponseAction]:
    """What the n8n webhook node receives: lower-case headers and the raw body, signed by the connector's code."""
    action = action or make_action()
    body = encode_body(build_payload(action, target_type="host", sent_at=datetime.fromtimestamp(at, UTC)))
    timestamp = str(int(at))
    headers = {
        "content-type": "application/json",
        IDEMPOTENCY_HEADER.lower(): str(action.id),
        TIMESTAMP_HEADER.lower(): timestamp,
        SIGNATURE_HEADER.lower(): sign(secret, timestamp, body),
    }
    return headers, body, action


def run_code(
    workflow: Dict[str, Any],
    tmp_path: Path,
    node: str,
    items: List[Dict[str, Any]],
    *,
    raw: Optional[bytes] = None,
    static: Optional[Dict[str, Any]] = None,
    variables: Optional[Dict[str, str]] = None,
    env: Optional[Dict[str, str]] = None,
    now: float = NOW,
    nodes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    assert NODE is not None
    harness = tmp_path / "harness.js"
    harness.write_text(HARNESS)
    context = {
        "code": by_name(workflow)[node]["parameters"]["jsCode"],
        "items": items,
        "raw_body_b64": base64.b64encode(raw).decode() if raw is not None else None,
        "static": static or {},
        "vars": variables,
        "env": env,
        "now_ms": now * 1000,
        "nodes": nodes or {},
    }
    done = subprocess.run(
        [NODE, str(harness)], input=json.dumps(context), capture_output=True, text=True, timeout=30, check=True
    )
    return json.loads(done.stdout)


def verify(workflow: Dict[str, Any], tmp_path: Path, headers: Dict[str, str], body: bytes, **kw: Any) -> Dict[str, Any]:
    kw.setdefault("variables", {"LGSOTF_WEBHOOK_SECRET": SECRET})
    out = run_code(workflow, tmp_path, VERIFY, [{"headers": headers, "body": json.loads(body)}], raw=body, **kw)
    assert "error" not in out, out
    (item,) = out["items"]
    return item["json"]


@needs_node
def test_verify_accepts_a_request_signed_by_the_connector(workflow: Dict[str, Any], tmp_path: Path) -> None:
    headers, body, action = delivery()
    out = verify(workflow, tmp_path, headers, body)
    assert out["verdict"] == "execute" and out["action_type"] == "isolate_host" and out["action_id"] == str(action.id)
    assert out["action"]["target"] == "ws-042" and out["tenant_id"] == "t1"
    assert out["alert"] == {"id": "a1", "severity": "high", "title": "C2 beacon"}
    assert out["rollback_of"] is None


@needs_node
def test_verify_passes_the_original_action_id_of_a_rollback(workflow: Dict[str, Any], tmp_path: Path) -> None:
    original = make_action()
    rollback = make_action(action_type="release_host", rollback_of=original.id, execution_owner="scheduler")
    headers, body, _ = delivery(rollback)
    out = verify(workflow, tmp_path, headers, body)
    assert out["verdict"] == "execute" and out["action_type"] == "release_host"
    assert out["rollback_of"] == str(original.id)


@needs_node
@pytest.mark.parametrize("tamper", ["wrong_secret", "body", "timestamp", "key_mismatch", "no_signature"])
def test_verify_rejects_bad_signatures(workflow: Dict[str, Any], tmp_path: Path, tamper: str) -> None:
    headers, body, _ = delivery(secret="-".join(("fake", "other", "signing", "secret")) if tamper == "wrong_secret" else SECRET)
    if tamper == "body":
        body = body.replace(b"ws-042", b"ws-043")
    elif tamper == "timestamp":
        headers[TIMESTAMP_HEADER.lower()] = str(int(NOW) + 1)
    elif tamper == "key_mismatch":
        headers[IDEMPOTENCY_HEADER.lower()] = str(uuid.uuid4())
    elif tamper == "no_signature":
        del headers[SIGNATURE_HEADER.lower()]
    out = verify(workflow, tmp_path, headers, body)
    assert out["verdict"] == "reject" and out["status_code"] == 401
    assert out["response"] == {"status": "rejected", "error": "unauthorized"}


@needs_node
@pytest.mark.parametrize("skew, verdict", [(-301, "reject"), (-300, "execute"), (300, "execute"), (301, "reject")])
def test_verify_enforces_the_timestamp_window(workflow: Dict[str, Any], tmp_path: Path, skew: int, verdict: str) -> None:
    headers, body, _ = delivery(at=NOW + skew)
    assert verify(workflow, tmp_path, headers, body)["verdict"] == verdict


@needs_node
def test_verify_answers_a_repeated_action_with_the_stored_result(workflow: Dict[str, Any], tmp_path: Path) -> None:
    headers, body, action = delivery()
    first = verify(workflow, tmp_path, headers, body)
    vendor = {"statusCode": 200, "body": {"id": "machine-action-1"}, "headers": {}}
    done = run_code(workflow, tmp_path, RESULT, [vendor], nodes={VERIFY: first})
    (item,) = done["items"]
    assert item["json"]["response"] == {
        "status": "succeeded", "action_id": str(action.id), "action_type": "isolate_host", "detail": {"http_status": 200},
    }
    stored = done["static"]

    retry_headers, retry_body, _ = delivery(action, at=NOW + 30)  # re-signed retry of the same action
    again = verify(workflow, tmp_path, retry_headers, retry_body, static=stored, now=NOW + 30)
    assert again["verdict"] == "duplicate" and again["response"] == item["json"]["response"]

    moved = action.model_copy(update={"target": "ws-999"})
    conflict = verify(workflow, tmp_path, *delivery(moved)[:2], static=stored)
    assert conflict["status_code"] == 409 and conflict["response"]["error"] == "idempotency_conflict"


@needs_node
def test_verify_fails_closed_without_a_secret_or_raw_body(workflow: Dict[str, Any], tmp_path: Path) -> None:
    headers, body, _ = delivery()
    items = [{"headers": headers, "body": json.loads(body)}]
    out = run_code(workflow, tmp_path, VERIFY, items, raw=body, variables=None, env=None)
    assert "LGSOTF_WEBHOOK_SECRET" in out["error"]
    out = run_code(workflow, tmp_path, VERIFY, items, raw=body, variables={"LGSOTF_WEBHOOK_SECRET": "x" * 15}, env=None)
    assert "LGSOTF_WEBHOOK_SECRET" in out["error"]  # too short to be a webhook secret LG-SOTF accepts
    out = run_code(workflow, tmp_path, VERIFY, items, raw=None, variables={"LGSOTF_WEBHOOK_SECRET": SECRET})
    assert "Raw Body" in out["error"]
    via_env = run_code(workflow, tmp_path, VERIFY, items, raw=body, variables=None, env={"LGSOTF_WEBHOOK_SECRET": SECRET})
    assert via_env["items"][0]["json"]["verdict"] == "execute"


@needs_node
def test_verify_rejects_another_schema(workflow: Dict[str, Any], tmp_path: Path) -> None:
    action = make_action()
    payload = build_payload(action, target_type="host", sent_at=datetime.fromtimestamp(NOW, UTC))
    body = encode_body({**payload, "schema": "lg-sotf.response-action.v2"})
    headers = {IDEMPOTENCY_HEADER.lower(): str(action.id), TIMESTAMP_HEADER.lower(): str(int(NOW)),
               SIGNATURE_HEADER.lower(): sign(SECRET, str(int(NOW)), body)}
    out = verify(workflow, tmp_path, headers, body)
    assert out["verdict"] == "reject" and out["response"]["error"] == "unsupported_schema"


@needs_node
def test_result_node_maps_vendor_outcomes(workflow: Dict[str, Any], tmp_path: Path) -> None:
    headers, body, action = delivery()
    verified = verify(workflow, tmp_path, headers, body)
    nodes = {VERIFY: verified}

    passthrough = run_code(workflow, tmp_path, RESULT, [verified], nodes=nodes)  # TODO node still disabled
    assert passthrough["items"][0]["json"]["response"]["error"] == "not_implemented" and passthrough["static"] == {}

    for vendor, status in (
        ({"statusCode": 500, "body": "boom"}, "failed"),
        ({"error": {"message": "getaddrinfo ENOTFOUND todo.invalid"}}, "failed"),
        ({"statusCode": 202, "body": {}}, "succeeded"),
    ):
        out = run_code(workflow, tmp_path, RESULT, [vendor], nodes=nodes)
        assert out["items"][0]["json"]["status_code"] == 200
        assert out["items"][0]["json"]["response"]["status"] == status
        assert out["static"]["lgsotfActions"][str(action.id)]["response"]["status"] == status


@needs_node
def test_unsupported_node_rejects(workflow: Dict[str, Any], tmp_path: Path) -> None:
    out = run_code(workflow, tmp_path, UNSUPPORTED, [{"action_id": "x", "action_type": "wipe_host"}])
    assert out["items"][0]["json"] == {
        "status_code": 200,
        "response": {"status": "rejected", "error": "unsupported_action_type", "action_id": "x", "action_type": "wipe_host"},
    }
