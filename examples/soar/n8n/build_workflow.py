#!/usr/bin/env python3
"""Generates ``lg-sotf-response.json`` (the importable n8n workflow) from this file and ``code/*.js``.

Maintainers: edit the Code node sources in ``code/`` or the per-action table
below, then run ``python3 examples/soar/n8n/build_workflow.py`` and commit the
regenerated JSON. ``tests/unit/examples/test_soar_n8n.py`` fails when the JSON
is out of date or when an action type of LG-SOTF's catalog has no branch.

Node types and versions are chosen to exist in n8n 1.x and 2.x: Webhook 2,
Code 2, If 2, Switch 3, HTTP Request 4.2, Respond to Webhook 1.1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "lg-sotf-response.json"

WEBHOOK = "LG-SOTF webhook"
VERIFY = "Verify LG-SOTF signature"
GATE = "Authentic and new?"
ROUTE = "Route by action type"
RESULT = "Build LG-SOTF result"
UNSUPPORTED = "Unsupported action type"
RESPOND = "Respond to LG-SOTF"

# action type -> (what the placeholder node is for, JSON body fields, example vendor calls to verify)
ACTIONS: List[Tuple[str, str, str, str]] = [
    ("block_ip", "firewall or EDR indicator", "ip: $json.action.target",
     "Defender for Endpoint POST /api/indicators (IpAddress, Block); PAN-OS dynamic address group tag; "
     "Cloudflare IP access rule."),
    ("block_domain", "DNS or proxy block list", "domain: $json.action.target",
     "Defender for Endpoint indicator (DomainName, Block); Cisco Umbrella destination list."),
    ("block_url", "web proxy block list", "url: $json.action.target",
     "Defender for Endpoint indicator (Url, Block); Zscaler ZIA custom URL category, then activate."),
    ("isolate_host", "EDR network isolation", "host: $json.action.target",
     "Resolve the host to exactly one device first. Defender for Endpoint POST /api/machines/{id}/isolate; "
     "CrowdStrike devices-actions contain."),
    ("terminate_process", "EDR kill on the scoped hosts",
     "process: $json.action.target, hosts: ($json.action.params.scope || {}).hosts || []",
     "Only on params.scope.hosts; empty scope = do nothing. CrowdStrike Real Time Response kill."),
    ("quarantine_file", "EDR quarantine by hash",
     "hash: $json.action.target, hosts: ($json.action.params.scope || {}).hosts || []",
     "Defender for Endpoint POST /api/machines/{id}/StopAndQuarantineFile (SHA-1) per scoped host."),
    ("disable_user", "disable the account in the identity provider", "user: $json.action.target",
     "Microsoft Graph PATCH /v1.0/users/{id} {accountEnabled:false}; Okta lifecycle/suspend."),
    ("reset_password", "force a password reset in the identity provider", "user: $json.action.target",
     "Okta lifecycle/expire_password; AD Set-ADUser -ChangePasswordAtLogon via a runner."),
    ("revoke_sessions", "revoke sessions in the identity provider", "user: $json.action.target",
     "Microsoft Graph POST /v1.0/users/{id}/revokeSignInSessions; Okta DELETE /api/v1/users/{id}/sessions."),
    ("collect_forensics", "EDR evidence collection", "host: $json.action.target",
     "Defender for Endpoint POST /api/machines/{id}/collectInvestigationPackage; return the job id."),
    ("create_ticket", "ticketing system",
     "title: $json.alert.title, severity: $json.alert.severity, alert_id: $json.alert.id",
     "Only sent when the tenant has no ticketing integration in LG-SOTF. Jira POST /rest/api/3/issue; "
     "ServiceNow POST /api/now/table/incident."),
    ("send_alert", "SOC chat or paging", "text: 'LG-SOTF: ' + ($json.alert.title || $json.alert.id)",
     "Slack chat.postMessage; PagerDuty Events API v2 /v2/enqueue."),
    ("block_sender", "mail gateway sender block list", "sender: $json.action.target",
     "Microsoft 365: no Graph API; New-TenantAllowBlockListItems -ListType Sender -Block "
     "(Exchange Online PowerShell) from a runner."),
    ("purge_message", "mailbox purge (Message-ID, sender and subject)", "match: $json.action.params.match",
     "Match Message-ID AND sender AND subject. Microsoft Graph per mailbox: "
     "messages?$filter=internetMessageId eq '...' then move or delete."),
    ("notify_reporter", "email the reporter", "to: $json.action.params.reporter, alert_id: $json.alert.id",
     "Microsoft Graph POST /v1.0/users/{mailbox}/sendMail from a restricted shared mailbox."),
    ("confirm_compromised", "mark the account compromised in the risk engine", "user: $json.action.target",
     "Microsoft Graph POST /v1.0/identityProtection/riskyUsers/confirmCompromised {userIds:[id]} (Entra ID P2)."),
    # Rollbacks: the inverse type with the same target; rollback_of is the id of the action to undo.
    ("release_host", "lift EDR network isolation (rollback)",
     "host: $json.action.target, rollback_of: $json.rollback_of",
     "Defender for Endpoint POST /api/machines/{id}/unisolate; CrowdStrike devices-actions lift_containment."),
    ("unblock_ip", "remove the IP block (rollback)", "ip: $json.action.target, rollback_of: $json.rollback_of",
     "Delete the rule or indicator created for rollback_of: Defender for Endpoint DELETE /api/indicators/{id}."),
    ("unblock_domain", "remove the DNS or proxy block (rollback)",
     "domain: $json.action.target, rollback_of: $json.rollback_of",
     "Defender for Endpoint DELETE /api/indicators/{id}; Cisco Umbrella destination list remove."),
    ("unblock_url", "remove the web proxy block (rollback)", "url: $json.action.target, rollback_of: $json.rollback_of",
     "Defender for Endpoint DELETE /api/indicators/{id}; Zscaler ZIA REMOVE_FROM_LIST, then activate."),
    ("unblock_file", "remove the hash block (rollback)", "hash: $json.action.target, rollback_of: $json.rollback_of",
     "Defender for Endpoint DELETE /api/indicators/{id} of the file indicator created for rollback_of."),
    ("unblock_sender", "remove the sender block (rollback)",
     "sender: $json.action.target, rollback_of: $json.rollback_of",
     "Microsoft 365: Remove-TenantAllowBlockListItems -ListType Sender (Exchange Online PowerShell) from a runner."),
    ("enable_user", "re-enable the account (rollback)", "user: $json.action.target, rollback_of: $json.rollback_of",
     "Microsoft Graph PATCH /v1.0/users/{id} {accountEnabled:true}; Okta lifecycle/unsuspend."),
    ("restore_message", "restore the purged messages (rollback)",
     "message_id: $json.action.target, rollback_of: $json.rollback_of",
     "Move back exactly the items the purge of rollback_of removed: Microsoft Graph "
     "POST /v1.0/users/{id}/messages/{item}/move to the original folder."),
    ("dismiss_user_risk", "dismiss the account risk (rollback)",
     "user: $json.action.target, rollback_of: $json.rollback_of",
     "Microsoft Graph POST /v1.0/identityProtection/riskyUsers/dismiss {userIds:[id]}."),
]

README = (
    "## LG-SOTF response actions\n"
    "Receives the signed POST that LG-SOTF sends for each approved action "
    "(schema `lg-sotf.response-action.v1`).\n\n"
    "1. Store the tenant's webhook secret as the n8n variable `LGSOTF_WEBHOOK_SECRET` "
    "(or environment variable, with `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`). Never paste it into a node.\n"
    "2. Self-hosted: set `NODE_FUNCTION_ALLOW_BUILTIN=crypto` (on the task runners too).\n"
    "3. For each action type you handle: configure the **TODO** node (URL, credential, body), then enable it. "
    "Disabled nodes answer `rejected` / `not_implemented`.\n"
    "4. Activate the workflow and set the production URL as the tenant's webhook URL in LG-SOTF.\n\n"
    "Rollbacks arrive as their own action types (`release_host`, `unblock_ip`, ...) with `rollback_of` "
    "set to the id of the action to undo.\n\n"
    "The vendor calls in the node notes are examples: verify them against your vendor's API documentation. "
    "See docs/soar-playbooks.md."
)


def todo_name(action: str, purpose: str) -> str:
    return f"TODO {action}: {purpose}"


def _link(name: str) -> Dict[str, Any]:
    return {"node": name, "type": "main", "index": 0}


def _equals(condition_id: str, left: str, right: str) -> Dict[str, Any]:
    return {
        "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict"},
        "conditions": [
            {"id": condition_id, "leftValue": left, "rightValue": right, "operator": {"type": "string", "operation": "equals"}}
        ],
        "combinator": "and",
    }


def _code(node_id: str, name: str, source: str, position: List[int], notes: str) -> Dict[str, Any]:
    return {
        "parameters": {"jsCode": (HERE / "code" / source).read_text(encoding="utf-8").rstrip() + "\n"},
        "id": node_id,
        "name": name,
        "type": "n8n-nodes-base.code",
        "typeVersion": 2,
        "position": position,
        "notes": notes,
    }


def build_workflow() -> Dict[str, Any]:
    top = -(len(ACTIONS) * 120) // 2
    nodes: List[Dict[str, Any]] = [
        {
            "parameters": {"content": README, "height": 420, "width": 520},
            "id": "lgsotf-readme",
            "name": "Read me",
            "type": "n8n-nodes-base.stickyNote",
            "typeVersion": 1,
            "position": [-40, -560],
        },
        {
            "parameters": {
                "httpMethod": "POST",
                "path": "lg-sotf-response",
                "responseMode": "responseNode",
                "options": {"rawBody": True},
            },
            "id": "lgsotf-webhook",
            "name": WEBHOOK,
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 2,
            "position": [0, 0],
        },
        _code(
            "lgsotf-verify", VERIFY, "verify-signature.js", [240, 0],
            "HMAC-SHA256 over '<timestamp>.<raw body>', 5-minute window, Idempotency-Key = action.id, "
            "dedup on action.id.",
        ),
        {
            "parameters": {"conditions": _equals("lgsotf-verdict-execute", "={{ $json.verdict }}", "execute"), "options": {}},
            "id": "lgsotf-gate",
            "name": GATE,
            "type": "n8n-nodes-base.if",
            "typeVersion": 2,
            "position": [480, 0],
        },
        {
            "parameters": {
                "rules": {
                    "values": [
                        {
                            "conditions": _equals(f"lgsotf-route-{action}", "={{ $json.action_type }}", action),
                            "renameOutput": True,
                            "outputKey": action,
                        }
                        for action, *_ in ACTIONS
                    ]
                },
                "options": {"fallbackOutput": "extra", "renameFallbackOutput": "unsupported", "ignoreCase": False},
            },
            "id": "lgsotf-route",
            "name": ROUTE,
            "type": "n8n-nodes-base.switch",
            "typeVersion": 3,
            "position": [720, -40],
        },
    ]
    for index, (action, purpose, fields, notes) in enumerate(ACTIONS):
        nodes.append(
            {
                "parameters": {
                    "method": "POST",
                    # A reserved name that never resolves: nothing is called until you configure the node.
                    "url": f"https://todo.invalid/{action.replace('_', '-')}",
                    "sendBody": True,
                    "specifyBody": "json",
                    "jsonBody": "={{ JSON.stringify({ " + fields + ", lgsotf_action_id: $json.action_id }) }}",
                    "options": {"response": {"response": {"fullResponse": True, "neverError": True}}, "timeout": 10000},
                },
                "id": f"lgsotf-todo-{action}",
                "name": todo_name(action, purpose),
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4.2,
                "position": [1040, top + index * 120],
                "disabled": True,
                "onError": "continueRegularOutput",
                "notes": "Example to verify: " + notes,
                "notesInFlow": True,
            }
        )
    nodes += [
        _code(
            "lgsotf-unsupported", UNSUPPORTED, "unsupported-action.js", [1040, top + len(ACTIONS) * 120],
            "Action types without a branch are answered rejected (never silently succeeded).",
        ),
        _code(
            "lgsotf-result", RESULT, "build-result.js", [1360, 0],
            "2xx from the vendor = succeeded, anything else = failed; remembered for 7 days for deduplication.",
        ),
        {
            "parameters": {
                "respondWith": "json",
                "responseBody": "={{ JSON.stringify($json.response) }}",
                "options": {
                    "responseCode": "={{ $json.status_code }}",
                    "responseHeaders": {"entries": [{"name": "Cache-Control", "value": "no-store"}]},
                },
            },
            "id": "lgsotf-respond",
            "name": RESPOND,
            "type": "n8n-nodes-base.respondToWebhook",
            "typeVersion": 1.1,
            "position": [1600, 0],
        },
    ]
    connections: Dict[str, Any] = {
        WEBHOOK: {"main": [[_link(VERIFY)]]},
        VERIFY: {"main": [[_link(GATE)]]},
        GATE: {"main": [[_link(ROUTE)], [_link(RESPOND)]]},
        ROUTE: {"main": [[_link(todo_name(a, p))] for a, p, *_ in ACTIONS] + [[_link(UNSUPPORTED)]]},
        **{todo_name(a, p): {"main": [[_link(RESULT)]]} for a, p, *_ in ACTIONS},
        UNSUPPORTED: {"main": [[_link(RESPOND)]]},
        RESULT: {"main": [[_link(RESPOND)]]},
    }
    return {
        "name": "LG-SOTF response actions",
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"executionOrder": "v1"},
        "pinData": {},
        "tags": [],
    }


def render() -> str:
    return json.dumps(build_workflow(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT
    target.write_text(render(), encoding="utf-8")
    print(f"wrote {target}")
