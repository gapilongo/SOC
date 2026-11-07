"""The response action catalog: every action type, its target kind and risk, and the guardrail reason codes.

:data:`ACTION_CATALOG` is the one list of action types the response service
plans, guards and executes; the connectors and the Microsoft capability
catalog read it from here. :mod:`lg_sotf.services.response` re-exports every
name. :data:`GUARDRAIL_REASONS` explains each stable ``blocked_reason`` code
written on a ledger row.

Pure values: standard library only, no I/O (docs/adr/0001-layering.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Literal, Optional

__all__ = [
    "ACTION_CATALOG",
    "ACTION_TARGET_KINDS",
    "APPROVAL_EXPIRED_REASON",
    "APPROVAL_SUPERSEDED_REASON",
    "BLAST_RADIUS_REASON",
    "DEFAULT_BLAST_RADIUS",
    "FORWARD_OF",
    "GUARDRAIL_REASONS",
    "HOURLY_CAP_REASON",
    "POLICY_INVALID_REASON",
    "PROTECTED_INVALID_REASON",
    "ActionSpec",
    "TargetKind",
    "guardrail_result",
]

TargetKind = Literal["ip", "domain", "url", "hash", "user", "host", "process", "alert", "email", "message"]
# Stable ``blocked_reason`` codes the response service writes itself (the rest are literals in its guardrails).
HOURLY_CAP_REASON = "hourly_cap_reached"
BLAST_RADIUS_REASON = "blast_radius_exceeded"
POLICY_INVALID_REASON = "response_policy_invalid"
APPROVAL_EXPIRED_REASON = "approval_expired"
APPROVAL_SUPERSEDED_REASON = "approval_superseded"
PROTECTED_INVALID_REASON = "protected_assets_invalid"


@dataclass(frozen=True)
class ActionSpec:
    target_kind: TargetKind
    risk: str
    containment: bool
    description: str
    # An entity kind the plan must have for the action to be proposed (its values go into the params).
    requires: Optional[str] = None
    # The type that undoes this one (a rollback is a new ledger row of that type).
    inverse: Optional[str] = None
    # False: never proposed by playbooks or recommendations (only rollbacks create it).
    plannable: bool = True
    # Undoes one of our own changes: rollbacks of it skip the non-public-IP, protected-asset and
    # internal-sender guardrails, so an asset protected after the change can still be released.
    restorative: bool = False
    # What a rollback cannot undo, or what stays in effect after the action (shown in the UI).
    irreversible_note: str = ""


ACTION_CATALOG: Dict[str, ActionSpec] = {
    "block_ip": ActionSpec("ip", "medium", True, "Block an IP address at the perimeter", inverse="unblock_ip"),
    "block_domain": ActionSpec("domain", "medium", True, "Block a domain in DNS/proxy", inverse="unblock_domain"),
    "block_url": ActionSpec("url", "medium", True, "Block a URL in the web proxy", inverse="unblock_url"),
    "isolate_host": ActionSpec("host", "high", True, "Network-isolate a host through EDR", inverse="release_host"),
    "terminate_process": ActionSpec(
        "process", "medium", True, "Terminate a process through EDR",
        irreversible_note="a terminated process is not restarted by a rollback",
    ),
    "quarantine_file": ActionSpec(
        "hash", "low", True, "Quarantine a file by hash through EDR", inverse="unblock_file"
    ),
    "disable_user": ActionSpec("user", "critical", True, "Disable a user account", inverse="enable_user"),
    "reset_password": ActionSpec(
        "user", "critical", True, "Force a password reset",
        irreversible_note="the previous password cannot be restored",
    ),
    "revoke_sessions": ActionSpec(
        "user", "high", True, "Revoke a user's active sessions",
        irreversible_note="existing access tokens stay valid until they expire, about 1 h",
    ),
    "collect_forensics": ActionSpec(
        "host", "low", False, "Collect forensic evidence from a host",
        irreversible_note="a collected investigation package cannot be un-collected",
    ),
    "create_ticket": ActionSpec("alert", "low", False, "Open an incident ticket"),
    "send_alert": ActionSpec("alert", "low", False, "Notify the SOC channel"),
    "block_sender": ActionSpec(
        "email", "medium", True, "Block a sender address in the mail gateway", inverse="unblock_sender"
    ),
    "purge_message": ActionSpec(
        "message", "high", True, "Remove a message (by Message-ID, sender and subject) from every mailbox",
        inverse="restore_message",
    ),
    "notify_reporter": ActionSpec(
        "alert", "low", False, "Tell the user who reported the email what was found", requires="reporter",
        irreversible_note="a sent notification cannot be recalled",
    ),
    "confirm_compromised": ActionSpec(
        "user", "high", True, "Confirm a user as compromised in Entra ID Protection", inverse="dismiss_user_risk"
    ),
    # Inverse types: created only by rollbacks, never planned.
    "release_host": ActionSpec(
        "host", "high", False, "Release a host from network isolation", plannable=False, restorative=True
    ),
    "unblock_ip": ActionSpec(
        "ip", "medium", False, "Remove an IP address block", plannable=False, restorative=True
    ),
    "unblock_domain": ActionSpec(
        "domain", "medium", False, "Remove a domain block", plannable=False, restorative=True
    ),
    "unblock_url": ActionSpec("url", "medium", False, "Remove a URL block", plannable=False, restorative=True),
    "unblock_file": ActionSpec(
        "hash", "medium", False, "Remove a file hash block", plannable=False, restorative=True
    ),
    "unblock_sender": ActionSpec(
        "email", "medium", False, "Remove a sender block", plannable=False, restorative=True
    ),
    "enable_user": ActionSpec(
        "user", "critical", False, "Re-enable a disabled user account", plannable=False, restorative=True
    ),
    "restore_message": ActionSpec(
        "message", "high", False, "Restore a removed message to the mailboxes it was removed from",
        plannable=False, restorative=True,
    ),
    "dismiss_user_risk": ActionSpec(
        "user", "high", False, "Dismiss a user's risk in Entra ID Protection", plannable=False, restorative=True
    ),
}

# Forward type of each inverse type (``release_host`` -> ``isolate_host``).
FORWARD_OF: Dict[str, str] = {spec.inverse: name for name, spec in ACTION_CATALOG.items() if spec.inverse}

ACTION_TARGET_KINDS: Dict[str, FrozenSet[str]] = {name: frozenset({spec.target_kind}) for name, spec in ACTION_CATALOG.items()}

# Per action type, how many may start executing per tenant per hour (tenants may override).
DEFAULT_BLAST_RADIUS: Dict[str, int] = {
    "isolate_host": 5,
    "disable_user": 3,
    "reset_password": 5,
    "revoke_sessions": 10,
    "terminate_process": 20,
    "quarantine_file": 20,
    "purge_message": 10,
    "block_sender": 20,
    "release_host": 5,
    "enable_user": 3,
    "restore_message": 10,
    "confirm_compromised": 10,
    "dismiss_user_risk": 5,
}

GUARDRAIL_REASONS: Dict[str, str] = {
    "unknown_action": "the action type is not in the action catalog",
    "action_not_allowed": "the tenant's allowed_actions list does not include this action type",
    "target_type_not_allowed": "the action does not accept this kind of target",
    "invalid_target": "the target is empty, too long or malformed",
    "invalid_ip": "the target is not an IP address",
    "invalid_domain": "the target is not a valid domain name",
    "invalid_url": "the target is not an http(s) URL with a host",
    "invalid_hash": "the target is not an MD5/SHA-1/SHA-256/SHA-512 hex digest",
    "invalid_host": "the target is not a valid host name",
    "invalid_user": "the target is not a valid user name",
    "invalid_process": "the target is not a valid process name",
    "invalid_email": "the target is not an email address",
    "invalid_message": "the target is not an Internet Message-ID",
    "internal_sender": "senders of the tenant's own domains are never blocked (disable or reset the account instead)",
    "unroutable_ip": "loopback, link-local, multicast, unspecified and reserved addresses are never blocked",
    "non_public_ip": "private/internal addresses are blocked only when the tenant allows internal IP blocks",
    "protected_asset": "the target is on the tenant's protected assets list",
    PROTECTED_INVALID_REASON: (
        "the tenant's protected assets setting is malformed or too large, so no action on hosts, users, "
        "addresses, domains, URLs, files or processes is allowed until it is fixed"
    ),
    POLICY_INVALID_REASON: "the tenant's response policy is malformed, so no action is allowed until it is fixed",
    "autonomy_disabled": "the tenant's autonomy policy disables actions of this risk level",
    HOURLY_CAP_REASON: "the tenant's hourly action cap was reached",
    BLAST_RADIUS_REASON: "the hourly limit for this action type (blast radius) was reached",
    APPROVAL_EXPIRED_REASON: "the approval was not executed within response.approval_ttl_s and expired",
    APPROVAL_SUPERSEDED_REASON: (
        "the approval arrived while the alert's workflow run was still active, and the run ended without "
        "executing it"
    ),
}


def guardrail_result(code: str, /, **detail: Any) -> Dict[str, Any]:
    """The ``result`` of a row a guardrail blocked after planning: the code, its explanation, then ``detail``."""
    return {"guardrail": code, "explanation": GUARDRAIL_REASONS.get(code, code), **detail}
