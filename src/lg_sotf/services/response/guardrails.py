"""The response guardrails: the first rule an action fails blocks it, before approval and again before execution.

Malformed policy fails closed. When the guardrail keys of ``response`` (or
the top-level ``autonomy``) do not match the schema, every action is blocked
with ``response_policy_invalid``; when ``protected_assets`` /
``protected_cidrs`` are malformed or hold more than
:data:`MAX_PROTECTED_ENTRIES` entries per list, every action on a host, user,
address, domain, URL, hash or process is blocked with
``protected_assets_invalid``. Both are logged with the problems found.

Guardrails, in order (the first that fails blocks the action, and blocked
actions can never be approved later):

0. the tenant's response policy and protected assets are well formed;
1. the action type is known and allowed by the tenant's allowlist;
2. the target kind is one the action accepts (:data:`ACTION_TARGET_KINDS`);
3. the target is syntactically valid for its kind;
4. IP blocks never target loopback, link-local, multicast, unspecified or
   reserved addresses (also when embedded in IPv4-mapped, 6to4, NAT64,
   Teredo or IPv4-compatible IPv6 addresses), and target private/CGNAT/ULA
   addresses only when the tenant sets ``allow_internal_ip_blocks``;
5. protected hosts, users, domains (and their subdomains) and CIDRs are never
   acted on, whatever the target's spelling (sender addresses are checked by
   their domain and as a whole address; senders of the tenant's own
   ``tools.internal_domains`` are never blocked: disable or reset the account
   instead): IP literals in host, domain and
   URL targets (including the decimal/hex/octal IPv4 forms browsers accept
   and IPv6 forms embedding an IPv4 address) are checked against protected
   CIDRs; domain and URL hosts are checked against protected host names;
   user names are compared as written, as the CN/UID of a DN and as the bare
   account (``DOMAIN\\user``, ``domain/user``, ``user@domain``); names are
   compared case-insensitively after Unicode NFKC normalisation with
   invisible format characters removed;
6. the tenant's autonomy policy is not ``disabled`` for the action's risk.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

from lg_sotf.domain.actions import (
    ACTION_CATALOG,
    ACTION_TARGET_KINDS,
    FORWARD_OF,
    GUARDRAIL_REASONS,
    POLICY_INVALID_REASON,
    PROTECTED_INVALID_REASON,
)
from lg_sotf.services.response.policy import ResponsePolicy
from lg_sotf.services.response.targets import ip_block_class, validate_target


@dataclass(frozen=True)
class GuardrailBlock:
    code: str
    detail: str

    @property
    def explanation(self) -> str:
        return f"{GUARDRAIL_REASONS.get(self.code, self.code)}: {self.detail}" if self.detail else GUARDRAIL_REASONS.get(
            self.code, self.code
        )


def check_guardrails(
    action_type: str,
    target: str,
    policy: ResponsePolicy,
    *,
    target_kind: Optional[str] = None,
    restorative: bool = False,
) -> Optional[GuardrailBlock]:
    """The first guardrail the action fails (module docstring, rules 0-6), or ``None``.

    ``restorative`` (a rollback that undoes one of our own changes) skips the
    non-public-IP, protected-asset and internal-sender rules: releasing a host
    that became protected after it was isolated must stay possible. An
    inverse type passes the ``allowed_actions`` allowlist when it or its
    forward type is listed; autonomy is checked against its own risk.
    """
    spec = ACTION_CATALOG.get(action_type)
    if spec is None:
        return GuardrailBlock("unknown_action", action_type[:64])
    if policy.problems:
        return GuardrailBlock(POLICY_INVALID_REASON, "; ".join(policy.problems)[:300])
    if policy.allowed_actions is not None and not (
        action_type in policy.allowed_actions or FORWARD_OF.get(action_type) in policy.allowed_actions
    ):
        return GuardrailBlock("action_not_allowed", action_type)
    kind = target_kind or spec.target_kind
    if kind not in ACTION_TARGET_KINDS[action_type]:
        return GuardrailBlock("target_type_not_allowed", f"{action_type} accepts {sorted(ACTION_TARGET_KINDS[action_type])}, got {kind[:32]}")
    invalid = validate_target(kind, target)
    if invalid is not None:
        return GuardrailBlock(invalid, "")
    if kind != "alert" and policy.protected.invalid:
        return GuardrailBlock(PROTECTED_INVALID_REASON, "; ".join(policy.protected.problems)[:300])
    if kind == "ip":
        cls = ip_block_class(ipaddress.ip_address(target.strip("[]")))
        if cls == "unroutable":
            return GuardrailBlock("unroutable_ip", "")
        if cls == "internal" and not policy.allow_internal_ip_blocks and not restorative:
            return GuardrailBlock("non_public_ip", "tenant setting response.allow_internal_ip_blocks is off")
    if not restorative:
        category = policy.protected.match(kind, target)
        if category is not None:
            return GuardrailBlock("protected_asset", f"matches a protected {category} entry")
        if kind == "email" and policy.internal_sender(target):
            return GuardrailBlock("internal_sender", "")
    if policy.autonomy.get(spec.risk) == "disabled":
        return GuardrailBlock("autonomy_disabled", f"{spec.risk} risk")
    return None
