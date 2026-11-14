/**
 * Descriptions of blocked_reason codes: the guardrail codes (lg_sotf.services.response GUARDRAIL_REASONS)
 * plus the reviewer rejection codes. tests/deploy/test_frontend_contracts.py checks the keys.
 */
export const GUARDRAIL_REASONS: Record<string, string> = {
  unknown_action: 'The action type is not in the action catalog.',
  action_not_allowed: "The tenant's allowed actions list does not include this action type.",
  target_type_not_allowed: 'The action does not accept this kind of target.',
  invalid_target: 'The target is empty, too long or malformed.',
  invalid_ip: 'The target is not an IP address.',
  invalid_domain: 'The target is not a valid domain name.',
  invalid_url: 'The target is not an http(s) URL with a host.',
  invalid_hash: 'The target is not an MD5/SHA-1/SHA-256/SHA-512 hex digest.',
  invalid_host: 'The target is not a valid host name.',
  invalid_user: 'The target is not a valid user name.',
  invalid_process: 'The target is not a valid process name.',
  invalid_email: 'The target is not an email address.',
  invalid_message: 'The target is not an Internet Message-ID.',
  internal_sender: "Senders from the tenant's own domains are never blocked; disable or reset the account instead.",
  unroutable_ip: 'Loopback, link-local, multicast, unspecified and reserved addresses are never blocked.',
  non_public_ip: 'Private addresses are blocked only when the tenant allows internal IP blocks.',
  protected_asset: "The target is on the tenant's protected assets list.",
  protected_assets_invalid: "The tenant's protected assets setting is malformed, so no action is allowed until it is fixed.",
  response_policy_invalid: "The tenant's response policy is malformed, so no action is allowed until it is fixed.",
  autonomy_disabled: "The tenant's autonomy policy disables actions of this risk level.",
  hourly_cap_reached: "The tenant's hourly action cap was reached.",
  blast_radius_exceeded: 'The hourly limit for this action type (blast radius) was reached.',
  approval_expired: 'The approval was not executed in time (response.approval_ttl_s) and expired.',
  approval_superseded: "The approval arrived while the alert's workflow was still running, and it ended without executing it.",
  rejected_by_reviewer: 'A reviewer rejected this action.',
  rejected_with_remaining: "A reviewer decided on other actions of this alert and rejected the remaining pending ones, including this one.",
};

/** Readable text for a stored blocked_reason (a code, or a code followed by detail). */
export function describeBlockedReason(reason: string): string {
  const code = reason.split(/[:\s]/, 1)[0];
  const known = GUARDRAIL_REASONS[reason] ?? GUARDRAIL_REASONS[code];
  if (!known) return reason;
  const detail = reason.slice(code.length).replace(/^[:\s]+/, '');
  return detail ? `${known} (${detail})` : known;
}
