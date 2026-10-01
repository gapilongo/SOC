"""Handler stubs for the LG-SOTF reference receiver: one function per action type.

Every stub answers ``rejected`` with ``not_implemented``, so LG-SOTF never
records an action as done until you connect it to a real system. Replace the
body of the stubs you use with your vendor call and return:

* ``Outcome.succeeded(reference=...)`` when the change was made, or was
  already in place (an existing block, an already isolated host);
* ``Outcome.failed(error, message)`` when it was attempted and did not happen;
* raise ``RetryLater()`` only when the vendor surely did nothing (429, 503,
  connection refused): LG-SOTF then sends the same action again.

LG-SOTF waits for the answer (15 s by default, ``response.webhook_timeout_s``):
start long jobs (forensic packages, mailbox-wide purges) and return once the
vendor has accepted them, with its job id as ``reference``.

Targets were validated by LG-SOTF's guardrails, but they came from alert data:
URL-encode them in paths, escape them in query languages (OData, KQL, SPL) and
never pass them to a shell. The vendor calls named below are well-known
examples; check each against your vendor's current API documentation and give
the integration only the permissions it needs.
"""

from __future__ import annotations

from typing import Dict

from lgsotf_receiver import Action, Handler, Outcome


def not_implemented(action: Action) -> Outcome:
    return Outcome.rejected("not_implemented", f"no integration is configured for {action.type}")


def block_ip(action: Action) -> Outcome:
    """Block ``action.target`` (an IPv4/IPv6 address) at the perimeter.

    Examples: Defender for Endpoint ``POST /api/indicators`` (indicatorType
    ``IpAddress``, action ``Block``); PAN-OS tag the address into a dynamic
    address group; Cloudflare IP access rule (mode ``block``).
    """
    return not_implemented(action)


def block_domain(action: Action) -> Outcome:
    """Block ``action.target`` (a domain name) in DNS or the web proxy.

    Examples: Defender for Endpoint indicator ``DomainName`` / ``Block``;
    Cisco Umbrella destination list ``POST .../destinationlists/{id}/destinations``.
    """
    return not_implemented(action)


def block_url(action: Action) -> Outcome:
    """Block ``action.target`` (an http(s) URL) in the web proxy.

    Examples: Defender for Endpoint indicator ``Url`` / ``Block``; Zscaler ZIA
    add to a custom URL category, then activate the change.
    """
    return not_implemented(action)


def isolate_host(action: Action) -> Outcome:
    """Network-isolate the host named ``action.target`` through the EDR.

    Resolve the name to exactly one device first (refuse ambiguous matches).
    Examples: Defender for Endpoint ``POST /api/machines/{id}/isolate``;
    CrowdStrike ``POST /devices/entities/devices-actions/v2?action_name=contain``.
    """
    return not_implemented(action)


def terminate_process(action: Action) -> Outcome:
    """Terminate the process ``action.target`` on the hosts in ``action.scope_hosts`` only.

    An empty scope means the alert named no host: do not act fleet-wide.
    Example: CrowdStrike Real Time Response ``kill`` in a session on each host.
    """
    return not_implemented(action)


def quarantine_file(action: Action) -> Outcome:
    """Quarantine the file with hash ``action.target`` on the hosts in ``action.scope_hosts``.

    Examples: Defender for Endpoint ``POST /api/machines/{id}/StopAndQuarantineFile``
    (SHA-1) per host; a tenant-wide block is a Defender indicator
    ``FileSha256`` / ``BlockAndRemediate``.
    """
    return not_implemented(action)


def disable_user(action: Action) -> Outcome:
    """Disable the account ``action.target`` (critical risk: LG-SOTF requires an admin approval).

    Examples: Microsoft Graph ``PATCH /v1.0/users/{id}`` with
    ``{"accountEnabled": false}``; Okta ``POST /api/v1/users/{id}/lifecycle/suspend``.
    """
    return not_implemented(action)


def reset_password(action: Action) -> Outcome:
    """Force a password reset for ``action.target``.

    Examples: Okta ``POST /api/v1/users/{id}/lifecycle/expire_password``;
    Active Directory ``Set-ADUser -ChangePasswordAtLogon $true`` from a runner.
    """
    return not_implemented(action)


def revoke_sessions(action: Action) -> Outcome:
    """Revoke the sessions and refresh tokens of ``action.target``.

    Examples: Microsoft Graph ``POST /v1.0/users/{id}/revokeSignInSessions``;
    Okta ``DELETE /api/v1/users/{id}/sessions``.
    """
    return not_implemented(action)


def collect_forensics(action: Action) -> Outcome:
    """Start an evidence collection on the host ``action.target``; return the job id as ``reference``.

    Example: Defender for Endpoint ``POST /api/machines/{id}/collectInvestigationPackage``.
    """
    return not_implemented(action)


def create_ticket(action: Action) -> Outcome:
    """Open an incident ticket for ``action.alert`` (the target is ``alert:<id>``).

    Only reaches the SOAR when the tenant has no ticketing integration in
    LG-SOTF. Examples: Jira ``POST /rest/api/3/issue``; ServiceNow
    ``POST /api/now/table/incident``.
    """
    return not_implemented(action)


def send_alert(action: Action) -> Outcome:
    """Notify the SOC channel about ``action.alert``.

    Examples: Slack ``chat.postMessage``; PagerDuty Events API v2 ``POST /v2/enqueue``.
    """
    return not_implemented(action)


def block_sender(action: Action) -> Outcome:
    """Block the sender address ``action.target`` in the mail gateway.

    Microsoft 365 has no Graph API for the Tenant Allow/Block List: run
    ``New-TenantAllowBlockListItems -ListType Sender -Block -Entries <address>``
    (Exchange Online PowerShell) from an automation runner.
    """
    return not_implemented(action)


def purge_message(action: Action) -> Outcome:
    """Remove the message from every mailbox, matching ``action.message_match``.

    A Message-ID is chosen by the sender: match it *and* the sender and subject
    when they are given. Example: Microsoft Graph per mailbox
    ``GET /v1.0/users/{id}/messages?$filter=internetMessageId eq '<id>'`` then
    move or delete the matching message.
    """
    return not_implemented(action)


def notify_reporter(action: Action) -> Outcome:
    """Tell the reporter (``action.params["reporter"]``) what the analysis found.

    Example: Microsoft Graph ``POST /v1.0/users/{mailbox}/sendMail`` from a
    shared mailbox the application is restricted to.
    """
    return not_implemented(action)


def confirm_compromised(action: Action) -> Outcome:
    """Mark the account ``action.target`` as compromised in the identity provider's risk engine.

    Example: Microsoft Graph ``POST /v1.0/identityProtection/riskyUsers/confirmCompromised``
    with ``{"userIds": ["<object id>"]}`` (Entra ID P2).
    """
    return not_implemented(action)


# Rollbacks. LG-SOTF sends them as actions of the inverse type, with the same
# target, once an analyst asked to undo an action this receiver executed:
# ``action.rollback_of`` is the id of that original action. Undo what you did
# for it (the ``reference`` you answered then), and answer ``succeeded`` when
# it is already undone.


def release_host(action: Action) -> Outcome:
    """Lift the network isolation of the host ``action.target`` (rollback of ``isolate_host``).

    Examples: Defender for Endpoint ``POST /api/machines/{id}/unisolate``;
    CrowdStrike ``POST /devices/entities/devices-actions/v2?action_name=lift_containment``.
    """
    return not_implemented(action)


def unblock_ip(action: Action) -> Outcome:
    """Remove the block of ``action.target`` created for ``action.rollback_of`` (rollback of ``block_ip``).

    Example: Defender for Endpoint ``DELETE /api/indicators/{id}`` of the indicator you created.
    """
    return not_implemented(action)


def unblock_domain(action: Action) -> Outcome:
    """Remove the DNS or proxy block of ``action.target`` (rollback of ``block_domain``).

    Examples: Defender for Endpoint ``DELETE /api/indicators/{id}``; Cisco Umbrella
    ``DELETE .../destinationlists/{id}/destinations/remove``.
    """
    return not_implemented(action)


def unblock_url(action: Action) -> Outcome:
    """Remove the web proxy block of ``action.target`` (rollback of ``block_url``).

    Examples: Defender for Endpoint ``DELETE /api/indicators/{id}``; Zscaler ZIA
    ``PUT /api/v1/urlCategories/{id}?action=REMOVE_FROM_LIST``, then activate.
    """
    return not_implemented(action)


def unblock_file(action: Action) -> Outcome:
    """Remove the hash block or quarantine of ``action.target`` (rollback of ``quarantine_file``).

    Example: Defender for Endpoint ``DELETE /api/indicators/{id}`` of the file
    indicator you created. A file stopped and quarantined per host has no
    documented undo call: answer ``failed`` and restore it by hand.
    """
    return not_implemented(action)


def unblock_sender(action: Action) -> Outcome:
    """Remove the sender block of ``action.target`` (rollback of ``block_sender``).

    Microsoft 365: ``Remove-TenantAllowBlockListItems -ListType Sender -Entries <address>``
    (Exchange Online PowerShell) from an automation runner.
    """
    return not_implemented(action)


def enable_user(action: Action) -> Outcome:
    """Re-enable the account ``action.target`` (rollback of ``disable_user``; critical risk).

    Examples: Microsoft Graph ``PATCH /v1.0/users/{id}`` with
    ``{"accountEnabled": true}``; Okta ``POST /api/v1/users/{id}/lifecycle/unsuspend``.
    """
    return not_implemented(action)


def restore_message(action: Action) -> Outcome:
    """Put back the messages removed for ``action.rollback_of`` (rollback of ``purge_message``).

    Restore exactly the items the purge removed (keep their ids and original
    folders in the purge's ``reference`` or your own store). Example:
    Microsoft Graph ``POST /v1.0/users/{id}/messages/{message id}/move`` back
    to the original folder.
    """
    return not_implemented(action)


def dismiss_user_risk(action: Action) -> Outcome:
    """Dismiss the risk of the account ``action.target`` (rollback of ``confirm_compromised``).

    Example: Microsoft Graph ``POST /v1.0/identityProtection/riskyUsers/dismiss``
    with ``{"userIds": ["<object id>"]}``.
    """
    return not_implemented(action)


# Every action type LG-SOTF can send (lg_sotf.services.response.ACTION_CATALOG).
HANDLERS: Dict[str, Handler] = {
    "block_ip": block_ip,
    "block_domain": block_domain,
    "block_url": block_url,
    "isolate_host": isolate_host,
    "terminate_process": terminate_process,
    "quarantine_file": quarantine_file,
    "disable_user": disable_user,
    "reset_password": reset_password,
    "revoke_sessions": revoke_sessions,
    "collect_forensics": collect_forensics,
    "create_ticket": create_ticket,
    "send_alert": send_alert,
    "block_sender": block_sender,
    "purge_message": purge_message,
    "notify_reporter": notify_reporter,
    "confirm_compromised": confirm_compromised,
    "release_host": release_host,
    "unblock_ip": unblock_ip,
    "unblock_domain": unblock_domain,
    "unblock_url": unblock_url,
    "unblock_file": unblock_file,
    "unblock_sender": unblock_sender,
    "enable_user": enable_user,
    "restore_message": restore_message,
    "dismiss_user_risk": dismiss_user_risk,
}
