# Microsoft Entra ID direct response

The Entra package contains a compromised user in Microsoft Entra ID through
Microsoft Graph v1.0: it disables the account, revokes sign-in sessions,
resets the password to one nobody knows, and confirms the user as
compromised in ID Protection. Each action proves itself by re-reading the
user, and the two reversible ones can be rolled back. The shared framework
(the live switches, routing, rehearsal, verification, rollback and the
connection test) is described in [Microsoft direct response](microsoft.md).

## 1. Overview

| Capability | Actions | Reversible | Options |
|---|---|---|---|
| `entra.account` | `disable_user`, `enable_user` (its rollback) | yes | `allow_guests` (default off), `allow_synced_users` (default on) |
| `entra.sessions` | `revoke_sessions` | no | none |
| `entra.password` | `reset_password` | no | `require_mfa_on_change` (default off) |
| `entra.risk` | `confirm_compromised`, `dismiss_user_risk` (its compensating rollback) | yes (compensating) | none |

All four capabilities use Graph v1.0 only (no beta endpoint) and are
available in the `global`, `usgov_gcc_high` and `usgov_dod` clouds.

Every action follows the same steps:

1. **Resolve** the target to exactly one user and its object id (below).
   Every later request addresses `/v1.0/users/{object id}`.
2. **Refuse** what this capability does not act on: guests and synced
   users where noted, and any **privileged** user (the guard below).
3. **Checkpoint** `{user_id, requested: true, ...}` into the ledger row
   before the write, so a re-run after a crash adopts the earlier attempt
   instead of acting twice.
4. **Write**, then **re-read** the user to prove the change (`verified`)
   or schedule a later check (`pending`).

When the capability is enabled but not **Live**, the action is a
*rehearsal*: steps 1 and 2 run with GET requests only and the row is
recorded `dry_run` with `result.resolved`:

```json
{"would_execute": {"method": "PATCH", "path_template": "/v1.0/users/{id}"},
 "user": {"id": "<object id>", "upn": "alice@contoso.com", "synced": false, "user_type": "Member"},
 "guard": "passed"}
```

`guard` is `"passed"` or the refusal (`{"refused": "privileged_target_refused", "reason": "directory_role"}`).
The `entra.risk` rehearsal also shows the user's current risk (or
`risk_error: "not_licensed"`).

Suggested containment order for a confirmed account takeover: disable the
account, revoke sessions, confirm compromised, then reset the password (an
admin password reset can move the user's risk to `remediated`).

### Resolving the user

The ledger target is untrusted alert data. It is validated and encoded
before it reaches a URL or a filter:

* An **object id** (GUID): `GET /v1.0/users/{id}`.
* A **user principal name or email address**: `GET /v1.0/users/{upn}`
  (percent-encoded; a guest's `#EXT#` becomes `%23EXT%23`; a UPN starting
  with `$` uses the key form `/v1.0/users('{upn}')` with inner quotes
  doubled, because Graph answers the plain form with 400).
* Graph resolves `/users/{x}` by object id or UPN only: a mail or proxy
  address that is not the UPN answers `404 Request_ResourceNotFound`. On a
  404 LG-SOTF runs four separate default queries (no `ConsistencyLevel`:
  advanced queries read an eventually consistent index):
  `userPrincipalName eq '<t>'`, `mail eq '<t>'`,
  `proxyAddresses/any(x:x eq 'smtp:<t>')` and
  `proxyAddresses/any(x:x eq 'SMTP:<t>')`. Quotes in the value are
  doubled and the whole value is percent-encoded once (`+` as `%2B`,
  `'` as `%27`, `#` as `%23`, `&` as `%26`).
* Exactly one distinct object id must match: none is `not_found`, more
  than one `ambiguous_target` (use the object id or UPN instead).
* `DOMAIN\user` and bare account names are `invalid_target`: Graph cannot
  resolve them.

Every read selects the properties it needs
(`id,userPrincipalName,mail,userType,accountEnabled,onPremisesSyncEnabled,signInSessionsValidFromDateTime,lastPasswordChangeDateTime`):
Graph returns most of them only when selected. A `202 Accepted` counts as
success.

### The privileged-target guard

Before **every** write of this package, including the rollbacks
`enable_user` and `dismiss_user_risk`, the guard refuses the action with
`privileged_target_refused` when the user:

| `reason` | Read |
|---|---|
| `directory_role`: holds an active directory role | `GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '<id>'` (and an activated `directoryRole` in `memberOf`) |
| `role_assignable_group`: is a member of a role-assignable group | `GET /v1.0/users/{id}/memberOf?$select=id,isAssignableToRole,isMemberManagementRestricted` (up to 2,000 objects, paged) |
| `restricted_admin_unit`: is a member of a restricted management administrative unit | the same `memberOf` read (`isMemberManagementRestricted`) |
| `role_assignable_group_owner`: owns a role-assignable group | `GET /v1.0/users/{id}/ownedObjects?$select=id,isAssignableToRole` |

Only a Privileged Authentication Administrator or a Global Administrator
may disable, reset or revoke such users, and a member of a restricted
management administrative unit can be changed only by a role scoped to
that unit (application permissions do not apply there at all). Holding
those roles would make the SOC daemon a Tier-0 identity. LG-SOTF refuses
instead and the refusal goes to a human.

The guard **fails closed**. Any of these gives
`privileged_guard_unavailable` and nothing is written:

* a 403 or another error on any of the three reads (a 403 is never retried);
* a group or administrative unit without the flag it needs (without
  `GroupMember.Read.All`, Graph returns directory objects with an id only);
* more than 2,000 memberships or owned objects.

Throttling and token failures are not guard failures: the action is
deferred or fails with the credential error, and nothing is written either
way.

**Gaps.** PIM-*eligible* role assignments that are not activated are not
returned by `roleAssignments` and are not seen: a user who is only eligible
for Global Administrator is not refused. List PIM-eligible
administrators in `protected_assets.users` in the tenant settings.

**Protected users.** `protected_assets.users` is checked twice: by the
guardrails against the action's target as the alert gives it, and by the
Entra package against the user that target *resolves* to, before any
write. An alias, a proxy address or an object id of a protected user
therefore gets `protected_asset` too (the UPN, `mail` and object id are
matched; the result names the resolved user). Rollbacks (`enable_user`,
`dismiss_user_risk`) are exempt, as in the guardrails: undoing LG-SOTF's
own change stays possible after the user became protected. Which permission
Microsoft requires to read `ownedObjects` and administrative-unit
membership app-only is still to be confirmed in a lab tenant; until then
the guard fails closed when the answer is incomplete.

## 2. Actions and Microsoft calls

### `disable_user` (`entra.account`)

1. Resolve; refuse a guest (`guest_refused`) unless `allow_guests`, and a
   synced user (`synced_user_refused`) when `allow_synced_users` is off;
   run the guard.
2. Already disabled: `succeeded` with `already: true`, `changed: false` and
   nothing to roll back. The exception is a re-run of an action whose
   earlier attempt did it (`external_ref.requested`): that stays reversible.
3. Checkpoint `{user_id, prior: {accountEnabled: true}, synced, requested}`.
4. `PATCH /v1.0/users/{id}` with `{"accountEnabled": false}`, which answers
   `204`. The request is idempotent, so `409 Directory_ConcurrencyViolation`,
   `429` and `503` are retried.
5. Re-read with `GET /v1.0/users/{id}?$select=id,accountEnabled` (up to
   three reads, a second apart, in case a replica lags):

   | Observed | Outcome |
   |---|---|
   | disabled, cloud-only user | `verified` |
   | disabled, synced user | verification `pending` (first check after 40 minutes, until 60 minutes): the disable is temporary until the on-premises account is disabled too |
   | still enabled | `failed` with `error: "not_verified"` and `observed` (retryable) |

`result.synced` and `result.note` flag a synced user.

### `enable_user` (rollback of `disable_user`)

Runs only when the disable changed something (`prior.accountEnabled` true
and `requested`); otherwise `succeeded` with `error: "rollback_not_needed"`.
The user is the **recorded object id**, not the name (which may since
belong to someone else). The guard runs again: a user who became
privileged is not re-enabled by LG-SOTF. Then
`PATCH /v1.0/users/{id} {"accountEnabled": true}` and an inline re-read.

### `revoke_sessions` (`entra.sessions`)

1. Resolve; refuse guests (`guest_refused`: a guest's sessions live in
   their home tenant); run the guard.
2. A re-run of this action whose earlier attempt already moved
   `signInSessionsValidFromDateTime` to the execution time sends nothing
   (`already: true`). A recent revocation by *someone else* does not skip
   the call: an attacker could revoke their own sessions and sign in again.
3. `POST /v1.0/users/{id}/revokeSignInSessions` (no body; any 2xx is
   success; idempotent).
4. Re-read `signInSessionsValidFromDateTime`: at or after the execution time
   (minus 60 s of clock skew) is `verified`, otherwise `pending`.

It invalidates refresh tokens and browser session cookies. **Access tokens
already issued stay valid until they expire (about 1 hour)** unless the
application supports continuous access evaluation (CAE), and sessions an
application issued itself are not revoked. Disable the account first when
that hour matters.

### `reset_password` (`entra.password`)

1. Resolve; refuse guests (`guest_refused`) and synced users
   (`synced_user_refused`: reset the password on-premises); run the guard.
2. A re-run whose earlier attempt already reset the password
   (`lastPasswordChangeDateTime` at or after the execution time) sends
   nothing. A recent change by anyone else, possibly the attacker, does not
   skip the reset.
3. `PATCH /v1.0/users/{id}` with
   `{"passwordProfile": {"password": <random>, "forceChangePasswordNextSignIn": true, "forceChangePasswordNextSignInWithMfa": <require_mfa_on_change>}}`,
   which answers `204`.
4. Re-read `lastPasswordChangeDateTime` and `passwordProfile` (below).

The password is 40 characters from a cryptographic random source, with
upper case, lower case, digits and symbols. It is **never** logged,
checkpointed, stored in the ledger, returned, or put in an error: it
exists only in the request to Microsoft. The user gets back in through the
helpdesk or a Temporary Access Pass.

The force flag is never sent without a new password: whoever knows the
current password (the attacker) would get to choose the next one.

The request is not idempotent (each call sets another password), so it is
not retried after a network error. The action is deferred and its re-run
reads `lastPasswordChangeDateTime` first. `passwordProfile` cannot be used
for federated users: a 400 whose code names federation is `federated_user`,
any other 400 `bad_request` (only the error code is kept).

### `confirm_compromised` (`entra.risk`)

1. Resolve; run the guard.
2. Read the prior risk with `GET /v1.0/identityProtection/riskyUsers/{id}`
   and the header `Prefer: include-unknown-enum-members`. A 404 means no
   risk record. Both a plain object and the documented `{"value": [...]}`
   wrapper are parsed.
3. Already `confirmedCompromised`: `succeeded` with `already: true` and
   nothing to roll back.
4. Checkpoint `{user_id, prior: {riskState, riskLevel}, requested}`.
5. `POST /v1.0/identityProtection/riskyUsers/confirmCompromised` with
   `{"userIds": ["<id>"]}` (204; idempotent). This sets the user's risk to
   high (`riskState: confirmedCompromised`,
   `riskDetail: adminConfirmedUserCompromised`), so risk-based Conditional
   Access policies apply to the user.

### `dismiss_user_risk` (rollback of `confirm_compromised`)

Runs only when the confirmation changed something; otherwise `succeeded`
with `error: "rollback_not_needed"`. It uses the recorded object id and
runs the guard, then sends
`POST /v1.0/identityProtection/riskyUsers/dismiss {"userIds": ["<id>"]}`
(204). A risk already dismissed or at level `none` sends nothing.
`result.note` says "the earlier risk state was not restored".

### Result fields

Besides the framework's fields (`connector`, `capability`, `live`,
`summary`, `changed`, `already`, and on failure `error`, `http_status`,
`ms_code`, `request_id`, `retryable`, `hint`), results carry
`user: {id, upn}`. Refusals also carry the refusal's `reason` (and for
`privileged_guard_unavailable`, the `step`). `external_ref` holds `user_id`,
`upn`, `requested`, `reversible` and, for the reversible types, `prior`
(`synced` for accounts).

## 3. Permissions and setup

Use the single-tenant app registration described in
[Microsoft direct response](microsoft.md#2-app-registration). Add these
**Microsoft Graph application permissions** for the capabilities you
enable, then select **Grant admin consent** (again after every change):

| Permission | Capabilities | Purpose |
|---|---|---|
| `User.Read.All` | all | resolve the user (least privilege for reading users) |
| `RoleManagement.Read.Directory` | all | privileged-target guard: active role assignments |
| `GroupMember.Read.All` | all | privileged-target guard: `isAssignableToRole` of groups the user belongs to or owns |
| `User.EnableDisableAccount.All` | `entra.account` | disable and enable the account (Microsoft requires `User.Read.All` with it) |
| `User.RevokeSessions.All` | `entra.sessions` | revoke refresh tokens and session cookies (the only application permission for it) |
| `User-PasswordProfile.ReadWrite.All` | `entra.password` | reset the password and require a change |
| `IdentityRiskyUser.ReadWrite.All` | `entra.risk` | confirm compromised and dismiss risk |
| `IdentityRiskyUser.Read.All` | `entra.risk` | read the user's risk (the read lists only this permission) |

Do not grant broader permissions such as `User.ReadWrite.All` or
`Directory.ReadWrite.All`: nothing in this package needs them.

**Directory role.** App-only changes of `accountEnabled` and
`passwordProfile` also need an administrator role on the app's service
principal. Assign **User Administrator** at tenant scope: in the Entra
admin center go to *Roles & admins > User Administrator > Add assignments*
and select the app (its enterprise application). User Administrator covers
non-administrators and the limited administrator roles Microsoft lists
(Helpdesk, Password, Groups and User Administrators, Directory Readers,
Guest Inviter, Message Center Reader, Reports Reader, Usage Summary
Reports Reader).

**Never** assign Privileged Authentication Administrator or Global
Administrator to the app. Privileged targets are refused by the guard on
purpose and escalated to a human; those roles would make LG-SOTF a Tier-0
identity.

Tokens do not show directory roles, so the connection test reports
`User Administrator` as `unknown` with guidance. The probes it runs are
GETs only:

| Capability | Probes |
|---|---|
| `entra.account` | `GET /v1.0/users?$top=1&$select=id,accountEnabled`, `GET /v1.0/roleManagement/directory/roleAssignments?$top=1` |
| `entra.sessions` | `GET /v1.0/users?$top=1&$select=id,signInSessionsValidFromDateTime` |
| `entra.password` | `GET /v1.0/users?$top=1&$select=id,lastPasswordChangeDateTime` |
| `entra.risk` | `GET /v1.0/identityProtection/riskyUsers?$top=1` (403: `forbidden`, or `not_licensed` when the code names a licence) |

**Hybrid (synced) users.** A cloud disable of a synced user is undone by
the next Entra Connect sync cycle (30 minutes by default) unless the
on-premises account is disabled too; a cloud password reset of a synced
user is overwritten. Microsoft's emergency-revocation guidance for hybrid
users has **human steps** that LG-SOTF does not perform:

* disable the on-premises account (`Disable-ADAccount`);
* reset the on-premises password twice (against pass-the-hash);
* disable the user's registered devices (not possible app-only: listing a
  user's devices is not supported for applications, and changing a
  device's `accountEnabled` needs the Cloud Device Administrator role).

Turn `allow_synced_users` off to refuse synced users in `entra.account`
instead of disabling them temporarily.

## 4. Verification

| Action | Verified when | Pending (first check, maximum) | Failed |
|---|---|---|---|
| `disable_user` | `accountEnabled` is false (cloud-only users inline) | synced users: 40 min, 60 min | `reverted_by_sync` (synced) or `re_enabled`: the account is enabled again |
| `enable_user` | `accountEnabled` is true (inline) | only when the inline read failed | `disabled_again` |
| `revoke_sessions` | `signInSessionsValidFromDateTime` at or after the execution time minus 60 s | 30 s, 10 min | never (it becomes `inconclusive` at the deadline) |
| `reset_password` | `lastPasswordChangeDateTime` at or after the execution time minus 60 s, and `forceChangePasswordNextSignIn` true when Graph returns `passwordProfile` | 30 s, 10 min | never (it becomes `inconclusive` at the deadline) |
| `confirm_compromised` | `riskState` is `confirmedCompromised` and not `isProcessing` | 60 s, 30 min | never (it becomes `inconclusive` at the deadline) |
| `dismiss_user_risk` | `riskState` is `dismissed` or `riskLevel` is `none`, and not `isProcessing` | 60 s, 30 min | never |

A user deleted in the meantime makes the check `inconclusive`. An inline re-read that fails (throttled, 403) never turns a
change Microsoft accepted into a failure: verification continues later.
Revocation can take a few minutes to show, and ID Protection processes
confirmations asynchronously.

## 5. Rollback

| Original | Rollback | Kind |
|---|---|---|
| `disable_user` | `enable_user` (critical risk) | true inverse: re-enables the account, only if it was enabled before and this action disabled it |
| `confirm_compromised` | `dismiss_user_risk` (high risk) | **compensating**: it dismisses the user's risk; the earlier risk state and level (kept in `prior`) cannot be restored |
| `revoke_sessions` | none | irreversible: revoked sessions cannot be restored |
| `reset_password` | none | irreversible: the old password cannot be restored |

A rollback is approved under the normal role and risk rules. It is always
executed by the scheduler with the recorded object id, runs the guard
again, and is verified like any other action. An action that changed
nothing (`already: true`) has nothing to roll back
(`rollback_unavailable` with the reason `nothing_changed`).

## 6. Limits and licensing

* **ID Protection** (`entra.risk`) needs **Microsoft Entra ID P2** (or
  Microsoft Entra Suite). Without it the probe reports `not_licensed`, and
  actions fail with `not_licensed` when the 403 error code names a licence,
  otherwise with `permission_denied` whose hint mentions both causes.
  Microsoft does not document the error code returned without P2.
* The risky-user endpoints allow about one request per second per tenant
  and send no `Retry-After`; the client backs off on 429.
* Not supported: PIM-eligible (inactive) roles in the guard; disabling
  devices; on-premises Active Directory actions; the delegated-only
  `authenticationMethod resetPassword` API (the reset uses
  `passwordProfile`); guests for sessions and passwords.
* Not verified yet in a lab tenant (see [Microsoft direct response](microsoft.md#13-limitations-and-follow-ups)):
  whether app-only `revokeSignInSessions` needs a directory role for
  limited-administrator targets; which permission reads `ownedObjects` and
  administrative-unit membership; whether the `proxyAddresses` prefix
  comparison is case-insensitive (both prefixes are queried); whether
  `passwordProfile` on a synced user without password writeback fails (and
  with which code); whether a Graph password reset moves the user's risk to
  `remediated`; the 403 code of ID Protection without P2; whether
  `riskyUsers/{id}` answers 404 for a user without risk history.

## 7. Troubleshooting

| Ledger `error` | Meaning | What to do |
|---|---|---|
| `permission_denied` (`ms_code: Authorization_RequestDenied`) | Microsoft refused the write. The code does not tell a missing application permission from a missing directory role or an out-of-scope target | Check the permission and its admin consent, the **User Administrator** assignment of the service principal, and whether the target is a privileged or restricted user the guard could not see (for example a PIM-eligible administrator who activated a role). Never retried automatically |
| `not_found` (`ms_code: Request_ResourceNotFound`) | No user with this object id, UPN, mail or proxy address (after the four fallback queries), or the user was deleted | Check the target in the alert; use the object id or UPN |
| `ambiguous_target` | Several users share the address (mail or proxy addresses) | Use the object id or UPN |
| `invalid_target` | `DOMAIN\user`, a bare name or a malformed address | Use the UPN or object id |
| `Directory_ConcurrencyViolation` (409) | A concurrent directory change | Retried automatically (up to `response.microsoft_retries`) for the idempotent writes; if it persists the action fails with `bad_request` and can be retried |
| `protected_asset` | The target resolved to a user on the tenant's protected assets list (by UPN, mail or object id), although the alert named an alias or an id | Intended: a human acts; the result's `user` shows who the target resolved to |
| `privileged_target_refused` | The guard found a directory role, a role-assignable group (member or owner) or a restricted management administrative unit | Intended: a human with the right role acts |
| `privileged_guard_unavailable` | The guard could not read (`reason`: `forbidden`, `incomplete_read`, `too_many_objects`, or an error) | Grant `RoleManagement.Read.Directory` and `GroupMember.Read.All` with admin consent; retry transient errors |
| `guest_refused`, `synced_user_refused` | The capability does not act on this kind of user | See the options and the hybrid steps above |
| `federated_user` | `passwordProfile` cannot be used for federated users | Reset the password at the identity provider |
| `not_verified` | Microsoft accepted the change but the account still reads as before | Retry; look for an automation or sync that reverts it |
| `not_licensed` | ID Protection is not licensed | Microsoft Entra ID P2 or Entra Suite |
| `throttled` | Microsoft kept throttling the call through `response.max_execution_attempts` attempts (until then the action is deferred and re-run by the scheduler) | Retry later |

Only Microsoft's error `code` and request id are kept, never its message
text; the request id (`request_id`) is what Microsoft support asks for.
