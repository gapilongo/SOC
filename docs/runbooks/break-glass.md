# Runbook: break-glass access

Break-glass is the emergency way in for a platform operator when nobody can
sign in the normal way. It trades the usual proof of identity (password,
MFA, your identity provider) for one sealed credential, so it is built to be
loud: every use is written to the audit log and mailed to every platform
admin before the session exists.

It is off until an operator turns it on in the deployment's configuration.
No API call and no tenant setting can turn it on.

## When to use it

Use it only when all of these are true:

* something must be done in LG-SOTF now (an incident is running, a customer
  is locked out, a response action must be stopped);
* no platform admin can sign in with their own password and MFA;
* the faster, narrower fixes below do not apply.

Try these first. They need the same level of access as break-glass set-up
(the deployment), and they are also audited:

| Situation | Use instead |
|---|---|
| The identity provider is down, platform admins still have their local accounts | Sign in locally. Platform admins never depend on the IdP ([identity.md](../identity.md#oidc-never-grants-platform-admin)). |
| One platform admin lost the authenticator and recovery codes | `lg-sotf reset-mfa --tenant <id> --email <email>` ([identity.md](../identity.md#recovery-procedures)) |
| No platform-admin account is left, or all are deactivated | `lg-sotf create-admin` with `--platform-admin` |

Do not use break-glass for routine work, to skip MFA because it is
inconvenient, or to test something. A drill is the only planned use, and it
is announced (see [Drill](#drill)).

## What it gives you, and what limits it

| Property | Detail |
|---|---|
| Who | The session is that of one active platform-admin account, named by its email. Its password and MFA are not asked for. |
| How long | `auth.break_glass_ttl_s`, 10 minutes by default (60 to 900 seconds, never longer than a normal access token). There is no refresh token: the session ends on its own and cannot be extended. Sign in again if you need longer; that alerts again. |
| Where | The API only (`Authorization: Bearer`). The web UI needs a refresh cookie and cannot use this session. |
| Audit | `auth.break_glass_used` in the account's tenant: the account, the source address, the reason, the session's token id and end. Written in the same transaction as the alerts. |
| Alert | One email per active platform admin of the install, in every tenant, through the install's SMTP (`integrations.smtp_*`). The list is read before the session exists. It is not an integration: no tenant admin can disable or delete it. |
| Not silent | If the audit entry or the alerts cannot be written, the sign-in fails and no session is issued. Without SMTP configured the endpoint stays off. |
| Failed attempts | `401`, audited as `auth.break_glass_failed` (reason `bad_credential` or `unknown_account`) in the bootstrap tenant's audit log, and rate-limited per client address like a login (`api.login_rate_limit_per_minute`). |

## Set-up (once, and after every use)

You need access to the deployment's secrets and a shell in an LG-SOTF
container.

1. Check that SMTP is configured (`LG_SOTF_INTEGRATIONS__SMTP_HOST`,
   `LG_SOTF_INTEGRATIONS__SMTP_FROM`). In staging and production the
   processes refuse to start with a break-glass credential and no SMTP.
2. Generate a credential and its hash:

   ```
   lg-sotf break-glass-credential
   ```

   It prints the credential once and the line to configure. Nothing is
   stored.
3. Seal the credential: write it down or print it, put it in a tamper-evident
   envelope in a safe, or store it in a vault entry whose access is itself
   logged and alerts. Record who holds it. Do not keep it in a password
   manager that platform admins use every day, and never next to the
   deployment's secrets.
4. Put the hash in the deployment's secret store as
   `LG_SOTF_AUTH__BREAK_GLASS_CREDENTIAL_HASH` and restart the API. The value
   contains `$` characters: quote it in env files (single quotes) so the
   shell or Compose does not expand it.
5. Run the [drill](#drill) to prove the alert reaches every platform admin.

To turn break-glass off, remove the variable and restart the API. The
endpoint then answers `404`.

## Using it

1. Open the envelope or vault entry. If you can, tell another platform
   admin by phone first; they are about to get the email.
2. Sign in. The reason is mandatory (10 to 300 characters): say what is
   broken and give the incident or ticket number.

   ```
   curl -sS https://<host>/api/v1/auth/break-glass \
     -H 'Content-Type: application/json' \
     -d '{"email": "<platform admin email>", "credential": "<sealed credential>", "reason": "IdP outage, incident INC-123"}'
   ```

   Add `"tenant": "<tenant id>"` if the same email is a platform admin in
   several tenants. The answer carries `access_token` and `expires_in`.
3. Do the one thing that restores normal access, with
   `Authorization: Bearer <access_token>` (and `X-Tenant-ID: <tenant>` to act
   on a customer tenant; each such request is audited in that tenant as
   `platform_admin.tenant_access`). Typical repairs:

   | Goal | Call |
   |---|---|
   | Let a locked-out admin sign in again | `POST /api/v1/users/{id}/mfa/reset`, or `PATCH /api/v1/users/{id}` with a new password |
   | Create a replacement admin | `POST /api/v1/users` |
   | Stop a tenant | `PATCH /api/v1/platform/tenants/{id}` with `{"status": "suspended"}` |

   See [api.md](../api.md) for the full list.
4. End the session as soon as you are done; do not wait for it to expire:

   ```
   curl -sS -X POST https://<host>/api/v1/auth/logout -H 'Authorization: Bearer <access_token>'
   ```

5. Go on to [After use](#after-use).

## If you get the alert and did not expect it

The email subject starts with `[LG-SOTF security] Break-glass access used`
and names the account, the source address and the reason. Treat an
unexpected one as a compromise of the sealed credential.

1. Call the holder of the credential and the person named in the mail. If
   nobody did it, continue.
2. Turn break-glass off: remove `LG_SOTF_AUTH__BREAK_GLASS_CREDENTIAL_HASH`
   and restart the API. Sessions already issued end within
   `auth.break_glass_ttl_s`; to end them at once, rotate
   `LG_SOTF_AUTH__JWT_SECRET` ([operations.md](../operations.md#7-key-rotation)).
3. Read what the session did: the audit log of the account's tenant from the
   `auth.break_glass_used` entry until its `expires_at`, with the account as
   actor, and `platform_admin.tenant_access` entries of that actor in every
   other tenant. Undo what should not stay (new users, API keys, grants,
   integrations, changed settings).
4. Find out how the credential leaked before generating a new one.

## After use

Always, also after a drill:

1. Rotate the credential: repeat [Set-up](#set-up-once-and-after-every-use)
   steps 2 to 4. The used credential stops working when the API restarts
   with the new hash. A credential that left its envelope is not sealed any
   more.
2. Check the record: the `auth.break_glass_used` entry exists, every platform
   admin got the email, and the actions taken in the session match the
   reason given.
3. Write the incident note: who, when, why, what was done, when the
   credential was rotated, who holds the new one.

## Drill

Run it after set-up, then at least every six months and after a change of
the identity provider, the SMTP relay or the list of platform admins.
Announce it to the platform admins beforehand, and use a reason that starts
with `DRILL`.

| # | Step | Expected | Record |
|---|---|---|---|
| 1 | Announce the drill and its time window | | Date, who runs it, who was told |
| 2 | Send a wrong credential once | `401 invalid_credentials`; no email | Time; the `auth.break_glass_failed` entry (bootstrap tenant) |
| 3 | Fetch the sealed credential | The seal is intact; the access is logged where it is stored | Who fetched it, how long it took |
| 4 | Sign in with reason `DRILL <date>` | `200`, `expires_in` at most 900 | Time of the call |
| 5 | Call `GET /api/v1/auth/me` with the token | The named account, `is_platform_admin: true` | |
| 6 | Check the alert | Every active platform admin received the email | Minutes from step 4 to the last mailbox; anyone who did not get it, and why |
| 7 | Check the audit log | `auth.break_glass_used` with the account, source address, reason and `admins_notified` equal to the number of platform admins | The entry's id |
| 8 | End the session (`POST /api/v1/auth/logout`), then repeat step 5 | `401` | |
| 9 | Try `POST /api/v1/auth/refresh` | `401`: the session cannot be extended | |
| 10 | Rotate the credential and seal the new one | The old credential now gets `401` | Time of rotation; the new holder |
| 11 | Review | | What was slow or unclear; changes to this runbook; date of the next drill |

Keep the filled-in table with your security records. A drill fails if any
platform admin did not get the email, or if the credential could be fetched
without leaving a trace.

## Reference

| Item | Value |
|---|---|
| Endpoint | `POST /api/v1/auth/break-glass` with `{"email", "credential", "reason", "tenant"?}`; `404` while off |
| Settings | `auth.break_glass_credential_hash`, `auth.break_glass_ttl_s` ([configuration.md](../configuration.md)) |
| Audit actions | `auth.break_glass_used` (the account's tenant), `auth.break_glass_failed` (the bootstrap tenant) |
| Log events | `auth.break_glass_used`, `auth.break_glass_failed` (level warning) |
| Delivery | Outbox rows with operation `email`, retried like other deliveries; metric `lgsotf_integration_deliveries_total{kind="email"}` |
| Threat model | TM-MSP-7 and TM-MSP-9 in [threat-model.md](../threat-model.md) |

**If the sealed credential is stolen.** The thief also needs the email of a
platform admin and network access to the API. They then get a platform-admin
API session of at most `auth.break_glass_ttl_s`, as often as they repeat the
sign-in: every tenant can be read and configured (accounts and API keys
included), but the session itself cannot decide escalations or approve
actions in a customer tenant. Each sign-in is
detected at once: the audit entry and the email to every platform admin are
committed before the token is returned, the recipient list cannot be edited
from inside the session, and a failed guess is audited and rate-limited. The
response is the section above: turn it off, rotate, review the window.
