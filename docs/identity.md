# Identity: MFA, single sign-on and provisioning

LG-SOTF supports two ways to sign in:

* **Local accounts**: email and password (argon2id), optionally with a
  time-based one-time password (TOTP) as a second factor. Platform admins of
  a multi-tenant (MSSP) install always use a local account.
* **OIDC single sign-on**: bearer tokens from your identity provider (IdP),
  optionally with just-in-time (JIT) provisioning of the local user record
  and role mapping from IdP groups.

SAML is not built in; connect a SAML IdP through an OIDC broker
([below](#saml-through-an-oidc-broker)).

Every setting mentioned here is listed in [configuration.md](configuration.md);
the endpoints are summarised in [api.md](api.md#authentication).

## TOTP MFA for local accounts

### What the user sees

1. The user enters email and password as before.
2. If the account has MFA, the sign-in page asks for the 6-digit code from
   the authenticator app (Microsoft Authenticator, Google Authenticator,
   1Password, FreeOTP, ...). A **Use a recovery code** link accepts one of
   the ten recovery codes instead.
3. If MFA is required by policy and the account has none yet, the page
   shows the enrollment screen instead: a QR code, the setup key for manual
   entry and an `otpauth://` link. After the first code is confirmed the
   recovery codes are shown once (copy or download) and the session starts.

Every user can manage their own MFA under **Account security**: set it up,
generate new recovery codes (needs a current authenticator code) and turn it
off (needs the password and a current or recovery code).

### Parameters

RFC 6238 TOTP as authenticator apps implement it: HMAC-SHA-1, 6 digits,
30-second steps, a 160-bit random secret. The server accepts the current
step and one step on either side (clock drift up to about 30 seconds).

### How sign-in works

* A correct password on an MFA account returns
  `{"mfa_required": true, "mfa_token": ..., "enrollment_required": false,
  "methods": ["totp", "recovery_code"]}` and **no session and no refresh
  cookie**.
* The `mfa_token` is a JWT signed like access tokens but with its own
  audience (`<auth.jwt_audience>:mfa`) and type, so it is refused everywhere
  a session is expected. It names the user and a fingerprint of the
  password hash (a password change kills it), expires after
  `auth.mfa_challenge_ttl_s` (default 5 minutes) and is spent on first
  successful use. The request body cannot name another user.
* `POST /auth/mfa/verify {"mfa_token", "code"}` with a valid TOTP or recovery
  code returns the normal login response and sets the refresh cookie.
* **Replay**: the time step of every accepted code is stored; a code for
  that step or an earlier one is never accepted again, even inside its
  window, and concurrent requests with the same code cannot both succeed.
  Recovery codes are removed when used.
* **Lockout**: the password step gives back its counted attempt without
  clearing earlier failures, and every code check counts as an attempt.
  Wrong codes therefore lock the account after `auth.max_login_attempts`
  (default 10) failures for `auth.lockout_minutes`, and re-entering the
  password never resets the count. A locked account refuses the password and
  codes alike. Only a successful second factor clears the count.
* **Rate limits**: `/auth/mfa/*` is limited per client address and
  challenge (or user) at `api.login_rate_limit_per_minute`, and failures
  count toward the per-address cap on failed sign-ins.

### Policy: who must use MFA

| Rule | Applies to | Set by |
|---|---|---|
| Tenant setting `security.require_mfa` | every local account of the tenant | tenant admin: **Tenant settings, Sign-in security**, or `PATCH /tenant/settings {"security": {"require_mfa": true}}` (audited as `tenant.settings_updated`) |
| `auth.require_mfa_for_platform_admins` (`LG_SOTF_AUTH__REQUIRE_MFA_FOR_PLATFORM_ADMINS`) | platform admins | operator. **Unset means on in `staging` and `production`, off in `development` and `test`** |

An account the policy covers but that has no MFA yet gets
`enrollment_required: true` after its password. That challenge token permits
only `POST /auth/mfa/enroll` and `POST /auth/mfa/confirm` (with
`mfa_token` in the body); confirming returns the recovery codes and the
session together. Existing sessions of such an account end at their next
refresh (at most `auth.access_token_ttl_s`, 15 minutes by default), so a new
policy takes effect quickly without signing everyone out at once.

The bootstrap admin created by `lg-sotf migrate` is a platform admin, so on
a staging or production install the first sign-in goes straight to
enrollment. Have an authenticator app ready.

The `scripts/smoke_stack.sh` and `scripts/e2e_ui_stack.sh` test stacks run
with `environment=staging` and sign the bootstrap platform admin in with a
password only, so they set
`LG_SOTF_AUTH__REQUIRE_MFA_FOR_PLATFORM_ADMINS=false` explicitly. The MFA
flows themselves are covered by `tests/integration/api/test_mfa.py` and the
frontend tests. Never set it to false in a deployment.

MFA applies to local password sign-in only. SSO users get MFA from their IdP
(enforce it there, e.g. with Entra ID Conditional Access or an Okta sign-on
policy). API keys are unaffected.

### Storage and cryptography

* The TOTP secret is encrypted with the install's `security.encryption_keys`
  (Fernet, the same helper as source credentials and webhook secrets), bound
  to the context `mfa:<tenant>:<user id>`; a ciphertext copied onto another
  account does not decrypt. It is returned exactly once, in the enrollment
  response, and never logged. After an encryption-key rotation
  ([operations.md](operations.md#7-key-rotation)) each secret is
  re-encrypted under the new primary key on its next successful use; an
  account that has not signed in with a code before the old key is removed
  needs an MFA reset.
* Recovery codes are 10 characters from a 32-symbol alphabet (50 bits each).
  Only an **HMAC-SHA-256** of each code is stored, keyed with a key derived
  from `security.indicator_hmac_key` and bound to tenant and user. Why HMAC
  and not argon2: the codes are random, not human-chosen, so a slow hash
  adds nothing against online guessing (which the lockout bounds), while
  the secret key makes a stolen database useless for offline guessing. HMAC
  also checks a code against the stored set in one constant-time pass
  instead of up to ten 64 MiB argon2 runs per attempt, which would turn the
  sign-in endpoint into a memory-exhaustion lever. Consequence: rotating
  `security.indicator_hmac_key` invalidates outstanding recovery codes; users
  generate new ones under Account security.
* The table `user_mfa` (tenant-owned, row-level security like every other
  table) holds the ciphertext, a pending ciphertext during enrollment (valid
  15 minutes), the enabled time, the last used time step and the
  recovery-code hashes.
* The QR code is generated on the server by a small built-in encoder
  (`lg_sotf.security.qr`: byte mode, error correction M, versions 1-25) and
  sent as a module matrix that the UI draws as an inline SVG path. No image
  library, no third-party QR service (the secret never leaves the
  install), no `data:` URLs for the Content-Security-Policy to allow. The
  encoder is tested by decoding every version with an independent reader.

### Audit events

| Action | When |
|---|---|
| `auth.mfa_enrolled` | enrollment confirmed |
| `auth.mfa_failed` | wrong code (`reason`: `bad_code`, `bad_password`, `enrollment_bad_code`, `locked`, `locked_now`) |
| `auth.mfa_recovery_code_used` | sign-in or disable with a recovery code (codes left in `details`) |
| `auth.mfa_recovery_codes_regenerated` | new recovery codes |
| `auth.mfa_disabled` | the user turned MFA off |
| `auth.mfa_reset` | an admin, a platform admin or the CLI removed a user's MFA |
| `auth.login` | `details.method` is `password`, `password+totp`, `password+recovery_code` or `password+mfa_enrollment` |

## Recovery procedures

**Lost phone, recovery codes at hand.** Sign in with a recovery code, open
Account security, turn MFA off (password plus another recovery code) and set
it up again on the new phone. Generate new recovery codes when few are
left.

**Lost phone and recovery codes.** An admin of the tenant opens **Users and
API keys** and uses **Reset MFA** on the account (`POST
/users/{id}/mfa/reset`). Verify the person's identity out of band first. The
reset removes the secret and recovery codes, ends all of the user's
sessions and is audited as `auth.mfa_reset`. The user signs in with the
password and, if policy requires MFA, enrolls again immediately. Admins
cannot reset their own MFA this way, and only a platform admin can reset a
platform admin's. A platform admin can reset any tenant's user with
`X-Tenant-ID` (the access is recorded in that tenant's audit log as well).

**Locked out by failed codes.** Wait `auth.lockout_minutes`, or an admin sets
a new password for the user (`PATCH /users/{id}`), which clears the lock and
signs the user out.

**The last admin, or a platform admin, lost every factor (break-glass).**
Run on a host with the schema-owner database connection (as for `lg-sotf
migrate`):

```
lg-sotf reset-mfa --tenant <tenant id> --email <login email>
```

It asks for confirmation (`--yes` skips it), removes the user's MFA, revokes
their refresh tokens and writes `auth.mfa_reset` with actor `system/cli` to
the tenant's audit log. Keep access to this command as tightly controlled as
database access.

## OIDC single sign-on

Configure the issuer and audience (see [api.md](api.md#oidc-single-sign-on)
for the verification rules):

```
LG_SOTF_AUTH__OIDC_ISSUER=https://idp.example.com/...
LG_SOTF_AUTH__OIDC_AUDIENCE=<API audience / client id>
```

### Role mapping

`auth.oidc_role_claim` names the claim with roles or groups (a string or a
list). `auth.oidc_role_map` maps claim values to LG-SOTF roles; the highest
mapped role wins:

```
LG_SOTF_AUTH__OIDC_ROLE_CLAIM=groups
LG_SOTF_AUTH__OIDC_ROLE_MAP={"SOC-Viewers": "viewer", "SOC-Analysts": "analyst", "SOC-Admins": "admin"}
LG_SOTF_AUTH__OIDC_DEFAULT_ROLE=            # unset: no matching group means 403
```

Without a map the claim must carry `viewer`, `analyst` or `admin` itself
(the behaviour of earlier releases). `auth.oidc_default_role` gives every
authenticated identity of the tenant that role when nothing maps; leave it
unset to deny.

### Just-in-time provisioning

With `LG_SOTF_AUTH__OIDC_JIT_PROVISIONING=true`, the first request of a
verified identity (valid tenant claim, a mapped role, an email whose
`auth.oidc_email_verified_claim` is true) that has no local account creates
one:

* email from the token, the mapped role, **no password** (the account cannot
  use password sign-in), never a platform admin;
* linked to the IdP subject (`sub`), not to the email, so a later token of
  another subject with the same email is never linked to it;
* audited as `user.provisioned` (actor `system/oidc`);
* counted against the tenant's `max_users` quota: when the tenant is full the
  sign-in is refused with `409 quota_exceeded` (the same error an admin gets
  when creating a user), and nothing is written.

A suspended tenant (including an erased one) is refused with
`403 tenant_suspended` before any provisioning or role sync, so no account
or audit row is written for it.

On every later request the stored role follows the mapping; a change is
audited as `user.role_synced`. The IdP is the source of truth for these
accounts: change their role in the IdP, not on the users page. Deactivating
the account in LG-SOTF blocks the identity even while the IdP still issues
tokens.

The provisioned account is a real tenant member, so SSO users can claim and
decide escalations and approve actions (which need a user record) without an
admin creating it by hand. Accounts that already exist (created by an admin,
with or without a password) keep working as before: linked by verified
email, their stored role untouched (the session role still comes from the
token).

JIT is off by default. Without it, identities without a local account still
sign in (read-only work, notes) but cannot decide or approve.

### OIDC never grants platform admin

A token cannot make anyone a platform admin, whatever its claims and even if
it is linked to a local platform-admin account: the OIDC principal always has
`is_platform_admin: false`, and `X-Tenant-ID` overrides are refused. JIT
provisioning never sets the flag. Platform admins sign in with a local
account, protected by MFA (required by default in staging and production).

### Example: Microsoft Entra ID

1. App registration for the LG-SOTF API; expose an API (the Application ID
   URI or client id is `auth.oidc_audience`). Issuer:
   `https://login.microsoftonline.com/<directory id>/v2.0`.
2. Roles, either way:
   * **App roles** (recommended): define `SOC.Viewer`, `SOC.Analyst`,
     `SOC.Admin` on the app registration and assign groups to them in
     Enterprise applications. Tokens carry them in `roles`:
     ```
     LG_SOTF_AUTH__OIDC_ROLE_CLAIM=roles
     LG_SOTF_AUTH__OIDC_ROLE_MAP={"SOC.Viewer": "viewer", "SOC.Analyst": "analyst", "SOC.Admin": "admin"}
     ```
   * **Group claims**: Token configuration, Add groups claim, Security
     groups, and choose *Groups assigned to the application* (users in more
     than 200 groups otherwise get an overage claim instead of `groups`).
     Values are group object ids:
     ```
     LG_SOTF_AUTH__OIDC_ROLE_CLAIM=groups
     LG_SOTF_AUTH__OIDC_ROLE_MAP={"3f2b0c9e-...-analysts": "analyst", "8d41a7f2-...-admins": "admin"}
     ```
3. Email: add the optional claim `email`. Entra ID does not send
   `email_verified`; add the optional claim `xms_edov` (email domain owner
   verified) and set `LG_SOTF_AUTH__OIDC_EMAIL_VERIFIED_CLAIM=xms_edov`, or
   JIT provisioning will not create accounts.
4. Tenant: for one LG-SOTF tenant per Entra directory set
   `LG_SOTF_AUTH__OIDC_DEFAULT_TENANT=<tenant id>`; otherwise emit a
   `tenant_id` claim (claims mapping policy or a custom claims provider).
5. Enforce MFA with Conditional Access for the app.

### Example: Okta

1. Use a custom authorization server (Security, API); its issuer is
   `https://<org>.okta.com/oauth2/<server id>`; the audience is the server's
   audience.
2. Claims on the access token:
   * `groups`: value type *Groups*, filter *Starts with* `SOC-`;
   * `email`: `user.email`; `email_verified`: an expression that is true only
     for addresses your org has verified;
   * `tenant_id`: a fixed value, or derived from a group or user profile
     attribute for several LG-SOTF tenants.
   ```
   LG_SOTF_AUTH__OIDC_ROLE_CLAIM=groups
   LG_SOTF_AUTH__OIDC_ROLE_MAP={"SOC-Viewers": "viewer", "SOC-Analysts": "analyst", "SOC-Admins": "admin"}
   LG_SOTF_AUTH__OIDC_JIT_PROVISIONING=true
   ```
3. Enforce MFA with an authentication policy on the app.

## SAML through an OIDC broker

LG-SOTF does not speak SAML natively yet. The recommended path is an OIDC
broker in front of the SAML IdP; LG-SOTF then sees a normal OIDC issuer and
everything above (role mapping, JIT, the platform-admin rule) applies.

* **Keycloak**: add the SAML IdP as an *Identity provider* (SAML v2.0) in a
  realm, map its group or role attributes to Keycloak groups or roles with
  *Mappers*, and create an OIDC client for LG-SOTF with mappers that emit
  `groups` (Group Membership, full path off), `email`, `email_verified` and
  `tenant_id` (Hardcoded claim or a user attribute) into the access token.
  Issuer: `https://<keycloak>/realms/<realm>`.
* **Microsoft Entra ID**: federate the SAML IdP with the Entra directory
  (external identities or domain federation), then configure LG-SOTF against
  Entra ID as above.

Native SAML is a candidate for a later release.

## Known limitations

* TOTP is the only second factor; WebAuthn/passkeys are not supported yet.
  TOTP codes can be phished in real time by a proxy that relays them.
* The first enrollment under a policy trusts the password alone (someone who
  already has a user's password can enroll their own device first). Enroll
  accounts before turning the policy on where that matters, or reset and
  re-enroll with the user present.
* Rotating `security.indicator_hmac_key` invalidates recovery codes.
* SSO users' MFA is the IdP's; LG-SOTF cannot see whether it was used
  (no `amr`/`acr` enforcement yet).
