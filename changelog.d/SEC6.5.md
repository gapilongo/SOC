### Added

- Break-glass access for platform operators: `POST /api/v1/auth/break-glass`
  opens a platform-admin API session from a sealed credential when nobody
  can sign in the normal way. It is off by default. An operator turns it on
  by setting `LG_SOTF_AUTH__BREAK_GLASS_CREDENTIAL_HASH` (the hash printed
  by the new `lg-sotf break-glass-credential` command); it also needs SMTP
  (`integrations.smtp_host`, `smtp_from`).
- `docs/runbooks/break-glass.md`: when to use break-glass, the procedure,
  what to do when the alert is unexpected, how to rotate the credential
  after use, and a drill checklist with what to record.

### Security

- Every break-glass sign-in is audited (`auth.break_glass_used`: account,
  source address, reason) and mailed to every active platform admin of the
  install. Both are written before the session is issued; if either fails,
  the sign-in fails.
- A break-glass session lasts `auth.break_glass_ttl_s` (10 minutes by
  default, at most 15) and has no refresh token. Failed attempts are audited
  (`auth.break_glass_failed`) and rate-limited like logins.
- Database migration `0020`: run `lg-sotf migrate` before starting the new
  version.
