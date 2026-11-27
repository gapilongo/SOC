### Added

- **Reopen an alert the AI closed, with a reason** (PRD-2.9a). On the case
  page, an alert the AI closed on the model's word has a **Reopen** control
  for an analyst or an admin. It asks for a reason and is not sent without
  one. While the case is open the alert joins it as open and the decision on
  the case settles it; in a decided case a new run reviews it and ends with
  an analyst. Either way the AI never closes it on the model's word again.
  The reopening is in the audit log with the person and the reason
  (`alert.reopened`), and the alert's row and the case timeline say who
  reopened it and why. API: `POST /api/v1/alerts/{id}/reopen` with
  `{reason, case_id?}`.
- **Flag an AI close as wrong, with a reason.** **Flag** reopens the alert in
  the same way and records the disagreement (`alert.flagged` in the audit
  log, with the person, the reason and the close it disagrees with). The
  blind-audit and accuracy reports count the flags of their window in
  `flagged_ai_closes`, beside their rates and never inside them: a flag is a
  person's choice, not a random sample. Because a person stands behind a
  flag, the safety net treats it as a confirmation: the other alerts the AI
  closed on the same host or user are reopened too. API:
  `POST /api/v1/alerts/{id}/flag`.
- The case view (`GET /api/v1/cases/{id}`) says which alerts can be reopened
  (`alerts[].can_reopen`), which were flagged, by whom and why
  (`alerts[].flagged`, `counts.flagged`), and for an alert a person reopened,
  who did it and the reason they gave (`alerts[].reopened.note`).

### Changed

- The case page no longer lists "flagging an alert" as not yet available.
- Alerts closed by a person, a suppression rule, an earlier analyst verdict
  or approved evidence cannot be reopened this way yet. A new run would close
  them the same way, so they keep today's paths: change the rule, or have an
  admin reprocess the alert.

### Security

- Reopen and flag are for a person of the tenant: an analyst or an admin
  with a user account, or an MSSP analyst under a grant. A viewer, an API
  key and a platform admin acting from outside the tenant are refused
  (`403`); another tenant's alert or case is not found (`404`).
- The reason a person types is stored and shown as plain text, at most 1000
  characters. It is kept on the audit entry and the alert's timeline only,
  never in the alert's summary, and no model is shown it.
