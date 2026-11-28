### Added

- **Reopen an alert the AI closed, with a reason** (PRD-2.9a). On the case
  page, an alert the AI closed on the model's word has a **Reopen** control
  for an analyst or an admin. It asks for a reason and is not sent without
  one. While the case is open the alert joins it as open and the decision on
  the case settles it; in a decided case a new run sends it to an analyst.
  Nothing closes a reopened alert again without a person (see Changed).
  The reopening is in the audit log with the person and the reason
  (`alert.reopened`), and the alert's row and the case timeline say who
  reopened it and why. API: `POST /api/v1/alerts/{id}/reopen` with
  `{reason, case_id?}`.
- **Flag an AI close as wrong, with a reason.** **Flag** reopens the alert in
  the same way and records the disagreement (`alert.flagged` in the audit
  log, with the person, the reason and the close it disagrees with). The
  blind-audit and accuracy reports count the flags of their window in
  `flagged_ai_closes`, beside their rates and never inside them: a flag is a
  person's choice, not a random sample. When no open case holds the flagged
  alert, a person now stands behind a threat there, so the other alerts the
  AI closed on the same host or user in the last 24 hours are reopened too
  (never one that waits for its blind-audit label). Inside an open case a
  flag reopens the flagged alert only. API: `POST /api/v1/alerts/{id}/flag`.
- The case view (`GET /api/v1/cases/{id}`) says which alerts can be reopened
  (`alerts[].can_reopen`), which were flagged, by whom and why
  (`alerts[].flagged`, `counts.flagged`), and for an alert a person reopened,
  who did it and the reason they gave (`alerts[].reopened.note`).

- **Who or what closed it, in the alerts list.** Every alert of
  `GET /api/v1/alerts` carries `closed_by`: an analyst, the AI on approved
  evidence, the AI on the model's word, a suppression rule or an earlier
  analyst verdict. The new `closed_by` filter lists the alerts one or more of
  them closed. On the Alerts page the Closed view shows it in a "Closed by"
  column, with the filter beside the others.
- **The Overview splits the closes without a person** by who or what closed
  them, for the chosen window, where it said "not measured yet"
  (`closed_without_human_by` on `GET /api/v1/dashboard/summary`; the counts
  add up to `handled_without_human`).

### Changed

- **A reopened alert is never closed again without a person** (#461). An
  alert the safety net or a person reopened used to be protected from a
  close on the model's word only: in its new run a suppression rule, an
  earlier analyst verdict, the first assessment or approved benign evidence
  could still close it. Now none of them does. The run sends the alert to an
  analyst, and the decision code says who reopened it (`reopened`,
  `reopened_by_analyst`, `flagged_by_analyst`). The change only holds
  closes: a threat score high enough for the response policy still gets its
  response plan. No alert of the evaluation corpora is reopened, so their
  numbers do not change.
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
- `closed_by` is `analyst` for an alert a person stands behind whatever its
  close reason (an analyst decided it, or a person approved or rejected one
  of its response actions), which is how the Overview counts it.
- The application log records the length of a reason, not its text; the
  audit log keeps the text.
- An alert that waits for its blind-audit label names no closer and matches
  no `closed_by` filter, and is left out of the Overview's split, as it is
  out of the other figures: who closed it is part of what the audit hides.
