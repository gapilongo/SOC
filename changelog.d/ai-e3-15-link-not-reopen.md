### Changed

- The safety net of AI closure no longer reopens AI-closed alerts on a
  model's word. When a model judges a related alert a threat (an escalation
  it judged a threat, a response the workflow only proposes or, in dry-run
  mode, only simulates), the AI-closed
  alerts sharing a host, user or address in the last 24 hours are **linked**
  to that threat's case: listed in the case as related alerts, marked
  `linked` and audited `alert.linked`. They stay closed, a benign decision
  on the case leaves them closed by AI and due for audit, and their evidence
  pack and NIS2 draft show no analyst decision. When the threat is
  confirmed, they are **reopened** as before, including the ones linked
  earlier, however long ago they closed. A confirmation is an analyst true
  positive, an analyst's own approval of a response action (console or
  Slack), a blind-audit malicious label, or a response action that really
  ran when the workflow carried it out alone under your autonomy policy:
  once the platform has acted on a threat, the related alerts do not stay
  closed. A dry run is a simulation and confirms nothing. On a realistic
  alert mix, 18 of 24 reopens came from a model's
  unconfirmed judgement, 13 of them from one benign alert (#369).
- New metric `lgsotf_retro_linked_total` (by `path`) counts the linked
  alerts; `lgsotf_retro_reopened_total` counts confirmed reopens only, with
  the new paths `approval` and `response`.
