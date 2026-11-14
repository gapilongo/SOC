### Changed

- The safety net of AI closure no longer reopens AI-closed alerts on a
  model's word. When a model judges a related alert a threat (an escalation
  it judged a threat, a response plan or a malicious close with no analyst
  decision behind it), the AI-closed alerts sharing a host, user or address
  in the last 24 hours are **linked** to that threat's case: listed in the
  case as related alerts, marked `linked` and audited `alert.linked`. They
  stay closed, and a benign decision on the case leaves them closed by AI
  and due for audit. When a person confirms the threat (an analyst true
  positive, an approved response action in the console or from Slack, a
  blind-audit malicious label), they are **reopened** as before, including
  the ones linked earlier, however long ago they closed. On a realistic
  alert mix, 18 of 24 reopens came from a model's unconfirmed judgement,
  13 of them from one benign alert (#369).
- New metric `lgsotf_retro_linked_total` (by `path`) counts the linked
  alerts; `lgsotf_retro_reopened_total` now counts confirmed reopens only,
  with the new path `approval`.
