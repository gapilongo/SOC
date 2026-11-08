### Fixed

- Claiming an escalation whose SLA has expired now works. Before, every
  click answered "Someone else changed this escalation first" and nothing
  changed. The escalation stays expired, so the missed SLA is kept in the
  queue and in reports, and you become its owner. The audit entry records
  the claim as late (`after_sla_expiry`). As with a claimed escalation,
  only an admin can take it over from its owner.
- A claim on an escalation that is already decided or closed now says so
  ("This escalation is already decided or closed") instead of reporting a
  change by someone else. The API answers `409 invalid_transition` for it,
  whatever the version sent; a stale version on an active escalation is
  still `409 conflict`.
- Repeating an action that fails the same way no longer stacks identical
  notifications: the newest replaces the one on screen.
