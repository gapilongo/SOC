### Changed

- The adversarial corpus v2 has a seventh gated family, `activity-camouflage`
  (6 malicious items): attacks whose detection rule name holds a word for
  the detected activity, such as `scheduled-task-update` or
  `scheduled-backup-deleted`.

### Security

- Rule-name words that name the activity a rule detects (`scheduled`,
  `update`, `backup`, `scan`, `monitoring`) are no longer false-positive
  evidence on their own: a new scheduled task is persistence and a disabled
  monitor is defence evasion. They count only with a trusted qualifier: a
  word of benign intent in the same rule name (`test`, `selftest`,
  `maintenance`, `health_check`), a test-like source id or, for `scan`, one
  of your `triage.known_scanners` among the alert's entities. Before this
  change, an info alert from a rule such as `scheduled-task-update` could
  close on the rules alone. Alerts whose only benign evidence was an
  activity word now reach the model and, when needed, an analyst; if your
  scanners raise `scan` alerts that used to close, list them in
  `triage.known_scanners`.
