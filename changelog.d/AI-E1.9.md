### Changed

- A low or medium alert can now close on its own when the deep model calls
  it benign (threat score below 30) and context the tenant declared
  corroborates it: one of the tenant's configured scanners
  (`triage.known_scanners`) is among the alert's entities. Before, only a
  rules' threat score below 30 corroborated a close, which Wazuh alerts never
  reach. High and critical alerts still close only through an analyst, and
  an alert whose text tries to steer the model is never closed this way.
- A benign deep-model verdict now takes precedence over the confidence grey
  zone (30 to 70), which is computed before analysis. Every other close test
  still applies, so the verdict alone never closes an alert.
- Both changes can be turned off: `routing.benign_verdict_precedence` and
  `routing.context_corroboration` (`false` restores the 1.2 policy).
- `lg-sotf eval` correlates on each alert's own time instead of the wall
  clock, so a replay of days of alerts in minutes no longer looks like one
  alert storm. Production keeps the wall clock. Reports record the clock
  (`run.correlation_clock`) and, per item, what the routing decision read
  (`decision_inputs`).
- The attack-emulation corpus declares its authorised vulnerability scanner,
  as a tenant would. The corpus gate now protects a benign auto-close floor.

### Added

- `python -m lg_sotf.eval.calibration REPORT` re-decides a recorded
  evaluation under each candidate routing policy with the real routing code
  and no model. `docs/scorecards/v2/deepseek-v4/CALIBRATION.md` holds the
  tables for scorecard v2 and the fake-model sets, and the chosen policy.
- `routing.cap_correlated_confidence` (off by default): related alerts never
  lift the confidence to the response policy. Measured, not turned on; see
  CALIBRATION.md.
