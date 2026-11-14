### Changed

- The attack-emulation corpus declares its authorised vulnerability scanner,
  as a tenant would (`_meta.tenant_settings`, `triage.known_scanners`).
- Evaluation reports record, per item, what the routing decision read
  (`decision_inputs`: the confidence, the triage, correlation and analysis
  scores and the verdict).
