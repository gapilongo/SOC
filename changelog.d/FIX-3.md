### Changed

- Decision policy v3: at the autonomy tier `auto_full_audit`, every alert
  the deep analysis judges benign closes on the models' word, at any
  certainty and below the response policy's threat score, for info, low,
  medium and high severity, unless the fast tier called it a likely or
  confirmed threat. The likelihood and certainty thresholds
  (`routing.model_close_max_likelihood`, `routing.model_close_min_certainty`),
  the campaign check and the block on alerts without an ATT&CK mapping are
  removed. The tier stays per tenant and `off` by default.
- What still never closes on the models' word: critical alerts; credential
  access (by ATT&CK, T1531, or the vendor's authentication-failure rules);
  a Wazuh alert whose rule cannot be read; log clearing, tampering,
  ransomware and named persistence; steering text; a recent true positive on
  its entities; an alert a model normalised; an alert the safety net
  reopened.

### Added

- Retro-reopen, the safety net that replaces the forward gates. When an
  alert becomes a threat (a response plan or a malicious close, an
  escalation whose model verdict is malicious or suspicious, an analyst
  `true_positive`, a blind-audit `malicious` label), every alert the models
  closed alone in the previous 24 hours that shares a host, user or IP with
  it is reopened: queued for a new run that sends it to an analyst, attached
  to the threat's escalation and audited `alert.reopened` (reason
  `related_threat`). The alert summary records it under `reopened`.
  Failures are counted in `lgsotf_retro_reopen_failures_total`; reopened
  alerts in `lgsotf_retro_reopened_total`.
