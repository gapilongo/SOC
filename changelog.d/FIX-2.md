### Changed

- Model-led closure (`ai_closure.tier = auto_full_audit`) can now close
  routine Wazuh noise that ships without an ATT&CK mapping. A reviewed,
  versioned catalogue of noise families, keyed by vendor and detection rule
  id, lifts the "no ATT&CK mapping" block for: package installs and updates
  (dpkg 2901, 2902; yum 2932, 2933), Windows software installs (60612),
  Defender scan and signature status (62107, 62108, 62130) and a single web
  4xx (31101). It lifts nothing else: the tier, severity, both model tiers
  benign at the install thresholds, steering text, a recent true positive
  and a campaign in progress still block. Such a close's decision reason
  names the family and the catalogue version.
- Alerts now record the format whose normalizer built them
  (`normalized.normalizer`: `wazuh`, `canonical`, `webhook`, `llm`, ...).
  Models never see it. Alerts stored before this release have none, so the
  catalogue does not apply to them.
- The campaign check is unchanged (FIX-1). A check that lets one detection
  rule repeat without blocking was deferred.

### Security

- Authentication failures never close on the models' word, whatever ATT&CK
  technique the vendor gave them: a Wazuh rule in the groups
  `authentication_failed`, `authentication_failures`, `invalid_login` or
  `login_denied`, the rules 6250 (Asterisk) and 44733 (FortiAuthenticator),
  and ATT&CK T1531, where Wazuh maps its Windows logon failures. Before,
  25 stock Wazuh rules of that kind (logon failures, a failed logon from a
  malicious IP, a possible replay attack) were closable.
- The catalogue reads only the rule id of the vendor's own event, and only
  on an alert the Wazuh normalizer built, never the title, description or
  rule-name text: a custom rule that copies a stock description, a forged
  rule-name prefix or a canonical push of a Wazuh document stays unmapped.
- The workflow state keeps the vendor rule (`raw.rule`: id, level,
  description, groups, ATT&CK) when an oversized raw event is dropped. A
  Wazuh alert whose rule cannot be read, or whose groups list had to be cut,
  never closes on the models' word.
