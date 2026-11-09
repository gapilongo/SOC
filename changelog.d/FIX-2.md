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
- The campaign check now tells one detection rule repeating apart from an
  attack. A burst of the same rule no longer blocks a model-led close, and
  neither do those repeats while they wait for an analyst (before, nothing
  closed, so everything stayed open and the check blocked itself), when
  every repeat was either closed as benign or is one the models could close
  themselves: no steering text, no recent true positive, both model tiers
  benign within the thresholds, no never-close class. The correlation
  digest has two new fields, `related_rule_repeats` and `related_complete`.
  A complete related set holds fewer than `agents.correlation.max_correlations`
  alerts (10 by default), so at most 9 repeats stand behind a close.
- Rule ids are known for Wazuh alerts only. For other vendors (Sentinel,
  CrowdStrike, ...) every related alert still blocks a model-led close.
- Alerts now record the format whose normalizer built them
  (`normalized.normalizer`: `wazuh`, `canonical`, `webhook`, `llm`, ...).
  Models never see it. Alerts stored before this release have none, so the
  catalogue and the repeat count do not apply to them.

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
  rule-name prefix or a canonical push of a Wazuh document stays unmapped. An alert whose
  raw event was dropped by the state size cap stays unmapped too.
- A related alert still blocks a model-led close when its detection rule
  differs (a possible kill chain, even if it was closed as benign), when a
  model judged it malicious or suspicious, when it is still waiting for a
  model or for its deep verdict, when it carries steering text or a recent
  true positive, when a model tier was not sure enough, when it is in a
  never-close class, or when it is a response plan awaiting approval. A related set that may be incomplete (the correlation query hit
  its limit, or a related alert is hidden while it waits for a blind-audit
  label) blocks too, and so does a digest from before this release that
  lists related alerts.
