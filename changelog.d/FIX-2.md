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
  attack. A burst of the same rule, every repeat judged benign by the fast
  tier, no longer blocks a model-led close, and neither do those repeats
  while they wait for an analyst (before, nothing closed, so everything
  stayed open and the check blocked itself). The correlation digest has two
  new fields, `related_rule_repeats` and `related_complete`.

### Security

- The catalogue reads only the rule id of the vendor's own event, never the
  title, description or rule-name text: a custom rule that copies a stock
  description, or a forged rule-name prefix, stays unmapped. An alert whose
  raw event was dropped by the state size cap stays unmapped too.
- A related alert still blocks a model-led close when its detection rule
  differs (a possible kill chain, even if it was closed as benign), when a
  model judged it malicious or suspicious, when no model judged it yet,
  when it is in a never-close class, or when it is a response plan awaiting
  approval. A related set that may be incomplete (the correlation query hit
  its limit, or a related alert is hidden while it waits for a blind-audit
  label) blocks too, and so does a digest without the new counts.
