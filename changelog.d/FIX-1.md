### Added

- A per-tenant autonomy tier for closing alerts on the models' word,
  `ai_closure.tier` in the tenant settings: `off` (the default) or
  `auto_full_audit`. At `auto_full_audit`, an info, low or medium alert
  closes as benign when both model tiers call it benign: the fast tier with
  a threat likelihood of at most 8 and the deep tier with a certainty of at
  least 85 (install settings `routing.model_close_max_likelihood` and
  `routing.model_close_min_certainty`). Such a close has the decision code
  `model_closed` and the close reason `ai_closed:audit_required`, so an
  analyst can find and audit every one. Only a tenant admin can change the
  tier, never under an MSSP grant, and the audit event records the tier set.

### Changed

- Every info, low and medium alert now goes through analysis. Before, a
  strong correlation (or a low confidence) sent it straight to the decision
  on a correlation-raised confidence, which could plan a response or hold a
  benign alert in the grey zone without any analysis.
- Correlation is evidence, not a score boost: related alerts, bursts and
  alert rates go to the analysis model and into the alert summary, but they
  no longer raise the alert's confidence. A response plan therefore needs
  the analysis threat score (or trusted triage evidence), never correlation
  alone.
- The grey zone (30 to 70) is tested on the analysis threat score, not on
  the confidence from before the analysis. Escalations record that score
  next to the review band.
- A low-threat benign verdict now closes an alert with approved benign
  evidence, the false-positive signals triage takes only from what an
  attacker cannot write: the detection rule's name, the EICAR test file, a
  test-environment source, a scanner you listed in `triage.known_scanners`
  or an authenticated internal sender. The rules' threat score no longer
  has to be below 30, which no Wazuh alert could reach.

### Security

- Even at `auto_full_audit`, the models never close alone: a high or
  critical alert; credential access, log clearing, security-tool tampering
  or ransomware behaviour; persistence through an object the attacker
  creates and names (scheduled tasks, services, autostart entries, WMI
  subscriptions, accounts); an alert whose detection rule maps it to no
  ATT&CK tactic or technique; an alert with text written to steer a model;
  an alert whose entities have an analyst-confirmed malicious history, a
  related alert closed as malicious or rule evidence of a threat. A verdict
  the rules produced because a model was not consulted never counts. With
  the tier `off`, nothing closes on the models' word alone.
- Nor while a campaign may be in progress: a burst of related alerts, a
  related alert a model judged malicious or suspicious, or one still waiting
  for an analyst or an approval. These are counted over every related alert,
  not only the ten shown to the correlation model. A related alert the models
  closed alone is shown to later models as `ai_closed_unaudited`, never as
  `benign`, so one persuaded close cannot vouch for the next.
- Approved benign evidence no longer closes an alert past text written to
  steer a model, analyst-confirmed malicious history, rule evidence of a
  threat or a related alert closed as malicious. A declared scanner or a
  test source never closes credential access, log clearing, tampering,
  ransomware or named persistence.
- `triage.known_scanners` now counts only when the scanner is the source of
  the activity (a source address or host field of the event, such as
  `srcip` or the Windows logon source), never when it is the host or address
  the activity reached. An attack on your scanner is still an attack. If
  your scanner alerts carry the scanner only as an entity, they now go to
  the model and, when needed, an analyst.
- ATT&CK tactics are matched whatever their spelling, so Sentinel's
  `CredentialAccess` is a never-close class like Wazuh's `Credential Access`.
