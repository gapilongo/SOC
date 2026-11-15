### Security

- At the autonomy tier `auto_full_audit`, the AI no longer closes an alert
  on the models' word while a serious related threat is open (#435). When
  the alert is decided, the platform reads your stored alerts of the
  previous 24 hours that share a host or user with it. The close is held
  back (reason code `related_open_threat`) when one of them is not closed
  and waits for a response approval, is high or critical and was judged
  malicious, a likely threat or a confirmed threat by a model, or was
  confirmed by a person (an analyst true positive, a blind-audit malicious
  label). It is also held back while a high or critical alert on the same
  host is being processed (`related_in_progress`). A held alert joins the
  threat's case as a related alert instead of opening its own, and the
  decision on that case settles it. A low or medium alert that only a model
  judged a threat holds nothing: the alert closes as before and is linked
  to that alert's case at once, and reopens if the threat is confirmed
  (`lgsotf_retro_linked_total`, path `forward`). The answer comes from the
  database, never from what a model wrote about related alerts; when it
  cannot be read, nothing closes. Shared IP addresses and the accounts every
  host has (`root`, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`) do not
  relate two alerts for this rule. A threat that appears after the close is
  still handled by the safety net. Before this change a model closed the
  command-and-control step of the demo attack chain while the credential
  dump on the same host was waiting for an analyst.
- The triage and analysis prompts now say that names and addresses that look
  reserved, test or demo are no evidence of harmless activity: a `.test` or
  `.example` domain, a documentation address range, an `example.*` host
  name, a vendor or id containing "demo" or "test", traffic that "looks
  synthetic". The model must not list them as false-positive indicators or
  as a reason for a benign verdict. The prompt hashes of `triage.assess`,
  `analysis.react_step` and `analysis.verdict` change.

### Changed

- The alert summary has two new fields: `related_open` (`threats`,
  `in_progress`, `model_only`: alert ids), written when an alert is decided
  at the tier `auto_full_audit`, and `held_by` (alert ids) on an alert an
  open threat holds. The investigation view lists the related alerts among
  the reasons the AI did not close the alert, the console names the two new
  reason codes in plain words, and `own_review_alert_ids` of a decision
  leaves out the held alerts the decision settles.
- `scripts/demo/seed_demo.py` (and so `make quickstart`) fails when a step of
  the demo attack chain on `WS-FIN-0142` (Word starts PowerShell, the LSASS
  dump, the beacon, PsExec) is closed without a person, and records
  `attack_chain_closed_without_a_person` in `.quickstart/timing.json`.
- The adversarial corpus v2 has an eighth gated family,
  `provenance-camouflage` (3 malicious items): a real attack pattern on
  hosts, domains, vendors and ids that look like test data. The corpus has
  100 items and a new sha256.
