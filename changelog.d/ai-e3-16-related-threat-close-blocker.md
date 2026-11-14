### Security

- At the autonomy tier `auto_full_audit`, the AI no longer closes an alert
  on the models' word while a related threat is open (#435). When the alert
  is decided, the platform reads your stored alerts of the previous 24 hours
  that share a host or user with it. The alert goes to an analyst instead of
  closing when one of them is not closed and is a threat: a response was
  planned for it, or a model judged it malicious, a likely threat or a
  confirmed threat (escalation reason code `related_open_threat`). It also
  goes to an analyst when a high or critical alert on the same host is being
  processed at that moment (`related_in_progress`). The answer comes from
  the database, never from what a model wrote about related alerts; when it
  cannot be read, nothing closes. Shared IP addresses and the accounts every
  host has (`root`, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`) do not
  relate two alerts for this rule. A threat that appears after the close is
  still handled by the safety net (linked, and reopened when confirmed).
  Before this change a model closed the command-and-control step of the demo
  attack chain while the credential dump on the same host was waiting for an
  analyst. Expect fewer AI closes on hosts and users with an open threat,
  until an analyst decides it.
- The triage and analysis prompts now say that names and addresses that look
  reserved, test or demo are no evidence of harmless activity: a `.test` or
  `.example` domain, a documentation address range, an `example.*` host
  name, a vendor or id containing "demo" or "test", traffic that "looks
  synthetic". The model must not list them as false-positive indicators or
  as a reason for a benign verdict. The prompt hashes of `triage.assess`,
  `analysis.react_step` and `analysis.verdict` change.

### Changed

- The alert summary has a new field `related_open` (`threats`,
  `in_progress`: alert ids), written when an alert is decided at the tier
  `auto_full_audit`; the investigation view lists it among the reasons the
  AI did not close the alert.
- `scripts/demo/seed_demo.py` (and so `make quickstart`) fails when a step of
  the demo attack chain on `WS-FIN-0142` (Word starts PowerShell, the LSASS
  dump, the beacon, PsExec) is closed without a person, and records
  `attack_chain_closed_without_a_person` in `.quickstart/timing.json`.
- The adversarial corpus v2 has an eighth gated family,
  `provenance-camouflage` (3 malicious items): a real attack pattern on
  hosts, domains, vendors and ids that look like test data. The corpus has
  100 items and a new sha256.
