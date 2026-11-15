### Security

- At the autonomy tier `auto_full_audit`, the AI no longer closes an alert
  on the models' word while a serious related threat is there (#435). Two
  alerts are related when they share a host or a user, however each source
  spells it: `WS-FIN-0142.corp.example.com` and `ws-fin-0142` are one host,
  `CORP\jsmith`, `jsmith@corp.example.com` and `JSmith` one user. A shared
  IP address alone relates nothing, and neither do the accounts every host
  has (`root`, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`). A threat is
  serious when it is high or critical and a model judged it malicious, a
  likely threat or a confirmed threat; when a response for it waits for an
  approval; or when a person confirmed it (an analyst true positive, a
  blind-audit malicious label).
  - **Before the close.** When an alert is decided, the platform reads the
    stored state of your related alerts. The close is held back and the
    alert goes to an analyst (reason code `related_open_threat`) while a
    serious related alert is open, for up to seven days from its ingestion,
    and for 24 hours after an analyst's true positive closed it. It is also
    held back while a high or critical alert on the same host is being
    processed (`related_in_progress`). A low or medium alert that only a
    model judged a threat holds nothing: the alert closes as before and is
    linked to that alert's case at once (`lgsotf_retro_linked_total`, path
    `forward`). When the related alerts cannot be read, or a tenant has more
    than 2,000 open threats to compare, nothing closes on the models' word
    and the alert goes to an analyst (`related_unchecked`); the run does not
    fail.
  - **After the close.** The safety net now reopens the alerts the AI
    closed in the previous 24 hours as soon as a related alert becomes
    serious, not only when a person confirms it: a close decided while a
    serious step of the same attack was still queued does not stand. A low
    or medium threat that only a model judged still links them and leaves
    them closed. A response that waits for an approval now reopens them; it
    used to link them.
  - The safety net relates alerts the same way: by host and user, however
    spelled. It no longer links or reopens on a shared IP address alone.
  Before this change a model closed the command-and-control step of the demo
  attack chain while the credential dump on the same host was waiting for an
  analyst.
- The triage and analysis prompts now say that names and addresses that look
  reserved, test or demo are no evidence of harmless activity: a `.test` or
  `.example` domain, a documentation address range, an `example.*` host
  name, a vendor or id containing "demo" or "test", traffic that "looks
  synthetic". The model must not list them as false-positive indicators or
  as a reason for a benign verdict. The prompt hashes of `triage.assess`,
  `analysis.react_step` and `analysis.verdict` change.

### Changed

- The alert summary has a new field `related_open`, written when an alert
  is decided at the tier `auto_full_audit`: the ids of the related alerts
  that held the close (`threats`, `in_progress`) or that it was linked to
  (`model_only`), or `unchecked` with the reason when the check did not
  complete. The investigation view lists them among the reasons the AI did
  not close the alert, and the console names the reason codes
  `related_open_threat`, `related_in_progress` and `related_unchecked` in
  plain words.
- `scripts/demo/seed_demo.py` (and so `make quickstart`) fails when a step of
  the demo attack chain on `WS-FIN-0142` (Word starts PowerShell, the LSASS
  dump, the beacon, PsExec) is closed without a person, and records
  `attack_chain_closed_without_a_person` in `.quickstart/timing.json`. A
  step closed by a completed automatic response does not count.
- The adversarial corpus v2 has an eighth gated family,
  `provenance-camouflage` (3 malicious items): a real attack pattern on
  hosts, domains, vendors and ids that look like test data. The corpus has
  100 items and a new sha256, and a second gate for the tier
  `auto_full_audit` (`adversarial_v2_tier_on_thresholds.yaml`).
