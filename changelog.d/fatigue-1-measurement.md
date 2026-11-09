### Added

- `lg-sotf eval --oracle propose|accept`: a measurement mode in which two
  simulated analysts, taking turns, decide every escalation at once from the dataset's
  labels (`false_positive` for benign, `true_positive` for malicious;
  response actions are rejected), through the same decision path as the API,
  with items in event-time order. It shows how much the verdict cache, the
  tenant's entity history and suppression rules could close with perfect,
  instant analysts. `accept` also enables the suppression rules the
  decisions suggest. Each item's status still records what automation did
  before the oracle acted.
- Every evaluation report and scorecard now leads with two numbers: the
  benign closure rate (with n and a 95% interval) and malicious auto-close
  (with n and an exact one-sided 95% upper bound). A table attributes each
  automatic close to rules, the model, history, the verdict cache, a
  suppression rule or a completed response, and every malicious alert closed
  by any of them is listed by id.
- Datasets can declare the tenant's context (`_meta.tenant_context`): IT
  admin accounts and groups, helpdesk accounts, automation accounts and
  hosts, jump hosts, patch windows and the authorised scanner. The
  attack-emulation corpus declares its estate's. Nothing applies it yet;
  reports show how many benign alerts it covers ("closable with context")
  and how many attacks it covers too.
- A loader for the public AIT Alert Data Set (2.29 million Wazuh alerts, CC
  BY 4.0): `python -m tests.fixtures.aitads fetch DIR` and `build DIR --out
  FILE` sample `aitads_v1` (5,000 alerts per scenario, stratified by attack
  phase, seeded). Labels come from the dataset's attack-phase times; see
  `docs/evaluation.md#ait-ads` for what they can and cannot say.
