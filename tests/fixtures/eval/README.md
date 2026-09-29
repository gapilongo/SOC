# Evaluation fixtures (synthetic)

| File | Purpose |
|---|---|
| `synthetic_v1.jsonl` | 64 **synthetic** labelled alerts for `lg-sotf eval` (48 `standard`, 16 `adversarial`) |
| `smoke_thresholds.yaml` | Regression gate for the CI smoke run with the fake LLM |

Everything in `synthetic_v1.jsonl` is hand-written: documentation address
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC 1918), `example.com`
style names and made-up identifiers, shaped like each vendor's documented
format (canonical, Splunk notables, CrowdStrike detections, Sentinel alerts,
Wazuh alerts, GuardDuty findings via EventBridge, QRadar offenses and a
generic webhook with a field map). Expected dispositions were assigned by
construction when writing each scenario; no analyst reviewed a real incident.
The file's first line (`_meta.synthetic: true`) and every item's `synthetic`
tag say so, and reports built from it carry a notice.

Coverage:

* malicious (35): credential dumping, ransomware, C2 beaconing, encoded
  PowerShell, brute force, exfiltration, MFA fatigue, inbox forwarding,
  web shells, cryptomining, cloud credential theft, lateral movement,
  Kerberoasting, DCSync, privilege escalation, VPN exploitation;
* benign (21): scheduled backups, maintenance, patching, authorised scanners,
  pipeline self-tests, monitoring gaps, routine identity events;
* inconclusive (8): ambiguous identity, DNS, cloud discovery and endpoint
  signals that need a human;
* adversarial split (16): prompt injection in descriptions, command lines,
  entity names, cloud tags and log lines; `</alert_data>` tag forgery;
  zero-width-space obfuscation; size padding; benign camouflage (malicious
  activity named "scheduled update test"); malicious camouflage (a benign
  newsletter full of threat words); response steering toward a domain
  controller; claimed authorisation.

Use this set to test the pipeline and its safety policy. Do not quote its
numbers as detection accuracy. How to evaluate on real labelled data (the
`analyst_feedback` export) and public benchmarks without committing them is
described in `docs/evaluation.md`.
