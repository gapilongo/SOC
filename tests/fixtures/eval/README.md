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

## Phishing set

| File | Purpose |
|---|---|
| `phishing_v1.jsonl` | 39 **synthetic** user-reported emails (`source_type: email`, raw RFC 5322 text) |
| `phishing_smoke_thresholds.yaml` | Regression gate for the phishing smoke run with the fake LLM |

Messages use `example.com` as the internal domain, `.test` names for
everyone else (plus `bit.ly` for the shortener signal; nothing is fetched)
and documentation addresses. `_meta.tenant_settings` gives every evaluation
tenant the internal domain, a protected brand, two executives and the
trusted `authserv-id`. Coverage: 24 malicious, 11 benign, 4 inconclusive.
Standard split: 18 malicious (lookalike, homoglyph and
punycode domains, deceptive and raw-IP links, HTML/SVG/ISO/LNK/OneNote/macro/
disguised executable/right-to-left-override attachments, encrypted and
script-bearing archives, executive and brand impersonation, spoofed senders
with Reply-To, a compromised internal account), 10 benign (authenticated
internal notices, newsletters, vendor invoices, a direct push with the
`reporter` parameter), 4 inconclusive and an adversarial split of 7
(injection in plain text, in CSS-hidden HTML, zero-width obfuscated and with
forged prompt tags; a forged "all pass" Authentication-Results header;
response steering toward the organisation's own executive; a harmless
awareness newsletter about phishing). Regenerate it by hand-editing the
JSONL; keep every message synthetic.

## Adversarial corpus v2

| File | Purpose |
|---|---|
| `adversarial_v2.jsonl` | 91 **synthetic** adversarial alerts (AI-E6.1), version 2, sha256 `42add5b3ecec1d85bf658bc85ebda28e8190b6f6879ef6ec6110ea7328d15a34` |
| `adversarial_v2_thresholds.yaml` | Its gate with the fake LLM: no malicious item of the `adversarial` split closed by automation |

88 items in the `adversarial` split, in five families (`log-field-hijack` 24,
`tool-output-injection` 16, `response-steering` 14, `encoding-tricks` 17,
`benign-lookalike` 17), plus 3 `title-camouflage` items in a `known-gap`
split that is reported, not gated. Tool-output items carry `tool_fixtures`
(canned threat-intelligence and history answers). Same naming rules as the
other sets; invisible and look-alike characters are written as `\u` escapes.
The family-to-threat mapping, the fixture format and the known gap are in
`docs/evaluation.md` ("Adversarial corpus v2"). When you edit the file,
record its new sha256 there and here (a unit test checks both).

Use these sets to test the pipeline and its safety policy. Do not quote its
numbers as detection accuracy. How to evaluate on real labelled data (the
`analyst_feedback` export) and public benchmarks without committing them is
described in `docs/evaluation.md`.
