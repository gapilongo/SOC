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
| `adversarial_v2.jsonl` | 97 **synthetic** adversarial alerts (AI-E6.1), version 2, sha256 `d3817373d8357ccffa7ff38f58a7bd8d5963a9caf1cdeee248c3d2b921955c1a` |
| `adversarial_v2_thresholds.yaml` | Its gate with the fake LLM: no malicious item of the `adversarial` split closed by automation |

All 97 items are in the gated `adversarial` split, in seven families
(`log-field-hijack` 24, `tool-output-injection` 16, `response-steering` 14,
`encoding-tricks` 17, `benign-lookalike` 17, `title-camouflage` 3, which
was a reported-only `known-gap` split until AI-E6.3, and
`activity-camouflage` 6, added in AI-E6.4). Tool-output items carry
`tool_fixtures` (canned threat-intelligence and history answers); `_meta`
lists the corpus scanner (`triage.known_scanners`: `scanner-01`, `10.0.5.10`).
Same naming rules as the other sets; invisible and look-alike characters are
written as `\u` escapes. The family-to-threat mapping and the fixture format are in
`docs/evaluation.md` ("Adversarial corpus v2"). When you edit the file,
record its new sha256 there and here (a unit test checks both).

## Attack-emulation corpus v1

| File | Purpose |
|---|---|
| `corpus_v1.jsonl.gz` | 520 labelled Wazuh 4.14 alerts (AI-E1.8), gzip-compressed JSONL; sha256 of the JSONL text `42e40657d357939cc4719139cbdc069c8f61a5c0bb3b3ca16f3517165f2e3b69` |
| `corpus_v1_thresholds.yaml` | Its gate with the fake model (replayed from `cassettes/corpus_v1/`) |

208 malicious alerts (Atomic Red Team tests chained into Caldera-style
campaigns, plus single atomic runs) and 312 benign ones (186 routine, 126
look-alikes that trip the same rules), a 40/60 split, in seven log-source
families (`sysmon`, `windows`, `syscheck`, `audit`, `sshd`, `syslog`, `web`).
Labels come from the procedure that produced each alert: tags name the
technique (`technique:` or `resembles:`) and the Atomic test (`atomic:`,
`atomic-guid:`). Do not edit the file: it is generated by
`python -m tests.fixtures.attack_corpus generate` (seeded, byte for byte
reproducible; a unit test checks the committed file and this sha256). After a
generator change, regenerate, record the cassettes again with
`make eval-corpus-cassettes` and update the sha256 here and in
`docs/evaluation.md` ("Attack-emulation corpus v1", which describes the
contents, the sources and the gate).

The `_meta` line also declares the estate's tenant context
(`tenant_context`: admin, helpdesk and automation accounts, automation and
jump hosts, the server patch window, the scanner). The evaluation measures
it; only the scanner is applied (`tenant_settings`). See `docs/evaluation.md`
("Declared tenant context").

## AIT-ADS (not committed)

`aitads_v1`, a sample of the public AIT Alert Data Set (CC BY 4.0), is built
outside the repository by `python -m tests.fixtures.aitads` (loader and a
19-alert fixture in `tests/fixtures/aitads/`); see `docs/evaluation.md`
("AIT-ADS").

Use these sets to test the pipeline and its safety policy. Do not quote its
numbers as detection accuracy. How to evaluate on real labelled data (the
`analyst_feedback` export) and public benchmarks without committing them is
described in `docs/evaluation.md`.

## Cassettes

`cassettes/synthetic_v1/` and `cassettes/phishing_v1/` hold one cassette per
item for the first 12 synthetic and the first 8 phishing items, recorded with
the fake model (`lg-sotf eval --cassettes DIR`, see `docs/evaluation.md`).
`tests/integration/eval/test_cassettes.py` replays them offline. Record them
again with `make eval-cassettes` after a prompt or agent change.

`cassettes/corpus_v1/` holds one gzip-compressed cassette (`<id>.jsonl.gz`)
for every item of `corpus_v1`, also recorded with the fake model;
`tests/integration/eval/test_corpus_v1_eval.py` replays all 520 and gates
the report. Record them again with `make eval-corpus-cassettes`.
