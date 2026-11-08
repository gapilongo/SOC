### Added

- An attack-emulation ground-truth corpus, `corpus_v1`
  (`tests/fixtures/eval/corpus_v1.jsonl.gz`): 520 labelled Wazuh 4.14
  alerts, 208 malicious and 312 benign (a 40/60 split). The malicious alerts
  come from Atomic Red Team tests chained into Caldera-style campaigns
  (Office macro to credential theft, PsExec to ransomware, SSH brute force to
  persistence, web exploitation to a web shell, Kerberoasting, UAC bypass
  and WMI persistence, a Linux cryptominer, password spraying and more); the
  benign ones are routine noise (admin logins, patching, backups, monitoring)
  and look-alikes that trip the same rules (an authorised scanner, IT using
  PsExec, Ansible editing root's crontab, updaters dropping executables).
  Every alert names its ATT&CK technique and, where one exists, its Atomic
  Red Team test. Alerts use the real rule ids, levels, groups and MITRE
  mappings of the Wazuh v4.14.8 ruleset. A seeded generator
  (`python -m tests.fixtures.attack_corpus`) rebuilds the file byte for byte.
- CI replays the corpus through the real pipeline from committed cassettes
  (fake model, no network) and gates it with
  `tests/fixtures/eval/corpus_v1_thresholds.yaml`: no malicious alert closed
  by automation in any log source. The Wazuh live tests load it into a 4.14
  indexer and read it back through the real Wazuh connector.
- `lg-sotf eval --dataset` reads gzip-compressed datasets (`.jsonl.gz`), and
  cassette replays read gzip-compressed cassettes (`<item>.jsonl.gz`).
