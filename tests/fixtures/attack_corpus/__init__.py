"""Attack-emulation ground-truth corpus (AI-E1.8): ``corpus_v1``.

A seeded generator writes Wazuh 4.14 alerts for what happened in an emulated
estate over twelve days: Atomic Red Team tests chained into Caldera-style
campaigns (macro intrusion, PsExec and ransomware, SSH brute force to
persistence, web exploitation to a web shell, Kerberoasting, UAC bypass and
WMI persistence, LOLBin ingress, a Linux cryptominer, password spraying, a
local admin backdoor, collection and exfiltration) plus single atomic runs,
mixed with benign noise and benign look-alikes that trip the same rules.
Every alert is labelled from the procedure that produced it.

No attack runs here (no Windows endpoints, no agents): the generator writes
what a 4.14 manager would have written, with real rule ids, levels, groups,
compliance tags and MITRE mappings from the v4.14.8 ruleset, real Atomic Red
Team test ids, and the decoder field names and value shapes of each source.

Modules: :mod:`.fleet` (hosts, people, address space), :mod:`.catalog`
(pinned upstream reference data in ``sources.json``), :mod:`.alerts` (alert
bodies per decoder), :mod:`.scenarios` (what happened) and :mod:`.corpus`
(alerts, labels and the dataset). Commands::

    python -m tests.fixtures.attack_corpus generate [--out tests/fixtures/eval/corpus_v1.jsonl.gz]
    python -m tests.fixtures.attack_corpus alerts OUT.json     # alerts.json lines for the Wazuh lab
    python -m tests.fixtures.attack_corpus check               # the committed file matches the generator
    python -m tests.fixtures.attack_corpus verify-sources      # sources.json against the pinned upstreams
"""

from tests.fixtures.attack_corpus.corpus import (
    BENIGN,
    MALICIOUS,
    NAME,
    SEED,
    Corpus,
    build_corpus,
    dataset_text,
    family,
    sha256_text,
)

__all__ = ["BENIGN", "MALICIOUS", "NAME", "SEED", "Corpus", "build_corpus", "dataset_text", "family", "sha256_text"]
