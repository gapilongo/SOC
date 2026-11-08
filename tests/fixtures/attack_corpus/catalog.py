"""Reference data the generator reads: Wazuh 4.14.8 rules, ATT&CK v16.1 names, Atomic Red Team tests.

``sources.json`` holds only the entries the corpus uses, extracted from pinned
upstream sources (``python -m tests.fixtures.attack_corpus verify-sources``
fetches them again and checks every entry):

* ``rules``: rule id -> level, description, groups and compliance mappings as
  the Wazuh v4.14.8 ruleset defines them (``ruleset/rules/*.xml``).
* ``attack``: technique id -> name and tactics, ATT&CK v16.1 (the
  ``enterprise-attack.json`` bundle of ``mitre/cti``), the version a 4.14
  manager's MITRE database carries.
* ``atomics``: ``T1003.001-1`` -> GUID and name of that Atomic Red Team test at
  commit ``ART_COMMIT`` (the last commit before ATT&CK v19 renumbered it).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

SOURCES = Path(__file__).with_name("sources.json")
WAZUH_TAG = "v4.14.8"
ATTACK_VERSION = "16.1"
ART_COMMIT = "61080b19460f2c6431c31689d58063c5f6c1f8fb"
COMPLIANCE_FIELDS = ("pci_dss", "gpg13", "gdpr", "hipaa", "nist_800_53", "tsc")


@dataclass(frozen=True)
class Atomic:
    key: str  # "T1003.001-1": technique and test number
    guid: str
    name: str

    @property
    def technique(self) -> str:
        return self.key.rsplit("-", 1)[0]


def _load() -> Dict[str, Any]:
    return json.loads(SOURCES.read_text(encoding="utf-8"))


_DATA = _load()
RULES: Dict[str, Dict[str, Any]] = _DATA["rules"]
ATTACK: Dict[str, Dict[str, Any]] = _DATA["attack"]
ATOMICS: Dict[str, Atomic] = {key: Atomic(key, v["guid"], v["name"]) for key, v in _DATA["atomics"].items()}


def atomic(key: str) -> Atomic:
    return ATOMICS[key]


def technique_name(technique: str) -> str:
    return str(ATTACK[technique]["name"])


def rule_block(rule_id: str, description: Optional[str] = None) -> Dict[str, Any]:
    """The alert's ``rule`` object (without ``firedtimes``), as a 4.14 manager writes it.

    ``description`` replaces the rule's text when it has ``$(field)`` placeholders the
    manager expands from the event.
    """
    rule = RULES[rule_id]
    level = int(rule["level"])
    block: Dict[str, Any] = {
        "level": level,
        "description": description or rule["description"],
        "id": rule_id,
        "mail": level >= 12,
        "groups": list(rule["groups"]),
    }
    mitre: List[str] = list(rule["mitre"])
    if mitre:
        tactics: List[str] = []
        for technique in mitre:
            for tactic in ATTACK[technique]["tactics"]:
                if tactic not in tactics:
                    tactics.append(tactic)
        block["mitre"] = {"id": mitre, "tactic": tactics, "technique": [technique_name(t) for t in mitre]}
    for name in COMPLIANCE_FIELDS:
        values = rule["compliance"].get(name)
        if values:
            block[name] = list(values)
    return block
