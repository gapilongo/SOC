"""Generate, check and inspect the attack-emulation corpus (see ``tests/fixtures/attack_corpus/__init__.py``).

    python -m tests.fixtures.attack_corpus generate [--out FILE]   # .jsonl or .jsonl.gz (default: the committed file)
    python -m tests.fixtures.attack_corpus check                   # the committed file is what the generator writes
    python -m tests.fixtures.attack_corpus alerts OUT              # alerts.json lines for `python -m tests.fixtures.wazuh_lab load`
    python -m tests.fixtures.attack_corpus verify-sources          # sources.json against the pinned upstream files
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from tests.fixtures.attack_corpus.catalog import ART_COMMIT, ATOMICS, ATTACK, ATTACK_VERSION, RULES, WAZUH_TAG
from tests.fixtures.attack_corpus.corpus import alerts_json, build_corpus, gzip_bytes, sha256_text

COMMITTED = Path(__file__).resolve().parents[1] / "eval" / "corpus_v1.jsonl.gz"
WAZUH_RULES_URL = f"https://raw.githubusercontent.com/wazuh/wazuh/{WAZUH_TAG}/ruleset/rules/{{file}}"
ART_INDEX_URL = (f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ART_COMMIT}"
                 "/atomics/Indexes/Indexes-CSV/index.csv")
ATTACK_URL = f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{ATTACK_VERSION}/enterprise-attack/enterprise-attack.json"
COMPLIANCE = ("pci_dss", "gpg13", "gdpr", "hipaa", "nist_800_53", "tsc")
TACTICS = {"initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
           "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
           "credential-access": "Credential Access", "discovery": "Discovery", "lateral-movement": "Lateral Movement",
           "collection": "Collection", "command-and-control": "Command and Control", "exfiltration": "Exfiltration",
           "impact": "Impact", "reconnaissance": "Reconnaissance", "resource-development": "Resource Development"}


def _write(text: str, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(gzip_bytes(text) if out.suffix == ".gz" else text.encode("utf-8"))


def _upstream_rules(files: List[str]) -> Dict[str, Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}
    for name in sorted(set(files)):
        text = httpx.get(WAZUH_RULES_URL.format(file=name), timeout=60).raise_for_status().text
        root = ET.fromstring("<root>" + re.sub(r"<\?xml[^>]*\?>", "", text) + "</root>")  # noqa: S314 - pinned upstream file
        for group in root.iter("group"):
            base = [g.strip() for g in (group.get("name") or "").split(",") if g.strip()]
            for rule in group.findall("rule"):
                groups: List[str] = list(base)
                compliance: Dict[str, List[str]] = {}
                for element in rule.findall("group"):
                    for value in [v.strip() for v in (element.text or "").split(",") if v.strip()]:
                        prefix = next((p for p in COMPLIANCE if value.startswith(p + "_")), None)
                        if prefix:
                            compliance.setdefault(prefix, []).append(value[len(prefix) + 1:])
                        else:
                            groups.append(value)
                found[str(rule.get("id"))] = {
                    "level": int(rule.get("level") or 0),
                    "description": "".join(d.text or "" for d in rule.findall("description")).strip(),
                    "groups": groups, "compliance": compliance,
                    "mitre": [m.text.strip() for m in rule.findall("mitre/id") if m.text],
                }
    return found


def verify_sources() -> int:
    """Fetch the pinned upstream files and compare every entry of sources.json."""
    problems: List[str] = []
    upstream = _upstream_rules([str(r["file"]) for r in RULES.values()])
    for rid, rule in RULES.items():
        theirs = upstream.get(rid)
        ours = {k: rule[k] for k in ("level", "description", "groups", "compliance", "mitre")}
        if theirs != ours:
            problems.append(f"rule {rid}: {ours} != upstream {theirs}")
    index = httpx.get(ART_INDEX_URL, timeout=60).raise_for_status().text
    tests = {f"{row['Technique #']}-{row['Test #']}": (row["Test GUID"], row["Test Name"].strip())
             for row in csv.DictReader(io.StringIO(index))}
    for key, atomic in ATOMICS.items():
        if tests.get(key) != (atomic.guid, atomic.name):
            problems.append(f"atomic {key}: ({atomic.guid}, {atomic.name}) != upstream {tests.get(key)}")
    bundle = httpx.get(ATTACK_URL, timeout=120).raise_for_status().json()
    names: Dict[str, Dict[str, Any]] = {}
    for obj in bundle["objects"]:
        refs = [r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        if obj.get("type") == "attack-pattern" and refs and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            names[refs[0]] = {"name": obj["name"], "tactics": [TACTICS[p["phase_name"]] for p in obj.get("kill_chain_phases", [])
                                                               if p["kill_chain_name"] == "mitre-attack"]}
    for technique, entry in ATTACK.items():
        if names.get(technique) != entry:
            problems.append(f"technique {technique}: {entry} != upstream {names.get(technique)}")
    for line in problems:
        print(line, file=sys.stderr)
    print(f"{len(RULES)} rules, {len(ATOMICS)} atomic tests, {len(ATTACK)} techniques checked; {len(problems)} problems")
    return 1 if problems else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.fixtures.attack_corpus")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="write the dataset (.jsonl, or .jsonl.gz)")
    gen.add_argument("--out", type=Path, default=COMMITTED)
    sub.add_parser("check", help="the committed dataset is byte-for-byte what the generator writes")
    alerts = sub.add_parser("alerts", help="write the alerts as alerts.json lines for the Wazuh lab")
    alerts.add_argument("out", type=Path)
    sub.add_parser("verify-sources", help="compare sources.json with the pinned upstream files (network)")
    args = parser.parse_args(argv)
    if args.command == "verify-sources":
        return verify_sources()
    corpus = build_corpus()
    text = corpus.text()
    if args.command == "generate":
        _write(text, args.out)
        meta = json.loads(text.split("\n", 1)[0])["_meta"]["composition"]
        print(f"{args.out}: {meta['items']} items ({meta['malicious']} malicious, {meta['benign']} benign), "
              f"sha256 {sha256_text(text)}")
        return 0
    if args.command == "alerts":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(alerts_json(corpus.alerts), encoding="utf-8")
        print(f"{args.out}: {len(corpus.alerts)} alerts")
        return 0
    committed = COMMITTED.read_bytes() if COMMITTED.exists() else b""
    if committed != gzip_bytes(text):
        print(f"{COMMITTED} differs from the generator output; run `python -m tests.fixtures.attack_corpus generate`",
              file=sys.stderr)
        return 1
    print(f"{COMMITTED}: up to date, sha256 {sha256_text(text)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
