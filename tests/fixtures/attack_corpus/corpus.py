"""Turn the generated drafts into Wazuh 4.14 alerts and the labelled ``corpus_v1`` dataset.

The dataset is built from alert documents plus a label per alert ``id``
(:func:`dataset_text`), so the same function builds it from the generator's
output and from what the real Wazuh connector reads back out of the lab
indexer; the live round-trip test checks both give the same sha256.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from tests.fixtures.attack_corpus.catalog import (
    ART_COMMIT,
    ATOMICS,
    ATTACK_VERSION,
    WAZUH_TAG,
    rule_block,
    technique_name,
)
from tests.fixtures.attack_corpus.fleet import MANAGER
from tests.fixtures.attack_corpus.scenarios import DAYS, START, Draft, Truth, generate

NAME = "corpus_v1"
VERSION = 1
SEED = 20261108
MALICIOUS = 208
BENIGN = 312
ID_PREFIX = "cv1"
BODY_ORDER = ("full_log", "previous_output", "predecoder", "decoder", "data", "syscheck", "location")
FAMILIES = ("sysmon", "windows", "syscheck", "audit", "sshd", "syslog", "web")


@dataclass(frozen=True)
class Corpus:
    alerts: List[Dict[str, Any]]  # in time order, as the manager writes them
    labels: Dict[str, Truth]  # alert id -> ground truth

    def text(self) -> str:
        return dataset_text(self.alerts, self.labels)


def family(alert: Mapping[str, Any]) -> str:
    """The alert's log source: sysmon, windows, syscheck, audit, sshd, syslog or web."""
    decoder = alert.get("decoder") or {}
    name, parent = str(decoder.get("name", "")), str(decoder.get("parent", ""))
    groups = alert["rule"]["groups"]
    if name.startswith("syscheck"):
        return "syscheck"
    if name == "windows_eventchannel":
        return "sysmon" if "sysmon" in groups else "windows"
    if parent == "auditd":
        return "audit"
    if parent in ("sshd", "pam"):
        return "sshd"
    if name == "web-accesslog":
        return "web"
    return "syslog"


def _stamp(draft: Draft) -> Tuple[str, str]:
    at = draft.at.astimezone(UTC)
    base = at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}"
    return base + "+0000", base + "Z"


def build_alerts(drafts: Sequence[Draft]) -> Tuple[List[Dict[str, Any]], Dict[str, Truth]]:
    """Alert documents in time order with manager-assigned ``id`` and ``firedtimes``."""
    ordered = sorted(enumerate(drafts), key=lambda pair: (pair[1].at, pair[0]))
    fired: Counter[Tuple[str, str]] = Counter()
    offset = 1_048_576
    alerts: List[Dict[str, Any]] = []
    labels: Dict[str, Truth] = {}
    for _, draft in ordered:
        timestamp, at_timestamp = _stamp(draft)
        rule = rule_block(draft.rule, draft.description)
        fired[(draft.host.agent_id, draft.rule)] += 1
        rule = {**{k: rule[k] for k in ("level", "description", "id")},
                "firedtimes": fired[(draft.host.agent_id, draft.rule)],
                **{k: v for k, v in rule.items() if k not in ("level", "description", "id")}}
        alert_id = f"{int(draft.at.timestamp())}.{offset}"
        alert: Dict[str, Any] = {"timestamp": timestamp, "@timestamp": at_timestamp, "rule": rule,
                                 "agent": draft.host.agent(), "manager": {"name": MANAGER}, "id": alert_id}
        for key in BODY_ORDER:
            if key in draft.body:
                alert[key] = draft.body[key]
        unknown = set(draft.body) - set(BODY_ORDER)
        if unknown:
            raise ValueError(f"unexpected alert keys {sorted(unknown)}")
        offset += len(json.dumps(alert)) + 1
        alerts.append(alert)
        labels[alert_id] = draft.truth
    return alerts, labels


def build_corpus(seed: int = SEED) -> Corpus:
    alerts, labels = build_alerts(generate(seed, malicious=MALICIOUS, benign=BENIGN))
    return Corpus(alerts, labels)


def _tags(alert: Mapping[str, Any], truth: Truth) -> List[str]:
    tags = ["synthetic", "vendor:wazuh", f"kind:{truth.kind}", f"scenario:{truth.scenario}",
            f"rule:{alert['rule']['id']}", f"level:{alert['rule']['level']}"]
    if truth.technique:
        tags.append(f"{'technique' if truth.kind == 'attack' else 'resembles'}:{truth.technique}")
    if truth.atomic:
        tags += [f"atomic:{truth.atomic}", f"atomic-guid:{ATOMICS[truth.atomic].guid}"]
    return tags


def _notes(truth: Truth) -> str:
    if truth.kind == "attack":
        name = technique_name(truth.technique) if truth.technique else ""
        if truth.atomic:
            atomic = ATOMICS[truth.atomic]
            how = f'Atomic Red Team {truth.atomic} "{atomic.name}" ({atomic.guid})'
        else:
            how = "manual procedure (no Atomic Red Team test for this step)"
        return f"{truth.procedure}. {truth.technique} {name}; {how}."
    if truth.kind == "lookalike" and truth.technique:
        return f"{truth.procedure}. Benign look-alike of {truth.technique} {technique_name(truth.technique)}."
    return f"{truth.procedure}."


def item(index: int, alert: Mapping[str, Any], truth: Truth) -> Dict[str, Any]:
    malicious = truth.disposition == "malicious"
    return {
        "id": f"{ID_PREFIX}-{index:04d}",
        "source_type": "wazuh",
        "alert": alert,
        "expected": {"disposition": truth.disposition, "escalation": malicious},
        "split": "standard",
        "family": family(alert),
        "tags": _tags(alert, truth),
        "notes": _notes(truth),
    }


def composition(alerts: Sequence[Mapping[str, Any]], labels: Mapping[str, Truth]) -> Dict[str, Any]:
    truths = [labels[a["id"]] for a in alerts]
    by_family: Dict[str, Dict[str, int]] = {}
    for alert, truth in zip(alerts, truths, strict=True):
        counts = by_family.setdefault(family(alert), {"malicious": 0, "benign": 0})
        counts[truth.disposition] += 1
    return {
        "items": len(alerts),
        "malicious": sum(t.disposition == "malicious" for t in truths),
        "benign": sum(t.disposition == "benign" for t in truths),
        "benign_lookalike": sum(t.kind == "lookalike" for t in truths),
        "techniques": len({t.technique for t in truths if t.kind == "attack"}),
        "atomic_tests": len({t.atomic for t in truths if t.atomic}),
        "families": dict(sorted(by_family.items())),
    }


def meta(alerts: Sequence[Mapping[str, Any]], labels: Mapping[str, Truth]) -> Dict[str, Any]:
    return {
        "synthetic": True,
        "version": VERSION,
        "name": NAME,
        "description": (
            "Attack-emulation ground-truth corpus (AI-E1.8): Wazuh 4.14 alerts generated for Atomic Red Team tests "
            "and Caldera-style campaigns, mixed with benign noise and benign look-alikes. Labels come from the "
            "procedure that produced each alert. Generated by tests/fixtures/attack_corpus; see docs/evaluation.md."
        ),
        "generator": {"module": "tests.fixtures.attack_corpus", "seed": SEED,
                      "window": [START.date().isoformat(), f"{DAYS} days"]},
        "sources": {"wazuh_ruleset": WAZUH_TAG, "attack": ATTACK_VERSION, "atomic_red_team": ART_COMMIT},
        "composition": composition(alerts, labels),
    }


def dataset_text(alerts: Iterable[Mapping[str, Any]], labels: Mapping[str, Truth]) -> str:
    """The JSONL dataset: a ``_meta`` line, then one item per alert in the order given."""
    ordered = list(alerts)
    lines = [json.dumps({"_meta": meta(ordered, labels)}, ensure_ascii=False, separators=(",", ":"))]
    for index, alert in enumerate(ordered, start=1):
        lines.append(json.dumps(item(index, alert, labels[alert["id"]]), ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def gzip_bytes(text: str) -> bytes:
    """Byte-reproducible gzip (no name, no timestamp)."""
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0, compresslevel=9) as fh:
        fh.write(text.encode("utf-8"))
    return buffer.getvalue()


def alerts_json(alerts: Iterable[Mapping[str, Any]]) -> str:
    """The manager's ``alerts.json`` form (one alert per line), loadable with ``python -m tests.fixtures.wazuh_lab load``."""
    return "".join(json.dumps(alert, ensure_ascii=False, separators=(",", ":")) + "\n" for alert in alerts)
