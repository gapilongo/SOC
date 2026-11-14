"""corpus_v1 (AI-E1.8): the committed attack-emulation corpus is reproducible, labelled and Wazuh 4.14-shaped.

The integration gate (tests/integration/eval/test_corpus_v1_eval.py) replays it
through the pipeline; the live test (tests/live/wazuh/test_attack_corpus.py)
round-trips it through the real connector and a 4.14 indexer.
"""

from __future__ import annotations

import gzip
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List

import pytest

from lg_sotf.eval.dataset import DatasetError, EvalItem, load_dataset
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.ingestion.normalizers.wazuh import WazuhNormalizer
from tests.fixtures.attack_corpus import BENIGN, MALICIOUS, build_corpus, dataset_text, sha256_text
from tests.fixtures.attack_corpus.catalog import ATOMICS, ATTACK, RULES, SOURCES
from tests.fixtures.attack_corpus.corpus import FAMILIES, gzip_bytes

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
DATASET = ROOT / "tests" / "fixtures" / "eval" / "corpus_v1.jsonl.gz"
SCENARIOS = ROOT / "tests" / "fixtures" / "attack_corpus" / "scenarios.py"
DOCS = (ROOT / "docs" / "evaluation.md", ROOT / "tests" / "fixtures" / "eval" / "README.md")
SHA256 = "42e40657d357939cc4719139cbdc069c8f61a5c0bb3b3ca16f3517165f2e3b69"


@pytest.fixture(scope="module")
def items() -> List[EvalItem]:
    return load_dataset(DATASET).items


@pytest.fixture(scope="module")
def meta() -> Dict[str, Any]:
    first = gzip.decompress(DATASET.read_bytes()).decode("utf-8").split("\n", 1)[0]
    return dict(json.loads(first)["_meta"])


def test_the_seeded_generator_reproduces_the_committed_file_byte_for_byte() -> None:
    text = build_corpus().text()
    assert gzip_bytes(text) == DATASET.read_bytes(), "run `python -m tests.fixtures.attack_corpus generate`"
    assert sha256_text(text) == load_dataset(DATASET).sha256 == SHA256
    for doc in DOCS:
        assert SHA256 in doc.read_text(encoding="utf-8"), f"record the corpus sha256 in {doc.name}"


def test_composition_is_500_plus_alerts_at_a_40_60_malicious_to_benign_split(
    items: List[EvalItem], meta: Dict[str, Any]
) -> None:
    counts = Counter(i.expected.disposition for i in items)
    assert len(items) >= 500 and counts == {"malicious": MALICIOUS, "benign": BENIGN}
    assert counts["malicious"] / len(items) == pytest.approx(0.4)
    assert meta["composition"]["items"] == len(items) and meta["synthetic"] is True
    families = Counter((i.family, i.expected.disposition) for i in items)
    for family in FAMILIES:  # every log source has both classes
        assert families[(family, "malicious")] >= 5 and families[(family, "benign")] >= 10, family
    kinds = Counter(next(t for t in i.tags if t.startswith("kind:")) for i in items)
    assert kinds["kind:attack"] == MALICIOUS and kinds["kind:lookalike"] >= 80 and kinds["kind:noise"] >= 150


def test_every_label_names_its_technique_and_atomic_test(items: List[EvalItem]) -> None:
    techniques, atomics = set(), set()
    for item in items:
        tags = {t.split(":", 1)[0]: t.split(":", 1)[1] for t in item.tags if ":" in t}
        assert item.source_type == "wazuh" and item.split == "standard" and item.notes
        assert item.expected.escalation is (item.expected.disposition == "malicious")
        if tags["kind"] == "attack":
            assert item.expected.disposition == "malicious" and tags["technique"] in ATTACK
            techniques.add(tags["technique"])
            if "atomic" in tags:
                atomic = ATOMICS[tags["atomic"]]
                assert atomic.technique == tags["technique"] and tags["atomic-guid"] == atomic.guid
                assert atomic.guid in item.notes and atomic.name in item.notes
                atomics.add(atomic.key)
            else:
                assert "manual procedure" in item.notes
        else:
            assert item.expected.disposition == "benign"
            if tags["kind"] == "lookalike":
                assert tags["resembles"] in ATTACK and "look-alike" in item.notes
    assert len(techniques) >= 40 and len(atomics) >= 40
    share = sum(1 for i in items if any(t.startswith("atomic:") for t in i.tags)) / MALICIOUS
    assert share >= 0.7  # most malicious alerts come from an Atomic Red Team test


def test_alerts_carry_the_4_14_rule_metadata_and_a_wazuh_shape(items: List[EvalItem]) -> None:
    normalizer = WazuhNormalizer()
    ctx = NormalizeContext(source_id="src-1", source_type="wazuh", now=datetime(2026, 11, 8, tzinfo=UTC))
    for item in items:
        alert = item.alert
        rule, source = alert["rule"], RULES[alert["rule"]["id"]]
        assert (rule["level"], rule["groups"]) == (source["level"], source["groups"])
        assert rule.get("mitre", {}).get("id", []) == source["mitre"]
        if "$(" in source["description"]:
            assert "$(" not in rule["description"]
        else:
            assert rule["description"] == source["description"]
        for key in ("timestamp", "agent", "manager", "id", "decoder", "location"):
            assert key in alert, (item.id, key)
        assert re.fullmatch(r"\d{10}\.\d+", alert["id"])
        win = (alert.get("data") or {}).get("win")
        if win:
            values = " ".join(str(v) for v in win["eventdata"].values())
            assert "\\" not in values.replace("\\\\", ""), item.id  # every backslash doubled, as 4.x writes them
        canonical = normalizer.normalize(alert, ctx)
        assert canonical.title == rule["description"]


def _context_events(name: str) -> List[Dict[str, Any]]:
    lines = gzip.decompress((DATASET.parent / name).read_bytes()).decode("utf-8").splitlines()
    return [doc for doc in map(json.loads, lines) if "_meta" not in doc]


def test_the_telemetry_does_not_give_the_label_away(items: List[EvalItem]) -> None:
    # The alerts of both datasets, and the context events an investigation reads next to them (AI-E1.10).
    documents = {item.id: item.alert for item in items}
    documents.update({item.id: item.alert for item in load_dataset(DATASET.parent / "corpus_skills_v1.jsonl.gz").items})
    for name in ("corpus_v1_events.jsonl.gz", "corpus_skills_v1_events.jsonl.gz"):
        events = _context_events(name)
        assert events, name
        documents.update({f"{name}:{doc['id']}": doc for doc in events})
        for doc in events:  # an event is a Wazuh document, never a dataset item: no label, tag or note travels with it
            assert not {"expected", "tags", "notes", "family", "split", "labels"} & set(doc), doc["id"]
    assert len(documents) > 1300
    for name, alert in documents.items():
        text = json.dumps(alert).lower()
        assert "atomic" not in text and "redteam" not in text and "red team" not in text, name
        # Rule texts are Wazuh's own ("...execute of malicious software"); the event itself carries no label.
        event = json.dumps({k: v for k, v in alert.items() if k != "rule"}).lower()
        assert "malicious" not in event and "benign" not in event and "lookalike" not in event, name
        for word in ("attack", "skills:", "context-abuse", "early-stage", "csk1-", "cv1-"):
            assert word not in event, (name, word)


def test_sources_hold_exactly_what_the_scenarios_reference() -> None:
    source = SCENARIOS.read_text(encoding="utf-8")
    rules = set(re.findall(r'g\.emit\([^"]*?"(\d{3,6})"', source, re.S)) | set(re.findall(r'rule = "(\d{3,6})"', source))
    atomics = set(re.findall(r'"(T\d{4}(?:\.\d{3})?-\d+)"', source))
    assert set(RULES) == rules and set(ATOMICS) == atomics
    data = json.loads(SOURCES.read_text(encoding="utf-8"))
    referenced = set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"', source)) | {t for r in RULES.values() for t in r["mitre"]}
    assert set(data["attack"]) == referenced


def test_the_dataset_can_be_rebuilt_from_the_alerts_alone() -> None:
    corpus = build_corpus()
    # The live round trip rebuilds the dataset from what the connector reads back, keyed by alert id.
    assert dataset_text(list(corpus.alerts), corpus.labels) == corpus.text()
    assert sha256_text(dataset_text(json.loads(json.dumps(corpus.alerts)), corpus.labels)) == SHA256


def test_a_damaged_gzip_dataset_is_a_dataset_error(tmp_path: Path) -> None:
    broken = tmp_path / "broken.jsonl.gz"
    broken.write_bytes(DATASET.read_bytes()[:200])
    with pytest.raises(DatasetError, match="cannot read dataset"):
        load_dataset(broken)
    plain = tmp_path / "not-gzip.jsonl.gz"
    plain.write_text('{"id": "x"}\n', encoding="utf-8")
    with pytest.raises(DatasetError, match="cannot read dataset"):
        load_dataset(plain)
