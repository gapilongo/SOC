"""The AIT-ADS loader on its committed fixture: labels from attack-phase times, hosts restored, a seeded sample."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, Iterator, List

import pytest

from lg_sotf.eval.closure import event_time
from lg_sotf.eval.dataset import parse_dataset
from tests.fixtures.aitads.__main__ import build_file
from tests.fixtures.aitads.loader import NO_PHASE, allocate, build, load_phases, phase_at

pytestmark = pytest.mark.unit

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "aitads" / "fixture"
SCENARIOS = ("russellmitchell", "shaw")


def _sources() -> Dict[str, Iterator[str]]:
    return {name: iter((FIXTURE / f"{name}_wazuh.json").read_text(encoding="utf-8").splitlines())
            for name in SCENARIOS}


def _labels() -> str:
    return (FIXTURE / "labels.csv").read_text(encoding="utf-8")


def test_phases_come_from_labels_csv_start_inclusive_end_exclusive() -> None:
    phases = load_phases(_labels())
    assert set(phases) == set(SCENARIOS)
    dirb = next(p for p in phases["russellmitchell"] if p.name == "dirb")
    assert phase_at(phases["russellmitchell"], datetime.fromtimestamp(dirb.start, UTC)) == "dirb"
    assert phase_at(phases["russellmitchell"], datetime.fromtimestamp(dirb.end, UTC)) != "dirb"
    assert phase_at(phases["russellmitchell"], datetime(2022, 1, 1, tzinfo=UTC)) == NO_PHASE


def test_the_fixture_becomes_a_valid_dataset_with_time_based_labels() -> None:
    text = build(_sources(), _labels(), per_scenario=50)
    dataset = parse_dataset(text)
    assert dataset.synthetic and dataset.meta["source"]["licence"] == "CC BY 4.0"
    assert dataset.splits() == {"russellmitchell": 15, "shaw": 4}
    labels = {i.id: (i.expected.disposition, next(t for t in i.tags if t.startswith("phase:"))) for i in dataset.items}
    by_label: Dict[str, List[str]] = {}
    for label, phase in labels.values():
        by_label.setdefault(label, []).append(phase)
    # Outside every phase: benign.
    assert set(by_label["benign"]) == {"phase:none"} and len(by_label["benign"]) == 13
    # Inside a phase, a detection that never fires outside one: malicious (web 400 bursts, the Nmap user agent).
    assert sorted(by_label["malicious"]) == ["phase:dirb", "phase:dirb", "phase:service_scans"]
    # Inside a phase, a detection also seen outside one (here: in another scenario): inconclusive.
    assert sorted(by_label["inconclusive"]) == ["phase:dirb", "phase:dirb", "phase:dnsteal"]
    for item in dataset.items:
        rule = item.alert["rule"]
        if rule["id"] == "31101":  # web 400s fire outside the phases in shaw
            assert item.expected.disposition != "malicious"


def test_hosts_are_restored_items_are_in_event_time_order_and_normalise() -> None:
    dataset = parse_dataset(build(_sources(), _labels(), per_scenario=50))
    russell = [i for i in dataset.items if i.split == "russellmitchell"]
    names = {i.alert["agent"]["ip"]: i.alert["agent"]["name"] for i in russell}
    assert names["192.168.231.56"] == "davey-mail" and names["172.19.130.4"] == "mail"
    times = [event_time(i) for i in russell]
    assert all(t is not None for t in times) and times == sorted(times)  # type: ignore[type-var]
    assert [i.id for i in russell][:2] == ["ait-russellmitchell-00001", "ait-russellmitchell-00002"]


def test_the_sample_is_stratified_and_reproducible(tmp_path: Path) -> None:
    small = build(_sources(), _labels(), per_scenario=6, attack_share=0.5)
    assert small == build(_sources(), _labels(), per_scenario=6, attack_share=0.5)
    assert small != build(_sources(), _labels(), per_scenario=6, attack_share=0.5, seed=1)
    russell = [i for i in parse_dataset(small).items if i.split == "russellmitchell"]
    phases = [next(t for t in i.tags if t.startswith("phase:")) for i in russell]
    assert len(russell) == 6 and phases.count("phase:none") == 3
    assert allocate({NO_PHASE: 100, "dirb": 1, "wpscan": 50}, 10, 0.4) == {"dirb": 1, "wpscan": 3, NO_PHASE: 6}
    assert allocate({NO_PHASE: 2, "dirb": 0}, 10, 0.2) == {NO_PHASE: 2}
    out = tmp_path / "aitads.jsonl.gz"
    text = build_file(FIXTURE, out, 50, 0.2, 20261108, list(SCENARIOS))
    assert gzip.decompress(out.read_bytes()).decode("utf-8") == text
    meta = json.loads(text.splitlines()[0])["_meta"]
    assert meta["composition"]["russellmitchell"]["labels"] == {"benign": 9, "inconclusive": 3, "malicious": 3}
