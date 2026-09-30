"""Dataset format, strict loading, selection, and the shipped synthetic dataset."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.eval.dataset import SOURCE_TYPES, DatasetError, load_dataset, parse_dataset
from lg_sotf.ingestion.normalizers import NormalizeContext, get_normalizer, resolve_format

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
SYNTHETIC = FIXTURES / "synthetic_v1.jsonl"


def item(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "id": "x-1",
        "source_type": "canonical",
        "alert": {"title": "t", "severity": "low"},
        "expected": {"disposition": "benign"},
    }
    base.update(overrides)
    return base


def jsonl(*rows: Dict[str, Any]) -> str:
    return "\n".join(json.dumps(r) for r in rows) + "\n"


def test_parse_minimal_item_with_defaults() -> None:
    ds = parse_dataset(jsonl(item()))
    assert len(ds.items) == 1
    it = ds.items[0]
    assert it.split == "standard" and it.tags == [] and it.labels == []
    assert it.expected.route is None and it.expected.escalation is None
    assert ds.synthetic is False and ds.sha256 and len(ds.sha256) == 64


def test_meta_line_comments_and_blank_lines() -> None:
    text = '{"_meta": {"synthetic": true, "description": "d"}}\n# comment\n\n' + jsonl(item())
    ds = parse_dataset(text)
    assert ds.synthetic and ds.meta["description"] == "d"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("not json\n", ":1: not valid JSON"),
        ("[1, 2]\n", ":1: each line must be a JSON object"),
        (jsonl(item(), {"_meta": {}}), ":2: _meta is only allowed on the first line"),
        (jsonl(item(), item()), ":2: duplicate id 'x-1' (first on line 1)"),
        (jsonl(item(expected={"disposition": "suspicious"})), "expected.disposition"),
        (jsonl(item(expected={"disposition": "benign", "route": "maybe"})), "expected.route"),
        (jsonl(item(source_type="splunkish")), "source_type"),
        (jsonl(item(alert={})), "alert must be a non-empty object"),
        (jsonl(item(source_type="webhook")), "needs source_config"),
        (jsonl(item(source_config={"field_map": {"title": "a"}})), "only used with source_type 'webhook'"),
        (jsonl(item(id="bad id")), "id"),
        (jsonl(item(extra_field=1)), "extra_field"),
        (jsonl(item(labels=[{"annotator": "a", "disposition": "benign"}] * 2)), "each annotator may label"),
        ("\n# only a comment\n", "has no items"),
    ],
)
def test_invalid_datasets_name_the_problem(text: str, message: str) -> None:
    with pytest.raises(DatasetError) as err:
        parse_dataset(text, path="ds.jsonl")
    assert message in str(err.value)


def test_load_dataset_reports_unreadable_files(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="cannot read dataset"):
        load_dataset(tmp_path / "missing.jsonl")
    bad = tmp_path / "latin1.jsonl"
    bad.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(DatasetError, match="not UTF-8"):
        load_dataset(bad)


def test_select_by_split_tags_and_limit() -> None:
    ds = parse_dataset(
        jsonl(
            item(id="a", split="standard", tags=["x", "y"]),
            item(id="b", split="adversarial", tags=["x"]),
            item(id="c", split="adversarial", tags=["x", "y"]),
        )
    )
    assert [i.id for i in ds.select(splits=["adversarial"]).items] == ["b", "c"]
    assert [i.id for i in ds.select(tags=["x", "y"]).items] == ["a", "c"]
    assert [i.id for i in ds.select(limit=1).items] == ["a"]
    assert ds.select(splits=["none"]).items == []
    assert ds.splits() == {"adversarial": 2, "standard": 1}
    assert ds.items[1].is_adversarial


# --------------------------------------------------------------- shipped synthetic dataset


@pytest.fixture(scope="module")
def synthetic() -> Any:
    return load_dataset(SYNTHETIC)


def test_synthetic_dataset_is_labelled_synthetic(synthetic: Any) -> None:
    assert synthetic.synthetic is True
    assert "SYNTHETIC" in synthetic.meta["description"]
    assert all("synthetic" in i.tags for i in synthetic.items)


def test_synthetic_dataset_covers_classes_vendors_and_adversarial_cases(synthetic: Any) -> None:
    assert len(synthetic.items) >= 60
    dispositions = Counter(i.expected.disposition for i in synthetic.items)
    assert dispositions["malicious"] >= 20 and dispositions["benign"] >= 15 and dispositions["inconclusive"] >= 5
    # Email items live in their own set (phishing_v1.jsonl).
    assert {i.source_type for i in synthetic.items} == set(SOURCE_TYPES) - {"email"}
    adversarial = [i for i in synthetic.items if i.split == "adversarial"]
    assert len(adversarial) >= 10
    assert sum(1 for i in adversarial if "prompt-injection" in i.tags) >= 8
    categories = {t for i in synthetic.items for t in i.tags if not t.startswith("vendor:")} - {"synthetic"}
    assert len(categories) >= 20


def _strings(value: Any) -> Any:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_synthetic_dataset_uses_only_documentation_or_private_addresses(synthetic: Any) -> None:
    for it in synthetic.items:
        for text in _strings(it.alert):
            for candidate in IPV4.findall(text):
                try:
                    ip = ipaddress.ip_address(candidate)
                except ValueError:
                    continue  # version strings such as 3.0.2 are not addresses
                assert ip.is_private or any(ip in net for net in DOCUMENTATION_NETS), (it.id, candidate)


def test_every_synthetic_item_normalizes_with_its_source_format(synthetic: Any) -> None:
    for it in synthetic.items:
        if it.source_type == "canonical":
            fmt = "canonical"
        elif it.source_type == "webhook":
            fmt = resolve_format("webhook", {"format": "generic", **(it.source_config or {})})
        else:
            fmt = it.source_type
        source_type = "webhook" if it.source_type in ("webhook", "canonical") else it.source_type
        config = {"format": "generic", **(it.source_config or {})} if it.source_type == "webhook" else {}
        ctx = NormalizeContext(source_id=f"eval-{it.source_type}", source_type=source_type, config=config)
        alert = get_normalizer(fmt).normalize(dict(it.alert), ctx)
        assert alert.title, it.id
