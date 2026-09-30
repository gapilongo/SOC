"""The shipped phishing evaluation set: shape, reserved names only, and every message parses."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

import pytest

from lg_sotf.core.phishing import PhishingProfile, assess
from lg_sotf.eval.dataset import DatasetError, load_dataset, parse_dataset
from lg_sotf.ingestion.email import parse_email
from lg_sotf.ingestion.normalizers import get_normalizer
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.security.redaction import redact

DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "phishing_v1.jsonl"
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
RESERVED_SUFFIXES = (".test", ".example", "example.com", "example.net", "example.org", "w3.org")
# The URL-shortener signal needs a real shortener host; nothing is ever fetched.
ALLOWED_HOSTS = frozenset({"bit.ly"})


@pytest.fixture(scope="module")
def dataset():  # type: ignore[no-untyped-def]
    return load_dataset(DATASET)


def test_shape_and_labels(dataset) -> None:  # type: ignore[no-untyped-def]
    assert dataset.synthetic and len(dataset.items) >= 30
    assert {i.source_type for i in dataset.items} == {"email"}
    counts = Counter(i.expected.disposition for i in dataset.items)
    assert counts["malicious"] >= 15 and counts["benign"] >= 8 and counts["inconclusive"] >= 3
    adversarial = [i for i in dataset.items if i.split == "adversarial"]
    assert sum("prompt-injection" in i.tags for i in adversarial) >= 4
    patch = dataset.tenant_settings
    assert patch["tools"]["internal_domains"] == ["example.com"]
    assert patch["phishing"]["trusted_authserv_ids"] == ["mx.example.com"]


def test_only_reserved_domains_and_documentation_addresses(dataset) -> None:  # type: ignore[no-untyped-def]
    for item in dataset.items:
        text = item.email.mime
        for candidate in IPV4.findall(text):
            ip = ipaddress.ip_address(candidate)
            assert ip.is_private or any(ip in n for n in DOCUMENTATION_NETS), (item.id, candidate)
        # Domains as the parser reads them (raw text may be folded or quoted-printable encoded).
        doc = parse_email(text.encode("utf-8"), reporter=item.email.reporter)
        hosts = [u["host"] for u in doc["urls"]] + [doc["from"]["domain"] or "example.com"]
        hosts += [a["address"].rsplit("@", 1)[-1] for a in doc["reply_to"]]
        for host in hosts:
            if IPV4.fullmatch(host) or host.isdigit() or host in ALLOWED_HOSTS:
                continue
            assert host.endswith(RESERVED_SUFFIXES), (item.id, host)


def test_every_message_parses_normalizes_and_malicious_ones_carry_signals(dataset) -> None:  # type: ignore[no-untyped-def]
    profile = PhishingProfile.from_settings(dataset.tenant_settings, {})
    for item in dataset.items:
        doc = parse_email(item.email.mime.encode("utf-8"), reporter=item.email.reporter)
        redacted, _ = redact(doc)
        alert = get_normalizer("email").normalize(redacted, NormalizeContext(source_id="email:eval", source_type="email"))
        assert alert.category == "phishing", item.id
        result = assess(alert.email or {}, profile)
        if item.expected.disposition == "malicious":
            assert result.tp and not result.fp, item.id


def test_email_items_are_validated() -> None:
    bad = {"id": "e1", "source_type": "email", "alert": {"body": "x"}, "expected": {"disposition": "benign"}}
    with pytest.raises(DatasetError, match="e1|mime"):
        parse_dataset(json.dumps(bad))
    meta = {"_meta": {"tenant_settings": {"phishing": {"nope": 1}}}}
    good = {"id": "e1", "source_type": "email", "alert": {"mime": "Subject: x\n\ny"}, "expected": {"disposition": "benign"}}
    with pytest.raises(DatasetError, match="tenant_settings"):
        parse_dataset(json.dumps(meta) + "\n" + json.dumps(good))
    assert parse_dataset(json.dumps(good)).tenant_settings == {}
