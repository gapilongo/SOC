"""Console digests: entity line, one-line reason, per-finding sources, and the routing band."""

from __future__ import annotations

import pytest

from lg_sotf.domain.digests import MAX_FINDINGS, entities_preview, findings, one_line
from lg_sotf.domain.routing import RoutingThresholds, review_band, routing_digest

pytestmark = pytest.mark.unit


def test_entities_preview_takes_the_first_value_of_the_first_three_kinds_in_reading_order() -> None:
    preview = entities_preview(
        {
            "ips": ["203.0.113.4", "198.51.100.7"],
            "users": ["j.doe@example.com"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "hosts": ["ws-042"],
            "domains": [],
        }
    )
    assert preview == {
        "items": [
            {"kind": "user", "value": "j.doe@example.com"},
            {"kind": "host", "value": "ws-042"},
            {"kind": "ip", "value": "203.0.113.4"},
        ],
        "counts": {"user": 1, "host": 1, "ip": 2, "hash": 1},
    }


@pytest.mark.parametrize("entities", [None, {}, {"users": []}, {"users": ["  ", 7]}, "not a mapping"])
def test_entities_preview_is_none_without_entities(entities: object) -> None:
    assert entities_preview(entities) is None


def test_entities_preview_caps_long_values() -> None:
    preview = entities_preview({"urls": ["https://example.com/" + "a" * 500]})
    assert preview is not None and len(preview["items"][0]["value"]) == 128


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Sign-in from a TOR exit node.  MFA was approved after 3 denials.", "Sign-in from a TOR exit node."),
        ("No sentence end\nacross lines", "No sentence end across lines"),
        ("", None),
        ("   ", None),
        (None, None),
        (42, None),
    ],
)
def test_one_line_is_the_first_sentence(text: object, expected: object) -> None:
    assert one_line(text) == expected


def test_one_line_cuts_long_sentences() -> None:
    line = one_line("word " * 100, limit=40)
    assert line is not None and len(line) <= 40 and line.endswith("...")


def test_findings_list_every_provider_result_with_its_source_and_time() -> None:
    summary = {
        "analysis": {
            "tools": [
                {
                    "tool": "reputation",
                    "kind": "ip",
                    "target": "185.220.101.4",
                    "checked_at": "2026-11-06T14:02:13+00:00",
                    "results": [
                        {"provider": "abuseipdb", "status": "ok", "verdict": "malicious", "data": {"score": 100}},
                        {"provider": "virustotal", "status": "error", "verdict": "unknown", "cached": True},
                    ],
                }
            ],
            "history": [
                {"kind": "user", "value": "j.doe", "provider": "history", "status": "ok", "verdict": "benign"},
            ],
        }
    }
    out = findings(summary)
    assert [(f["origin"], f["source"], f["verdict"], f["checked_at"], f["cached"]) for f in out] == [
        ("threat_intel", "abuseipdb", "malicious", "2026-11-06T14:02:13+00:00", False),
        ("threat_intel", "virustotal", "unknown", "2026-11-06T14:02:13+00:00", True),
        ("history", "history", "benign", None, False),
    ]
    assert out[0]["data"] == {"score": 100} and out[0]["target"] == "185.220.101.4"


@pytest.mark.parametrize("summary", [None, {}, {"analysis": "x"}, {"analysis": {"tools": "x", "history": [1]}}])
def test_findings_tolerate_missing_or_malformed_digests(summary: object) -> None:
    assert findings(summary) == []


def test_findings_are_capped() -> None:
    history = [{"kind": "ip", "value": str(i), "provider": "history"} for i in range(MAX_FINDINGS + 5)]
    assert len(findings({"analysis": {"history": history}})) == MAX_FINDINGS


def test_the_review_band_is_the_grey_zone_only_when_the_confidence_is_inside_it() -> None:
    t = RoutingThresholds()
    assert review_band("grey_zone", 42, t) == (t.correlation_grey_zone_min, t.correlation_grey_zone_max)
    assert review_band("grey_zone", 95, t) is None  # an inconclusive verdict, not the band
    assert review_band("false_positive_review", 42, t) is None
    narrow = RoutingThresholds(correlation_grey_zone_min=20, correlation_grey_zone_max=60)
    assert routing_digest("grey_zone", 42.0, narrow) == {"code": "grey_zone", "confidence": 42.0, "band": {"min": 20, "max": 60}}
    assert routing_digest("high_risk", 90.0, narrow) == {"code": "high_risk", "confidence": 90.0, "band": None}
