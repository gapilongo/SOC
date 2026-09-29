"""LLM fallback output is kept only when it is grounded in the event."""

from __future__ import annotations

from lg_sotf.ingestion.llm_fallback import Grounding

EVENT = {
    "msg": "connection from 11.1.1.10 to evil-example.com, SHA256=" + "ab" * 32,
    "host": "kiosk-9",
    "url": "https://evil-example.com/a?b=c",
    "nested": {"ip6": "2001:db8::1", "ts": "2024-03-05T10:00:00Z"},
}


def test_whole_values_and_tokens_are_grounded() -> None:
    g = Grounding(EVENT)
    assert g.contains("11.1.1.10", "ips")
    assert g.contains("KIOSK-9", "hosts")
    assert g.contains("evil-example.com", "domains")
    assert g.contains("https://evil-example.com/a?b=c", "urls")
    assert g.contains("ab" * 32, "hashes")
    assert g.contains("2001:0db8:0000::1", "ips")
    assert g.contains("2024-03-05T10:00:00Z")


def test_substrings_of_values_are_not_grounded() -> None:
    g = Grounding(EVENT)
    assert not g.contains("1.1.1.1", "ips")
    assert not g.contains("1.1.1.10", "ips")
    assert not g.contains("example.com", "domains")
    assert not g.contains("ab" * 16, "hashes")
    assert not g.contains("kiosk", "hosts")
    assert g.filter(["11.1.1.10", "1.1.1.1"], "ips") == ["11.1.1.10"]
