"""The scenario of the console v2 prototype's investigation screen, as today's workflow would store it.

``docs/design/console-v2`` draws one alert in full: at Northwind Logistics a
Word attachment starts a hidden, encoded PowerShell that downloads a script
from a three-day-old domain (ALR-48213), and the alert is with an analyst as
"needs your decision: likely malicious".

The prototype's observations come from the investigation harness (process
tree, prevalence, logon fan-out from the Wazuh indexer). Today's analysis
has two tools, reputation and tenant history, so this fixture holds what
those would have recorded for the same alert: the prototype's two empty
reputation lookups (the address, the document's hash), its empty tenant
history, a reputation lookup of the domain that returned data, and a lookup
of the script's URL whose provider did not answer (the prototype's failed
sandbox run). Everything is invented and synthetic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Tuple

TITLE = "Encoded PowerShell launched by Microsoft Word"
HOST = "WS-FIN-0142"
USER = "m.keller"
DOMAIN = "cdn-invoice-portal.example"
ADDRESS = "203.0.113.50"
DOCUMENT_SHA256 = "5d1e" + "0a" * 28 + "b07c"
SCRIPT_URL = f"https://{DOMAIN}/a.ps1"
#: The command line as the detector reported it: attacker-controlled text.
COMMAND_LINE = "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
OCCURRED_AT = datetime(2026, 11, 14, 9, 41, 52, tzinfo=UTC)
INGESTED_AT = datetime(2026, 11, 14, 9, 44, 26, tzinfo=UTC)
CHECKED_AT = "2026-11-14T09:44:29+00:00"

#: The fast model's indicators, in its own words: the prototype's claims 1 to 3 and 6.
MODEL_CLAIMS_MALICIOUS = [
    "Word started PowerShell directly from an email attachment that came from the internet.",
    "The PowerShell command is hidden and encoded. Decoded, it downloads a script and runs it in memory.",
    f"The script came from {DOMAIN}, a domain registered three days ago.",
]
MODEL_CLAIMS_BENIGN = ["There is no sign yet that the attacker moved to other hosts."]
CONCLUSION = (
    "Word ran a hidden, encoded PowerShell command that downloaded a script from a three-day-old domain and ran "
    "it in memory. Isolate the host and reset the user's sessions."
)


def normalized() -> Dict[str, Any]:
    """The normalized alert (``alerts.normalized``)."""
    return {
        "title": TITLE,
        "rule_name": "Office application started a script host",
        "description": f"WINWORD.EXE started {COMMAND_LINE}",
        "category": "execution",
        "mitre": {"tactics": ["Execution"], "techniques": ["T1059.001", "T1204.002"]},
        "entities": {
            "hosts": [HOST],
            "users": [USER],
            "domains": [DOMAIN],
            "ips": [ADDRESS],
            "urls": [SCRIPT_URL],
            "hashes": [DOCUMENT_SHA256],
            "processes": ["powershell.exe"],
        },
    }


def reputation(kind: str, target: str, *results: Dict[str, Any]) -> Dict[str, Any]:
    """One entry of ``summary.analysis.tools``."""
    return {
        "tool": "reputation", "kind": kind, "target": target, "results": list(results), "simulated": False,
        "checked_at": CHECKED_AT,
    }


def history(kind: str, value: str, status: str = "not_found", verdict: str = "unknown", **data: Any) -> Dict[str, Any]:
    """One entry of ``summary.analysis.history``."""
    entry: Dict[str, Any] = {"kind": kind, "value": value, "provider": "history", "status": status, "verdict": verdict}
    if data:
        entry["data"] = data
    return {**entry, "checked_at": CHECKED_AT}


def lookups() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``(history, tools)`` of the analysis: two empty history lookups, then four reputation lookups (one with
    data, two empty, one whose provider did not answer)."""
    not_found = {"provider": "virustotal", "status": "not_found", "verdict": "unknown"}
    return (
        [history("user", USER), history("host", HOST)],
        [
            reputation(
                "domain", DOMAIN,
                {"provider": "virustotal", "status": "ok", "verdict": "suspicious",
                 "data": {"malicious_votes": 2, "creation_date": "2026-11-11", "registrar": "Example Registrar"}},
            ),
            reputation("ip", ADDRESS, not_found, {"provider": "abuseipdb", "status": "not_found", "verdict": "unknown"}),
            reputation("hash", DOCUMENT_SHA256, not_found),
            reputation(
                "url", SCRIPT_URL,
                {"provider": "virustotal", "status": "error", "verdict": "unknown", "error": "timeout after 30 s"},
            ),
        ],
    )


def summary() -> Dict[str, Any]:
    """``alerts.summary`` after triage, correlation and analysis, before any decision."""
    past, tools = lookups()
    return {
        "triage": {
            "confidence": 78, "rule_confidence": 70, "priority": 8,
            "rule_fp": [], "rule_tp": ["file_hash_present", "network_connection"],
            "llm_fp": list(MODEL_CLAIMS_BENIGN), "llm_tp": list(MODEL_CLAIMS_MALICIOUS),
            "llm_used": True, "threat_assessment": "likely_threat", "threat_likelihood": 80,
            "threat_categories": ["execution"],
            "reasoning": "An Office document that starts an encoded PowerShell is a common first stage.",
        },
        "correlation": {
            "score": 55, "confidence": 78, "related_alert_ids": [], "related_count": 2, "indicator_count": 4,
            "burst": False, "frequency_level": "low", "llm_used": False, "related_dispositions": {},
        },
        "analysis": {
            "threat_score": 74, "certainty": 80, "verdict": "malicious", "rule_threat_score": 52,
            "rule_verdict": "inconclusive", "rule_corroborated": False, "rule_evidence": [],
            "corroborated_targets": [], "conclusion": CONCLUSION,
            "recommended_actions": ["isolate host", "block domain", "revoke sessions"],
            "llm_used": True, "tool_steps": 4, "llm_calls": 5, "stop_reason": "finished",
            "simulated_evidence": False,
            "threat_indicators": ["file_hash_present", "process_execution", "threat_intel_suspicious"],
            "tools": tools, "history": past,
            "reasoning": ["Check the domain first.", "The domain is new and flagged; check the address."],
        },
    }


#: Why the alert is with a person: no automatic policy applies to a 74 with a malicious verdict.
DECISION = {
    "route": "escalate", "reason": "no automatic policy applies", "disposition": None, "code": "inconclusive",
    "autonomy_tier": "off",
}


def escalation_summary() -> Dict[str, Any]:
    """``escalations.summary`` as the ``escalate`` node writes it."""
    return {
        "title": TITLE, "severity": "high", "confidence": 78, "threat_score": 74, "verdict": "malicious",
        "conclusion": CONCLUSION, "simulated_evidence": False,
        "recommended_actions": ["isolate host", "block domain", "revoke sessions"], "llm_used": True,
        "routing": {"code": "inconclusive", "confidence": 74, "band": None},
        "correlated_alert_ids": [],
    }


def node_events() -> List[Tuple[timedelta, str, str, Dict[str, Any]]]:
    """The timeline up to the escalation: ``(offset from arrival, node, actor type, digest)``."""
    return [
        (timedelta(seconds=1), "gate", "system", {"suppressed": False}),
        (timedelta(seconds=2), "triage", "agent",
         {"confidence": 78, "rule_confidence": 70, "priority": 8, "rule_fp": 0, "rule_tp": 2, "llm_used": True}),
        (timedelta(seconds=3), "correlation", "agent",
         {"score": 55, "related_count": 2, "indicators": 4, "burst": False, "llm_used": False}),
        (timedelta(seconds=7), "analysis", "agent",
         {"threat_score": 74, "rule_threat_score": 52, "verdict": "malicious", "llm_used": True, "tool_steps": 4,
          "simulated_evidence": False}),
        (timedelta(seconds=8), "decide", "system", dict(DECISION)),
        (timedelta(seconds=9), "escalate", "system",
         {"escalation_id": "esc-prototype", "level": "L2", "priority": 8, "created": True, "attached": False}),
    ]
