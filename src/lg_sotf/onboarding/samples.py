"""Built-in synthetic alerts a new tenant can send itself to watch the triage work end to end.

The set is fixed (five canonical-format alerts with stable
``source_alert_id``s), so sending it again stores nothing new: ingestion
deduplicates on ``(source_id, source_alert_id)``. Every indicator is
reserved for documentation and can never point at a real system:

* domains under ``example.com``/``example.net``/``example.org`` and the
  ``.example`` TLD (RFC 2606, RFC 6761);
* IPv4 addresses from TEST-NET-1/2/3 (``192.0.2.0/24``, ``198.51.100.0/24``,
  ``203.0.113.0/24``, RFC 5737);
* the only file hashes are those of the EICAR anti-virus test file.

They are stored under the reserved source id :data:`SAMPLE_SOURCE_ID`,
flagged ``sample`` and never metered for invoicing or quotas.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.domain.benign_evidence import EICAR_MD5, EICAR_SHA256

SAMPLE_NOTE = "Sample alert sent from the LG-SOTF getting-started checklist; all indicators are reserved test values."

_SAMPLES: List[Dict[str, Any]] = [
    {
        "source_alert_id": "sample-001-bruteforce",
        "title": "Multiple failed VPN logins followed by a success",
        "severity": "high",
        "category": "credential_access",
        "rule_name": "vpn-bruteforce-then-success",
        "description": (
            "27 failed VPN logins for one account from a single external address within 4 minutes, "
            "followed by a successful login from the same address."
        ),
        "entities": {"users": ["j.doe@example.com"], "ips": ["203.0.113.45"], "hosts": ["vpn-gw-01.corp.example"]},
        "mitre": {"tactics": ["TA0006"], "techniques": ["T1110"]},
        "minutes_ago": 42,
    },
    {
        "source_alert_id": "sample-002-eicar",
        "title": "EICAR test file detected and quarantined",
        "severity": "low",
        "category": "malware",
        "rule_name": "av-test-signature",
        "description": "The endpoint agent quarantined the EICAR anti-virus test file in a user's downloads folder.",
        "entities": {
            "hosts": ["ws-042.corp.example"],
            "users": ["a.smith@example.com"],
            "hashes": [EICAR_MD5, EICAR_SHA256],
        },
        "mitre": {"tactics": [], "techniques": []},
        "minutes_ago": 35,
    },
    {
        "source_alert_id": "sample-003-beacon",
        "title": "Periodic outbound connections to a newly registered domain",
        "severity": "high",
        "category": "command_and_control",
        "rule_name": "dns-beaconing",
        "description": (
            "Workstation resolved update-check.example every 60 seconds for 3 hours and connected to "
            "198.51.100.23 over HTTPS after each lookup."
        ),
        "entities": {
            "hosts": ["ws-017.corp.example"],
            "domains": ["update-check.example"],
            "ips": ["198.51.100.23"],
        },
        "mitre": {"tactics": ["TA0011"], "techniques": ["T1071.001"]},
        "minutes_ago": 28,
    },
    {
        "source_alert_id": "sample-004-powershell",
        "title": "Encoded PowerShell command launched by an Office document",
        "severity": "critical",
        "category": "execution",
        "rule_name": "office-spawns-encoded-powershell",
        "description": (
            "WINWORD.EXE started powershell.exe with a hidden window and an encoded command "
            "that downloads a script from files.example.net."
        ),
        "entities": {
            "hosts": ["ws-017.corp.example"],
            "users": ["m.jones@example.com"],
            "processes": ["WINWORD.EXE", "powershell.exe"],
            "command_lines": ["powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHMAYQBtAHAAbABlACcA"],
            "domains": ["files.example.net"],
        },
        "mitre": {"tactics": ["TA0002"], "techniques": ["T1059.001", "T1204.002"]},
        "minutes_ago": 20,
    },
    {
        "source_alert_id": "sample-005-scan",
        "title": "Port scan from the IT vulnerability scanner",
        "severity": "low",
        "category": "discovery",
        "rule_name": "internal-port-scan",
        "description": (
            "scanner-01.corp.example (192.0.2.10) probed 1,024 ports on 40 servers during the weekly "
            "scheduled vulnerability scan window."
        ),
        "entities": {"hosts": ["scanner-01.corp.example"], "ips": ["192.0.2.10"]},
        "mitre": {"tactics": ["TA0007"], "techniques": ["T1046"]},
        "minutes_ago": 10,
    },
]


def sample_events(now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """The sample alerts as canonical ingest events, timed a few minutes before ``now``."""
    now = now or datetime.now(UTC)
    events: List[Dict[str, Any]] = []
    for sample in _SAMPLES:
        event = copy.deepcopy(sample)
        minutes = event.pop("minutes_ago")
        event["occurred_at"] = (now - timedelta(minutes=minutes)).isoformat()
        event["description"] = f"{event['description']} {SAMPLE_NOTE}"
        events.append(event)
    return events


SAMPLE_COUNT = len(_SAMPLES)

__all__ = ["EICAR_MD5", "EICAR_SHA256", "SAMPLE_COUNT", "SAMPLE_SOURCE_ID", "sample_events"]
