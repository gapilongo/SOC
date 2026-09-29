"""Analysis tools.

These tools are SIMULATED: they apply static heuristics and tiny built-in
lists instead of querying threat-intelligence, EDR or SIEM services. Every
result carries ``"simulated": True`` and summaries label them as such. Real
integrations replace them one by one behind the same tool names.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional

from lg_sotf.tools.base import BaseToolAdapter

SUSPICIOUS_PORTS = {4444: "metasploit default", 6666: "irc/backdoor", 31337: "back orifice", 8080: "alt http"}
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


class SimulatedTool(BaseToolAdapter):
    cacheable = True
    simulated = True


class IPAnalysisTool(SimulatedTool):
    name = "ip_analysis"
    description = "Classify an IP address and look it up in a small built-in reputation list (simulated)."
    SUSPICIOUS_PREFIXES = ("185.220.", "45.133.", "31.220.", "89.248.", "193.176.")
    MALICIOUS = frozenset({"185.220.101.44", "45.133.1.87", "31.220.43.99"})

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        target = str(args.get("target", "")).strip()
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return {"success": False, "error": "invalid ip"}
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            reputation = "internal"
        elif target in self.MALICIOUS:
            reputation = "malicious"
        elif target.startswith(self.SUSPICIOUS_PREFIXES):
            reputation = "suspicious"
        else:
            reputation = "unknown"
        return {
            "success": True,
            "ip": target,
            "is_private": ip.is_private,
            "reputation": reputation,
            "is_malicious": reputation == "malicious",
            "is_suspicious": reputation in ("malicious", "suspicious"),
        }


class HashAnalysisTool(SimulatedTool):
    name = "hash_analysis"
    description = "Look a file hash up in a small built-in malware list (simulated)."
    # Only the EICAR test file: a known test value, never a real reputation claim.
    MALICIOUS = frozenset({"44d88612fea8a8f36de82e1278abb02f"})

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        target = str(args.get("target", "")).strip().lower()
        if not _HASH_RE.match(target):
            return {"success": False, "error": "invalid hash"}
        malicious = target in self.MALICIOUS
        kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(target)]
        return {
            "success": True,
            "hash_type": kind,
            "reputation": "malicious" if malicious else "unknown",
            "is_malicious": malicious,
            "is_suspicious": malicious,
        }


class ProcessAnalysisTool(SimulatedTool):
    name = "process_analysis"
    description = "Heuristic assessment of a process name (simulated)."
    SUSPICIOUS = frozenset({"mimikatz.exe", "psexec.exe", "procdump.exe", "rundll32.exe", "certutil.exe"})
    LOLBINS = frozenset({"powershell.exe", "cmd.exe", "wmic.exe", "mshta.exe", "regsvr32.exe"})

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        target = str(args.get("target", "")).strip()
        if not target:
            return {"success": False, "error": "missing process"}
        name = target.replace("\\", "/").rsplit("/", 1)[-1].lower()
        suspicious = name in self.SUSPICIOUS
        lolbin = name in self.LOLBINS
        return {
            "success": True,
            "process": name[:128],
            "is_suspicious": suspicious,
            "is_lolbin": lolbin,
            "reputation": "suspicious" if suspicious else ("dual_use" if lolbin else "unknown"),
        }


def network_facts(alert: Mapping[str, Any]) -> Dict[str, Any]:
    """The alert's destination port and transfer size, passed to ``network_analysis`` as arguments."""
    raw = alert.get("raw")
    if isinstance(raw, Mapping) and isinstance(raw.get("raw_data"), Mapping):
        raw = raw["raw_data"]
    raw = raw if isinstance(raw, Mapping) else {}
    return {"destination_port": raw.get("destination_port"), "bytes_transferred": raw.get("bytes_transferred")}


def _as_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class NetworkAnalysisTool(SimulatedTool):
    name = "network_analysis"
    description = "Port and transfer-size heuristics for the alert's network activity (simulated)."

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        port_num = _as_int(args.get("destination_port"))
        transferred = _as_int(args.get("bytes_transferred")) or 0
        return {
            "success": True,
            "destination_port": port_num,
            "port_note": SUSPICIOUS_PORTS.get(port_num if port_num is not None else -1),
            "is_suspicious": port_num in SUSPICIOUS_PORTS,
            "large_transfer": transferred > 1_000_000,
        }


class TemporalAnalysisTool(SimulatedTool):
    name = "temporal_analysis"
    description = "Business-hours and weekend context for the alert time (simulated baseline)."

    async def execute(self, args: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        value = str(args.get("target", ""))
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return {"success": False, "error": "invalid timestamp"}
        dt = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        business = 6 <= dt.hour < 18 and dt.weekday() < 5
        return {
            "success": True,
            "hour_utc": dt.hour,
            "is_business_hours": business,
            "is_weekend": dt.weekday() >= 5,
            "temporal_risk": "low" if business else "medium",
        }


def default_tools() -> List[SimulatedTool]:
    return [IPAnalysisTool(), HashAnalysisTool(), ProcessAnalysisTool(), NetworkAnalysisTool(), TemporalAnalysisTool()]
