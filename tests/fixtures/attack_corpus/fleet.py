"""The emulated estate: hosts with Wazuh agents, the people on them and the outside world.

Everything is synthetic: documentation address ranges (RFC 5737) for the
outside world, RFC 1918 inside, ``example.com`` names for the organisation and
``.test`` names for attacker infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

DOMAIN = "CORP"
DNS_SUFFIX = "corp.example.com"
MANAGER = "wazuh-manager"


@dataclass(frozen=True)
class Host:
    name: str
    agent_id: str
    ip: str
    os: str  # "windows" | "linux"
    role: str
    owner: str = ""  # the person who uses a workstation

    @property
    def fqdn(self) -> str:
        return f"{self.name}.{DNS_SUFFIX}"

    def agent(self) -> Dict[str, str]:
        return {"id": self.agent_id, "name": self.name, "ip": self.ip}


def _hosts(*rows: Tuple[str, str, str, str, str, str]) -> Dict[str, Host]:
    return {name: Host(name, agent, ip, os, role, owner) for name, agent, ip, os, role, owner in rows}


HOSTS = _hosts(
    # Linux servers
    ("web-01", "001", "10.20.2.11", "linux", "web", ""),
    ("web-02", "002", "10.20.2.12", "linux", "web", ""),
    ("app-01", "003", "10.20.2.21", "linux", "app", ""),
    ("db-01", "004", "10.20.2.31", "linux", "db", ""),
    ("bastion-01", "005", "10.20.2.5", "linux", "bastion", ""),
    ("build-01", "006", "10.20.2.41", "linux", "ci", ""),
    ("mon-01", "007", "10.20.2.51", "linux", "monitoring", ""),
    ("backup-01", "008", "10.20.2.61", "linux", "backup", ""),
    # Windows workstations
    ("FIN-WS-22", "014", "10.20.1.22", "windows", "workstation", "mjones"),
    ("FIN-WS-31", "015", "10.20.1.31", "windows", "workstation", "pnguyen"),
    ("HR-WS-07", "016", "10.20.1.47", "windows", "workstation", "lgarcia"),
    ("ENG-WS-14", "017", "10.20.1.64", "windows", "workstation", "rkhan"),
    ("ENG-WS-19", "018", "10.20.1.69", "windows", "workstation", "aturner"),
    ("SALES-WS-03", "019", "10.20.1.83", "windows", "workstation", "sbrown"),
    ("MKT-WS-11", "020", "10.20.1.91", "windows", "workstation", "dwilson"),
    ("EXEC-WS-02", "021", "10.20.1.102", "windows", "workstation", "eclark"),
    ("IT-WS-01", "022", "10.20.1.120", "windows", "workstation", "ksmith"),
    # Windows servers
    ("DC-01", "030", "10.20.0.10", "windows", "dc", ""),
    ("DC-02", "031", "10.20.0.11", "windows", "dc", ""),
    ("SRV-FS-01", "032", "10.20.0.20", "windows", "file", ""),
    ("SRV-APP-02", "033", "10.20.0.22", "windows", "app", ""),
    ("SRV-SQL-01", "034", "10.20.0.30", "windows", "sql", ""),
    ("SRV-RDS-01", "035", "10.20.0.40", "windows", "rds", ""),
    ("SRV-BKP-01", "036", "10.20.0.50", "windows", "backup", ""),
)


def by_role(*roles: str) -> Tuple[Host, ...]:
    return tuple(h for h in HOSTS.values() if h.role in roles)


WORKSTATIONS = tuple(h for h in by_role("workstation") if h.name != "IT-WS-01")
WIN_SERVERS = tuple(h for h in by_role("file", "app", "sql", "rds", "backup") if h.os == "windows")
DCS = by_role("dc")
LINUX = tuple(h for h in HOSTS.values() if h.os == "linux")
WEB = by_role("web")
LINUX_SERVERS = tuple(h for h in by_role("web", "app", "db", "ci", "monitoring", "backup") if h.os == "linux")

# People and accounts
LINUX_ADMINS = ("ksmith", "tlee")
WIN_ADMINS = ("adm.ksmith", "adm.tlee")
HELPDESK = ("hd.ochen", "hd.rpatel")
SERVICE_ACCOUNTS = {"backup": "svc_backup", "sccm": "svc_sccm", "sql": "svc_sql", "monitor": "svc_monitor"}
SPN_ACCOUNTS = ("svc_sql", "svc_web", "svc_report", "svc_sharepoint")
NEW_HIRES = ("jfoster", "nmorgan", "bwhite", "cyoung", "vreyes")

# Internal infrastructure
SCANNER_IP = "10.20.5.10"  # the authorised vulnerability scanner
SCANNER_NAME = "SCAN-01"
BASTION_IP = "10.20.2.5"
SCCM_SERVER = "SRV-APP-02"

# The outside world: documentation ranges only
ATTACKER_IPS = (
    "203.0.113.50", "203.0.113.77", "203.0.113.141", "198.51.100.23", "198.51.100.62", "198.51.100.199",
    "192.0.2.44", "192.0.2.180",
)
ATTACKER_DOMAINS = ("cdn-sync.test", "update-check.test", "files-share.test", "office-cdn.test", "telemetry-api.test")
INTERNET_NOISE_IPS = ("203.0.113.9", "203.0.113.200", "198.51.100.140", "192.0.2.77", "192.0.2.211")
VENDOR_UPDATE_HOST = "updates.example.net"
