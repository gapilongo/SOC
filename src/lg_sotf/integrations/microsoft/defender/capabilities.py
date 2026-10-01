"""The Defender for Endpoint capabilities (``docs/microsoft-defender.md``).

Every capability calls the Defender for Endpoint API (``api="defender"``) on
the fixed host of the global cloud (``api.security.microsoft.com`` or its
geo host) with a token for ``https://api.securitycenter.microsoft.com``, and
is available in the global cloud only (no Defender token scope is documented
for the US Government clouds). The permissions are WindowsDefenderATP
application permissions with admin consent.
"""

from __future__ import annotations

from lg_sotf.integrations.microsoft.capability import ActionSupport, CapabilitySpec, NoOptions, Permission
from lg_sotf.integrations.microsoft.clouds import GLOBAL_ONLY
from lg_sotf.integrations.microsoft.defender.forensics import ForensicsHandler
from lg_sotf.integrations.microsoft.defender.indicators import (
    DefenderIndicatorOptions,
    FileIndicatorHandler,
    IndicatorHandler,
)
from lg_sotf.integrations.microsoft.defender.isolation import DefenderIsolationOptions, IsolationHandler
from lg_sotf.integrations.microsoft.defender.stop_quarantine import (
    DefenderStopQuarantineOptions,
    StopQuarantineHandler,
)

READ_WRITE = "Machine.ReadWrite.All"
NETWORK_NOTE = "configuration applies in up to 48 h; outside Edge it needs Network Protection in block mode"

DEFENDER_ISOLATION = CapabilitySpec(
    key="defender.isolation",
    package="defender",
    api="defender",
    title="Device isolation",
    description=(
        "Isolate a device from the network in Microsoft Defender for Endpoint (isolate_host), and release it "
        "on rollback (release_host): the pending isolation is cancelled, otherwise the device is unisolated."
    ),
    actions={
        "isolate_host": ActionSupport(
            reversible=True,
            note="Defender lifts isolation automatically after 7 days; offline devices are retried for 3 days",
        ),
        "release_host": ActionSupport(),
    },
    permissions=(
        Permission("defender", "Machine.Isolate", "isolate and release"),
        Permission("defender", READ_WRITE, "find machines and poll machine actions"),
    ),
    options=DefenderIsolationOptions,
    handler=IsolationHandler,
    clouds=GLOBAL_ONLY,
    licence="Defender for Endpoint Plan 1 or 2, or Defender for Business",
    live_confirmation=(
        "Full isolation cuts the device off the network except for Defender; on proxy (PAC/WPAD) networks "
        "use Selective."
    ),
)

DEFENDER_INDICATORS = CapabilitySpec(
    key="defender.indicators",
    package="defender",
    api="defender",
    title="Network indicators",
    description=(
        "Block public IP addresses, domains and URLs with Defender for Endpoint custom indicators (block_ip, "
        "block_domain, block_url; action Block, always with an expiry), and delete the indicator on rollback."
    ),
    actions={
        "block_ip": ActionSupport(reversible=True, note=NETWORK_NOTE),
        "block_domain": ActionSupport(reversible=True, note=NETWORK_NOTE),
        "block_url": ActionSupport(reversible=True, note=NETWORK_NOTE),
        "unblock_ip": ActionSupport(),
        "unblock_domain": ActionSupport(),
        "unblock_url": ActionSupport(),
    },
    permissions=(Permission("defender", "Ti.ReadWrite.All", "create, find and delete indicators"),),
    options=DefenderIndicatorOptions,
    handler=IndicatorHandler,
    clouds=GLOBAL_ONLY,
    licence=(
        "Defender for Endpoint with the Custom network indicators advanced feature; outside Microsoft Edge, "
        "Network Protection in block mode and Defender Antivirus in active mode"
    ),
    live_confirmation=(
        "Indicators apply to every onboarded device (or the listed device groups), take effect within up to "
        "48 hours and count against the tenant's 15,000-indicator limit."
    ),
)

DEFENDER_FILE_INDICATORS = CapabilitySpec(
    key="defender.file_indicators",
    package="defender",
    api="defender",
    title="File indicators",
    description=(
        "Quarantine a file by hash (SHA-256, SHA-1 or MD5) with a Defender for Endpoint file indicator "
        "(quarantine_file; action BlockAndRemediate, always with an expiry), and delete the indicator on "
        "rollback (unblock_file)."
    ),
    actions={
        "quarantine_file": ActionSupport(
            reversible=True,
            note="blocks and remediates the file everywhere; typically enforced within 15-30 min, can take over 2 h",
        ),
        "unblock_file": ActionSupport(),
    },
    permissions=(Permission("defender", "Ti.ReadWrite.All", "create, find and delete indicators"),),
    options=DefenderIndicatorOptions,
    handler=FileIndicatorHandler,
    clouds=GLOBAL_ONLY,
    licence=(
        "Defender for Endpoint Plan 1 or 2, or Defender for Business (where file indicators always apply to "
        "the whole tenant), with the Allow or block file advanced feature and Defender Antivirus in active mode"
    ),
    live_confirmation=(
        "BlockAndRemediate blocks the file and remediates it on every device where it is found; a rollback "
        "deletes the indicator but files already quarantined stay quarantined."
    ),
    excludes=("defender.stop_quarantine",),
)

DEFENDER_STOP_QUARANTINE = CapabilitySpec(
    key="defender.stop_quarantine",
    package="defender",
    api="defender",
    title="Stop and quarantine file",
    description=(
        "Stop the processes of a file and quarantine it (quarantine_file, SHA-1 only) on each device in the "
        "alert's host scope. Cannot be undone through the API."
    ),
    actions={"quarantine_file": ActionSupport(note="stop-and-quarantine cannot be undone through the API")},
    permissions=(
        Permission("defender", "Machine.StopAndQuarantine", "stop and quarantine files"),
        Permission("defender", READ_WRITE, "find machines and poll machine actions"),
    ),
    options=DefenderStopQuarantineOptions,
    handler=StopQuarantineHandler,
    clouds=GLOBAL_ONLY,
    licence="Plan 2 (Plan 1 availability is unconfirmed; not in Defender for Business)",
    live_confirmation=(
        "Stops the file's processes and quarantines it on every device in the alert's host scope; this cannot "
        "be undone through the API."
    ),
    excludes=("defender.file_indicators",),
)

DEFENDER_FORENSICS = CapabilitySpec(
    key="defender.forensics",
    package="defender",
    api="defender",
    title="Investigation package",
    description=(
        "Collect an investigation package on a device (collect_forensics). The package stays in Defender; "
        "LG-SOTF never downloads it."
    ),
    actions={"collect_forensics": ActionSupport(note="the package stays in Defender; LG-SOTF never downloads it")},
    permissions=(
        Permission("defender", "Machine.CollectForensics", "collect investigation packages"),
        Permission("defender", READ_WRITE, "find machines and poll machine actions"),
    ),
    options=NoOptions,
    handler=ForensicsHandler,
    clouds=GLOBAL_ONLY,
    licence="Defender for Endpoint Plan 2",
    live_confirmation="Collection may fail on a device with a low battery or on a metered connection.",
)

__all__ = [
    "DEFENDER_FILE_INDICATORS",
    "DEFENDER_FORENSICS",
    "DEFENDER_INDICATORS",
    "DEFENDER_ISOLATION",
    "DEFENDER_STOP_QUARANTINE",
]
