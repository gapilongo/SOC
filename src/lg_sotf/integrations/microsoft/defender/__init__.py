"""Direct response in Microsoft Defender for Endpoint (``docs/microsoft-defender.md``).

* ``defender.isolation``        isolate_host, release_host
* ``defender.indicators``       block_ip, block_domain, block_url and their unblock_* rollbacks
* ``defender.file_indicators``  quarantine_file (BlockAndRemediate file indicator), unblock_file
* ``defender.stop_quarantine``  quarantine_file (StopAndQuarantineFile, SHA-1, irreversible)
* ``defender.forensics``        collect_forensics (investigation package, never downloaded)

``defender.file_indicators`` and ``defender.stop_quarantine`` exclude each
other: both execute ``quarantine_file``.
"""

from typing import Tuple

from lg_sotf.integrations.microsoft.capability import CapabilitySpec
from lg_sotf.integrations.microsoft.defender.capabilities import (
    DEFENDER_FILE_INDICATORS,
    DEFENDER_FORENSICS,
    DEFENDER_INDICATORS,
    DEFENDER_ISOLATION,
    DEFENDER_STOP_QUARANTINE,
)

CAPABILITIES: Tuple[CapabilitySpec, ...] = (
    DEFENDER_ISOLATION,
    DEFENDER_INDICATORS,
    DEFENDER_FILE_INDICATORS,
    DEFENDER_STOP_QUARANTINE,
    DEFENDER_FORENSICS,
)

__all__ = [
    "CAPABILITIES",
    "DEFENDER_FILE_INDICATORS",
    "DEFENDER_FORENSICS",
    "DEFENDER_INDICATORS",
    "DEFENDER_ISOLATION",
    "DEFENDER_STOP_QUARANTINE",
]
