"""Pull connectors, keyed by source type.

GuardDuty has no pull connector: findings reach the platform through an
EventBridge rule and API destination posting to the webhook endpoint (see
:mod:`lg_sotf.ingestion.normalizers.guardduty`). ``webhook`` sources are push
only as well.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Type

from lg_sotf.db.repos import Source
from lg_sotf.ingestion.errors import DecryptedSecretError, SourceConfigError, SourceNotPullable
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources.base import ConnectorDeps, FetchedPage, PullConnector, SourceHealth
from lg_sotf.ingestion.sources.crowdstrike import CrowdStrikeConnector
from lg_sotf.ingestion.sources.file import FileConnector
from lg_sotf.ingestion.sources.qradar import QRadarConnector
from lg_sotf.ingestion.sources.sentinel import SentinelConnector
from lg_sotf.ingestion.sources.splunk import SplunkConnector
from lg_sotf.ingestion.sources.wazuh import WazuhConnector
from lg_sotf.security.crypto import DecryptionError, SecretBox
from lg_sotf.settings import Settings

CONNECTORS: Dict[str, Type[PullConnector]] = {
    c.source_type: c
    for c in (SplunkConnector, SentinelConnector, CrowdStrikeConnector, WazuhConnector, QRadarConnector, FileConnector)
}
PUSH_ONLY_TYPES = ("webhook", "guardduty")


def source_secret_context(tenant_id: str, source_id: str) -> str:
    """Encryption context binding a source's credentials to that source (copying ciphertext fails)."""
    return f"source:{tenant_id}:{source_id}"


def encrypt_source_secret(box: SecretBox, tenant_id: str, source_id: str, secret: Mapping[str, Any]) -> str:
    """Ciphertext for ``sources.secret_ciphertext``; the API uses this when a source is created or updated."""
    return box.encrypt_json(dict(secret), context=source_secret_context(tenant_id, source_id))


def load_credentials(box: Optional[SecretBox], source: Source) -> Dict[str, Any]:
    if not source.secret_ciphertext:
        return {}
    if box is None:
        raise SourceConfigError("source credentials are encrypted but security.encryption_keys is not configured")
    try:
        value = box.decrypt_json(
            source.secret_ciphertext, context=source_secret_context(source.tenant_id, source.id)
        )
    except DecryptionError as exc:
        raise DecryptedSecretError("source credentials could not be decrypted") from exc
    if not isinstance(value, dict):
        raise DecryptedSecretError("source credentials must be a JSON object")
    return value


def create_connector(
    source: Source,
    credentials: Mapping[str, Any],
    *,
    settings: Settings,
    options: IngestionOptions,
    deps: Optional[ConnectorDeps] = None,
) -> PullConnector:
    if source.type in PUSH_ONLY_TYPES:
        raise SourceNotPullable(f"{source.type} sources are push-only")
    cls = CONNECTORS.get(source.type)
    if cls is None:
        raise SourceConfigError(f"no pull connector for source type {source.type!r}")
    return cls(source, credentials, settings=settings, options=options, deps=deps)


__all__ = [
    "CONNECTORS",
    "PUSH_ONLY_TYPES",
    "ConnectorDeps",
    "FetchedPage",
    "PullConnector",
    "SourceHealth",
    "create_connector",
    "encrypt_source_secret",
    "load_credentials",
    "source_secret_context",
]
