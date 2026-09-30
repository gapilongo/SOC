"""Deterministic per-format normalizers and the registry that picks one for a source.

Formats: ``canonical`` (our schema), ``splunk``, ``crowdstrike``, ``sentinel``,
``wazuh``, ``guardduty``, ``qradar``, ``webhook`` (generic, dot-path field
map) and ``email`` (documents from the platform's own MIME parser, for the
email push endpoint and the ``m365_mailbox``/``imap`` sources only). Vendor
source types use their own format. ``webhook`` and ``file``
sources choose one with ``config.format`` (``generic`` is the field-map
format); without one they use it when a ``field_map`` is configured and
``canonical`` otherwise, so vendors that
push native payloads (e.g. GuardDuty through EventBridge) can use a webhook
source with ``format: guardduty``.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.normalizers.base import NormalizeContext, Normalizer, event_hash, get_path
from lg_sotf.ingestion.normalizers.canonical import CanonicalNormalizer
from lg_sotf.ingestion.normalizers.crowdstrike import CrowdStrikeNormalizer
from lg_sotf.ingestion.normalizers.email import EmailNormalizer
from lg_sotf.ingestion.normalizers.guardduty import GuardDutyNormalizer
from lg_sotf.ingestion.normalizers.qradar import QRadarNormalizer
from lg_sotf.ingestion.normalizers.sentinel import SentinelNormalizer
from lg_sotf.ingestion.normalizers.splunk import SplunkNormalizer
from lg_sotf.ingestion.normalizers.wazuh import WazuhNormalizer
from lg_sotf.ingestion.normalizers.webhook import WebhookNormalizer, parse_webhook_config

NORMALIZERS: Dict[str, Normalizer] = {
    n.name: n
    for n in (
        CanonicalNormalizer(),
        SplunkNormalizer(),
        CrowdStrikeNormalizer(),
        SentinelNormalizer(),
        WazuhNormalizer(),
        GuardDutyNormalizer(),
        QRadarNormalizer(),
        WebhookNormalizer(),
        EmailNormalizer(),
    )
}
VENDOR_FORMATS = ("splunk", "crowdstrike", "sentinel", "wazuh", "guardduty", "qradar")
CANONICAL = "canonical"
EMAIL = "email"
# Sources whose events are parsed emails; ``email`` is the reserved push source type (POST /ingest/email).
EMAIL_SOURCE_TYPES = ("m365_mailbox", "imap", "email")


def get_normalizer(fmt: str) -> Normalizer:
    try:
        return NORMALIZERS[fmt]
    except KeyError:
        raise SourceConfigError(f"unknown event format {fmt!r}") from None


def resolve_format(source_type: Optional[str], config: Optional[Mapping[str, Any]] = None) -> str:
    """The normalizer name for a source; ``None`` (an unregistered source id) means canonical."""
    cfg = config or {}
    if source_type is None:
        return CANONICAL
    if source_type in VENDOR_FORMATS:
        return source_type
    if source_type in EMAIL_SOURCE_TYPES:
        return EMAIL
    if source_type in ("webhook", "file"):
        fmt = cfg.get("format")
        if fmt == "generic" or (fmt is None and "field_map" in cfg):
            fmt = "webhook"
        elif fmt is None:
            fmt = CANONICAL
        if fmt == EMAIL:
            # Only the platform's MIME parser produces email documents (their facts drive triage).
            raise SourceConfigError(f"the email format cannot be pushed to a {source_type} source")
        if fmt not in NORMALIZERS:
            raise SourceConfigError(f"unknown event format {fmt!r} for a {source_type} source")
        if fmt == "webhook":
            parse_webhook_config(cfg)
        return str(fmt)
    raise SourceConfigError(f"unknown source type {source_type!r}")


__all__ = [
    "CANONICAL",
    "EMAIL",
    "EMAIL_SOURCE_TYPES",
    "NORMALIZERS",
    "VENDOR_FORMATS",
    "NormalizeContext",
    "Normalizer",
    "event_hash",
    "get_normalizer",
    "get_path",
    "parse_webhook_config",
    "resolve_format",
]
