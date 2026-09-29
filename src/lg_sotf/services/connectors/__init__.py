"""Response connectors: how approved actions leave the platform (contract section 11).

* :class:`DryRunConnector` (default) records what would have happened.
* :class:`WebhookConnector` sends an HMAC-signed POST per action to the
  tenant's SOAR (Tracecat, Shuffle, Tines, ...); see
  :mod:`lg_sotf.services.connectors.webhook` for the payload schema.
* :class:`ConnectorRegistry` chooses the connector per tenant.
"""

from lg_sotf.services.connectors.base import (
    Connector,
    ConnectorConfigError,
    ConnectorResult,
    ConnectorStatus,
    MisconfiguredConnector,
)
from lg_sotf.services.connectors.dry_run import DryRunConnector
from lg_sotf.services.connectors.registry import (
    CONNECTOR_NAMES,
    ConnectorRegistry,
    encrypt_webhook_secret,
    tenant_response_settings,
    webhook_secret_context,
)
from lg_sotf.services.connectors.webhook import (
    SCHEMA as WEBHOOK_SCHEMA,
)
from lg_sotf.services.connectors.webhook import (
    WebhookConnector,
    WebhookTarget,
    sign,
    verify_request,
    verify_signature,
)

__all__ = [
    "CONNECTOR_NAMES",
    "Connector",
    "ConnectorConfigError",
    "ConnectorRegistry",
    "ConnectorResult",
    "ConnectorStatus",
    "DryRunConnector",
    "MisconfiguredConnector",
    "WEBHOOK_SCHEMA",
    "WebhookConnector",
    "WebhookTarget",
    "encrypt_webhook_secret",
    "sign",
    "tenant_response_settings",
    "verify_request",
    "verify_signature",
    "webhook_secret_context",
]
