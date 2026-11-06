"""Response connectors: how approved actions leave the platform (contract section 11).

* :class:`DryRunConnector` (default) records what would have happened.
* :class:`WebhookConnector` sends an HMAC-signed POST per action to the
  tenant's SOAR (Tracecat, Shuffle, Tines, ...); see
  :mod:`lg_sotf.services.connectors.webhook` for the payload schema.
* :class:`ConnectorRegistry` resolves the named built-in connectors per tenant.
* :mod:`lg_sotf.services.connectors.routing` chooses the connector per action
  (kill switches, pinned rows, ``response.routes``, ticketing, Microsoft
  capabilities, the tenant default).
* :mod:`lg_sotf.services.connectors.microsoft` executes actions directly in
  Microsoft 365, Entra ID and Defender for Endpoint (import it explicitly).
"""

from lg_sotf.domain.connectors import (
    Connector,
    ConnectorConfigError,
    ConnectorResult,
    ConnectorStatus,
    LedgerUnavailable,
    MisconfiguredConnector,
    VerificationResult,
    VerificationState,
    Verifier,
    VerifyPlan,
)
from lg_sotf.security.signing import sign, verify_request, verify_signature
from lg_sotf.services.connectors.dry_run import DryRunConnector
from lg_sotf.services.connectors.registry import (
    CONNECTOR_NAMES,
    ROUTE_NAMES,
    STATEFUL_CONNECTORS,
    ConnectorRegistry,
    encrypt_webhook_secret,
    tenant_response_settings,
    webhook_secret_context,
)
from lg_sotf.services.connectors.webhook import (
    SCHEMA as WEBHOOK_SCHEMA,
)
from lg_sotf.services.connectors.webhook import WebhookConnector, WebhookTarget

__all__ = [
    "CONNECTOR_NAMES",
    "Connector",
    "ConnectorConfigError",
    "ConnectorRegistry",
    "ConnectorResult",
    "ConnectorStatus",
    "DryRunConnector",
    "LedgerUnavailable",
    "MisconfiguredConnector",
    "ROUTE_NAMES",
    "STATEFUL_CONNECTORS",
    "VerificationResult",
    "VerificationState",
    "Verifier",
    "VerifyPlan",
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
