"""Choosing the connector that executes a tenant's approved actions.

Resolution order (first match wins):

1. ``settings.response.dry_run`` (install-wide kill switch) -> dry-run.
2. the tenant's ``response.dry_run: true`` -> dry-run (so does any value
   that is not a boolean: a malformed kill switch fails safe).
3. the tenant's ``response.connector`` (``"dry_run"`` or ``"webhook"``); when
   unset, ``"webhook"`` if the install configures ``response.webhook_url``,
   otherwise ``"dry_run"``.

Tenant settings (``tenants.settings["response"]``, non-secret JSON)::

    {"connector": "webhook",
     "webhook_url": "https://soar.example.com/hooks/lgsotf",
     "webhook_secret_ciphertext": "<Fernet token from encrypt_webhook_secret>",
     "ca_cert_pem": "-----BEGIN CERTIFICATE-----...",   # optional private CA
     "dry_run": false}

A tenant ``webhook_url`` must come with the tenant's own secret: payloads
for a tenant endpoint are never signed with the install secret (a tenant
able to verify with it could forge requests to other tenants' receivers).
The install ``response.webhook_url`` uses ``response.webhook_secret``.
The legacy top-level keys ``connector`` and ``dry_run`` are still honoured.

A configuration error never falls back to another connector silently: it
yields a :class:`MisconfiguredConnector` that fails every action with the
reason, so the problem is visible on the ledger.

Each webhook execution gets a total deadline of a third of
``worker.node_timeout_s`` (at most :data:`~lg_sotf.services.connectors.webhook.DEFAULT_DEADLINE_S`),
so one slow receiver cannot run the ``execute_actions`` node into its timeout.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

import httpx

from lg_sotf.domain.connectors import Connector, ConnectorConfigError, MisconfiguredConnector
from lg_sotf.errors import SourceConfigError
from lg_sotf.net.egress import Resolver, egress_policy
from lg_sotf.net.tls import PROCESS_TLS, TlsContexts, build_verify
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.crypto import DecryptionError, SecretBox
from lg_sotf.services.connectors.dry_run import DryRunConnector
from lg_sotf.services.connectors.webhook import DEFAULT_DEADLINE_S, MIN_ATTEMPT_S, WebhookConnector, WebhookTarget
from lg_sotf.settings import Settings

log = get_logger(__name__)

# What a tenant may choose as its default connector (response.connector).
CONNECTOR_NAMES = ("dry_run", "webhook")
# What response.routes may send one action type to (lg_sotf.services.connectors.routing).
ROUTE_NAMES = ("dry_run", "webhook", "ticketing", "microsoft")
# Connectors that keep external state per action: an execution interrupted mid-call is handed to the
# scheduler (re-run and reconciled) instead of being failed as orphaned.
STATEFUL_CONNECTORS = frozenset({"microsoft"})


def tenant_response_settings(tenant_settings: Mapping[str, Any]) -> Dict[str, Any]:
    """The tenant's ``response`` section merged over the legacy top-level keys."""
    merged: Dict[str, Any] = {}
    for key in ("connector", "dry_run"):
        if key in tenant_settings:
            merged[key] = tenant_settings[key]
    section = tenant_settings.get("response")
    if isinstance(section, Mapping):
        merged.update(section)
    return merged


def webhook_deadline_s(settings: Settings) -> float:
    """Total time one webhook execution may take: a third of the node timeout, at most the default deadline."""
    return max(MIN_ATTEMPT_S, min(DEFAULT_DEADLINE_S, float(settings.worker.node_timeout_s) / 3))


def webhook_secret_context(tenant_id: str) -> str:
    return f"tenant:{tenant_id}:response.webhook_secret"


def encrypt_webhook_secret(box: SecretBox, tenant_id: str, secret: str) -> str:
    """Ciphertext for ``tenants.settings["response"]["webhook_secret_ciphertext"]`` (used by the settings API)."""
    if len(secret.encode("utf-8")) < 16:
        raise ConnectorConfigError("webhook secret must be at least 16 bytes")
    return box.encrypt_json(secret, context=webhook_secret_context(tenant_id))


class ConnectorRegistry:
    def __init__(
        self,
        settings: Settings,
        *,
        overrides: Optional[Mapping[str, Connector]] = None,
        secret_box: Optional[SecretBox] = None,
        target_kinds: Optional[Mapping[str, str]] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        resolver: Optional[Resolver] = None,
        webhook_options: Optional[Mapping[str, Any]] = None,
        tls: TlsContexts = PROCESS_TLS,
    ) -> None:
        """``overrides`` replace built-in connectors by name; ``transport``/``resolver`` are test hooks."""
        self._settings = settings
        self._overrides: Dict[str, Connector] = dict(overrides or {})
        self._box = secret_box
        self._target_kinds = dict(target_kinds or {})
        self._transport = transport
        self._resolver = resolver
        self._webhook_options = dict(webhook_options or {})
        self._tls = tls
        self.dry_run = DryRunConnector()
        self._policy = egress_policy(settings)

    @property
    def install_dry_run(self) -> bool:
        """The install-wide kill switch (``settings.response.dry_run``)."""
        return bool(self._settings.response.dry_run)

    def forced_dry_run(self, tenant_settings: Mapping[str, Any]) -> bool:
        if self._settings.response.dry_run:
            return True
        tenant_flag = tenant_response_settings(tenant_settings).get("dry_run")
        if tenant_flag is None or tenant_flag is False:
            return False
        if tenant_flag is not True:
            log.warning("response.tenant_dry_run_invalid")
        return True

    def selected_name(self, tenant_settings: Mapping[str, Any]) -> str:
        if self.forced_dry_run(tenant_settings):
            return self.dry_run.name
        name = tenant_response_settings(tenant_settings).get("connector")
        if name is None:
            return "webhook" if self._settings.response.webhook_url else self.dry_run.name
        return str(name)

    def for_tenant(self, tenant_id: str, tenant_settings: Mapping[str, Any]) -> Connector:
        return self.named(tenant_id, tenant_settings, self.selected_name(tenant_settings))

    def named(self, tenant_id: str, tenant_settings: Mapping[str, Any], name: str) -> Connector:
        """The connector called ``name`` for this tenant (the dry-run kill switches still win)."""
        if self.forced_dry_run(tenant_settings) or name == self.dry_run.name:
            return self.dry_run
        if name in self._overrides:
            return self._overrides[name]
        if name == "webhook":
            try:
                return self._webhook(tenant_id, tenant_response_settings(tenant_settings))
            except ConnectorConfigError as exc:
                log.warning("response.connector_misconfigured", connector=name, reason=str(exc)[:200])
                return MisconfiguredConnector(name, str(exc))
        return MisconfiguredConnector(str(name)[:64], f"unknown connector {str(name)[:64]!r}")

    def _secret_box(self) -> SecretBox:
        """The injected box; a process without one cannot decrypt tenant webhook secrets."""
        if self._box is None:
            raise ConnectorConfigError("tenant webhook secret cannot be decrypted: encryption keys unavailable")
        return self._box

    def _webhook(self, tenant_id: str, rs: Mapping[str, Any]) -> WebhookConnector:
        install = self._settings.response
        tenant_url = rs.get("webhook_url")
        if tenant_url is not None:
            if not isinstance(tenant_url, str) or not tenant_url:
                raise ConnectorConfigError("tenant webhook_url must be a URL")
            ciphertext = rs.get("webhook_secret_ciphertext")
            if not isinstance(ciphertext, str) or not ciphertext:
                raise ConnectorConfigError("tenant webhook_url is set but webhook_secret_ciphertext is missing")
            try:
                secret = self._secret_box().decrypt_json(ciphertext, context=webhook_secret_context(tenant_id))
            except DecryptionError as exc:
                raise ConnectorConfigError("tenant webhook secret cannot be decrypted") from exc
            if not isinstance(secret, str):
                raise ConnectorConfigError("tenant webhook secret is malformed")
            url, secret_bytes, origin = tenant_url, secret.encode("utf-8"), "tenant"
        else:
            if not install.webhook_url:
                raise ConnectorConfigError("no webhook_url configured for the tenant or the install")
            if install.webhook_secret is None:
                raise ConnectorConfigError("response.webhook_secret is not configured")
            url, secret_bytes, origin = install.webhook_url, install.webhook_secret.get_secret_value().encode(), "install"
        try:
            verify = build_verify(
                {k: rs[k] for k in ("tls_verify", "ca_cert_pem") if k in rs} if origin == "tenant" else {},
                production=True,  # never allow a server-side CA path or tls_verify=false for outbound actions
                contexts=self._tls,
            )
        except SourceConfigError as exc:
            raise ConnectorConfigError(str(exc)) from exc
        options: Dict[str, Any] = {
            "timeout_s": float(install.webhook_timeout_s),
            "deadline_s": webhook_deadline_s(self._settings),
            **self._webhook_options,
        }
        return WebhookConnector(
            WebhookTarget(url=url, secret=secret_bytes, verify=verify, origin=origin),
            policy=self._policy,
            target_kinds=self._target_kinds,
            transport=self._transport,
            resolver=self._resolver,
            tls=self._tls,
            **options,
        )
