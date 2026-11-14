"""The Wazuh indexer behind an alert, for the evidence tools (INT3.4).

:class:`WazuhIndexers` resolves the backend of a tool call from the calling run alone: the alert the run
is about (``ctx.alert_id``), read under the run's tenant (``ctx.tenant_id``, that tenant's row-level
security), then the Wazuh source that alert came from. The client it builds talks to that source's
``base_url`` and ``index`` with that source's own stored credentials, under the install's destination
policy and the source's TLS settings: the same configuration the pull connector polls with. No tool
parameter names a source, a URL, an index or a tenant, so a call cannot be pointed at another tenant's
indexer.

A source on a cluster shared between customers has no agent-group or label setting yet (INT3.2, #239);
until it does, such a tenant is separated by its own index pattern and indexer user only.

Why a call cannot be answered is a fixed code (``not_configured``, ``no_wazuh_source``,
``credentials_missing``, ``destination_refused``, ``source_misconfigured``), never the configuration.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from datetime import timedelta
from typing import Optional, Tuple

from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Source
from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps, load_credentials
from lg_sotf.ingestion.sources.base import destination_policy
from lg_sotf.ingestion.sources.wazuh import DEFAULT_INDEX, DEFAULT_MAX_EVENT_LAG_S, WazuhConnector
from lg_sotf.net.egress import DestinationRefused
from lg_sotf.net.tls import build_verify
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from lg_sotf.tools.registry import ToolContext
from lg_sotf.tools.wazuh.indexer import IndexerClient, IndexerUnavailable

MAX_CLIENTS = 64
MAX_LAG_S = 7 * 86_400


class WazuhIndexers:
    """``await indexers(ctx)``: the client for the Wazuh source of the run's alert (one per source, kept open)."""

    def __init__(
        self, settings: Settings, box: Optional[SecretBox], *, deps: Optional[ConnectorDeps] = None,
        max_clients: int = MAX_CLIENTS,
    ) -> None:
        self._settings = settings
        self._box = box
        self._deps = deps or ConnectorDeps()
        self._max_clients = max(1, max_clients)
        self._clients: OrderedDict[Tuple[str, str], Tuple[str, IndexerClient]] = OrderedDict()

    async def __call__(self, ctx: ToolContext) -> IndexerClient:
        if ctx.repos is None:
            raise IndexerUnavailable("not_configured")
        try:
            alert = await ctx.repos.alerts.get(ctx.tenant_id, ctx.alert_id)
            source = await ctx.repos.sources.get(ctx.tenant_id, alert.source_id)
        except NotFound:
            raise IndexerUnavailable("no_wazuh_source") from None
        if source.type != WazuhConnector.source_type or not source.enabled:
            raise IndexerUnavailable("no_wazuh_source")
        key = (source.tenant_id, source.id)
        stamp = json.dumps([source.config, source.secret_ciphertext], sort_keys=True, default=str)
        kept = self._clients.get(key)
        if kept is not None and kept[0] == stamp:
            self._clients.move_to_end(key)
            return kept[1]
        client = self._build(source)
        self._clients[key] = (stamp, client)
        self._clients.move_to_end(key)
        retired = [kept[1]] if kept is not None else []  # the source changed: its old client goes
        while len(self._clients) > self._max_clients:
            retired.append(self._clients.popitem(last=False)[1][1])
        for old in retired:  # closed only once the cache is consistent: closing yields to other calls
            await old.aclose()
        return client

    def _build(self, source: Source) -> IndexerClient:
        config = source.config or {}
        try:
            credentials = load_credentials(self._box, source)
        except SourceConfigError:  # no encryption key, or the stored secret does not decrypt
            raise IndexerUnavailable("credentials_missing") from None
        username, password = credentials.get("username"), credentials.get("password")
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            raise IndexerUnavailable("credentials_missing")
        lag = config.get("max_event_lag_s", DEFAULT_MAX_EVENT_LAG_S)
        try:
            if isinstance(lag, bool) or not isinstance(lag, (int, float)) or not 0 <= lag <= MAX_LAG_S:
                raise SourceConfigError("wazuh config.max_event_lag_s must be between 0 and 604800 seconds")
            return IndexerClient(
                base_url=str(config.get("base_url") or ""),
                index=str(config.get("index") or DEFAULT_INDEX),
                username=username,
                password=password,
                policy=destination_policy(self._settings, IngestionOptions.from_settings(self._settings)),
                verify=build_verify(config, production=self._settings.is_production),
                lag=timedelta(seconds=float(lag)),
                transport=self._deps.transport,
                resolver=self._deps.resolver,
                now=self._deps.now,
            )
        except DestinationRefused:
            raise IndexerUnavailable("destination_refused") from None
        except SourceConfigError:
            raise IndexerUnavailable("source_misconfigured") from None

    async def aclose(self) -> None:
        clients, self._clients = self._clients, OrderedDict()
        for _, client in clients.values():
            await client.aclose()
