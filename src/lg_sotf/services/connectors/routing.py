"""Which connector executes one ledger action: the routing precedence.

Per action, first match wins:

1. install ``response.dry_run`` -> dry run (``kill_switch``);
2. the tenant's ``response.dry_run`` true (or malformed) -> dry run (``tenant_dry_run``);
3. an onboarding sample alert whose route would be ``microsoft`` or
   ``ticketing`` -> dry run (``sample``): a sample never acts on a real system;
4. **pinned** rows keep their recorded connector: a re-run of an
   ``executing`` row, a rollback, a retry, or a scheduler row with
   ``connector`` set. A ``microsoft`` row needs ``integration_id`` to be the
   tenant's *enabled* Microsoft integration (deleted or disabled ->
   :class:`~lg_sotf.services.connectors.base.MisconfiguredConnector`); a
   ``ticketing`` row needs an enabled ticketing integration;
5. **explicit** ``response.routes[action_type]``: ``microsoft`` needs an
   enabled capability executing the type, ``ticketing`` is for
   ``create_ticket`` only (and needs an enabled ticketing integration),
   ``webhook`` and ``dry_run`` are the registry's connectors;
6. ``create_ticket`` with an enabled ticketing integration whose
   ``response_actions`` is on -> ``ticketing``;
7. an enabled capability of the tenant's enabled Microsoft integration
   executes the type -> ``microsoft`` (``capability``);
8. the tenant default (``response.connector``, else the install webhook,
   else dry run).

A configuration problem never falls back to another connector: the route
carries the ``problem`` and the action gets a ``MisconfiguredConnector``
that fails it visibly. Database errors propagate (the workflow node
retries). One :class:`RoutingSnapshot` loads the tenant's integrations once
and routes every action of one execution pass.

Verification (:meth:`RoutingSnapshot.verifier`) only reads, so the dry-run
switches do not apply to it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Iterable, Literal, Mapping, Optional

from lg_sotf.integrations.config import (
    MICROSOFT_KIND,
    TICKETING_KINDS,
    IntegrationConfigError,
    MicrosoftConfig,
    parse_microsoft_config,
)
from lg_sotf.integrations.microsoft.catalog import capabilities, executor, is_live
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.connectors.base import Connector, MisconfiguredConnector, Verifier
from lg_sotf.services.connectors.registry import ROUTE_NAMES, ConnectorRegistry, tenant_response_settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Integration, Repositories, ResponseAction

log = get_logger(__name__)

RouteSource = Literal["kill_switch", "tenant_dry_run", "sample", "pinned", "explicit", "ticketing", "capability", "default"]
MICROSOFT = "microsoft"
TICKETING = "ticketing"
TICKET_ACTION = "create_ticket"
EXTERNAL_ROUTES = frozenset({MICROSOFT, TICKETING})

TicketConnectorFactory = Callable[["Integration"], Connector]
"""Builds the ``create_ticket`` connector for an enabled ticketing integration."""
MicrosoftConnectorFactory = Callable[[str, "Integration", Mapping[str, Any]], Awaitable[Connector]]
"""Builds the connector for the tenant's enabled Microsoft integration from ``(tenant, integration, tenant
settings)`` (the settings give it the protected assets); a ``MisconfiguredConnector`` on config errors."""


@dataclass(frozen=True)
class Route:
    """Where one action type goes: the connector name, why, and (Microsoft) the capability and its live flag."""

    connector: str
    source: RouteSource
    capability: Optional[str] = None
    live: Optional[bool] = None
    problem: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"connector": self.connector, "source": self.source, "capability": self.capability,
                "live": self.live, "problem": self.problem}


class ConnectorRouter:
    """Builds :class:`RoutingSnapshot` objects (one per execution pass)."""

    def __init__(
        self,
        registry: ConnectorRegistry,
        repos: Repositories,
        *,
        tickets: TicketConnectorFactory,
        microsoft: MicrosoftConnectorFactory,
    ) -> None:
        self._registry = registry
        self._repos = repos
        self._tickets = tickets
        self._microsoft = microsoft

    @property
    def registry(self) -> ConnectorRegistry:
        return self._registry

    async def snapshot(self, tenant_id: str, tenant_settings: Mapping[str, Any]) -> RoutingSnapshot:
        """Load the tenant's integrations once; database errors propagate."""
        integrations = await self._repos.integrations.list(tenant_id)
        microsoft = next((i for i in integrations if i.kind == MICROSOFT_KIND), None)
        config: Optional[MicrosoftConfig] = None
        problem: Optional[str] = None
        connector: Optional[Connector] = None
        if microsoft is not None:
            try:
                config = parse_microsoft_config(microsoft.config)
            except IntegrationConfigError as exc:
                problem = f"the Microsoft integration's config is invalid: {exc}"[:300]
            if microsoft.enabled:
                connector = await self._microsoft(tenant_id, microsoft, tenant_settings)
        ticketing = [
            i for i in integrations
            if i.kind in TICKETING_KINDS and i.enabled and i.config.get("response_actions", True)
        ]
        return RoutingSnapshot(
            self._registry,
            tenant_id,
            tenant_settings,
            microsoft=microsoft,
            microsoft_config=config,
            microsoft_problem=problem,
            microsoft_connector=connector,
            tickets=self._tickets(ticketing[0]) if ticketing else None,
        )


class RoutingSnapshot:
    """The routing decisions of one tenant at one moment (see the module docstring)."""

    def __init__(
        self,
        registry: ConnectorRegistry,
        tenant_id: str,
        tenant_settings: Mapping[str, Any],
        *,
        microsoft: Optional[Integration] = None,
        microsoft_config: Optional[MicrosoftConfig] = None,
        microsoft_problem: Optional[str] = None,
        microsoft_connector: Optional[Connector] = None,
        tickets: Optional[Connector] = None,
    ) -> None:
        self._registry = registry
        self._tenant_id = tenant_id
        self._settings = tenant_settings
        self._microsoft = microsoft
        self._config = microsoft_config
        self._problem = microsoft_problem
        self._connector = microsoft_connector
        self._tickets = tickets
        self._install_dry_run = bool(registry.install_dry_run)
        self._tenant_dry_run = registry.forced_dry_run(tenant_settings) and not self._install_dry_run
        raw = tenant_response_settings(tenant_settings).get("routes")
        self._routes: Dict[str, Any] = dict(raw) if isinstance(raw, Mapping) else {}
        if raw is not None and not isinstance(raw, Mapping):
            log.warning("response.routes_invalid")

    @property
    def dry_run_forced(self) -> bool:
        return self._install_dry_run or self._tenant_dry_run

    @property
    def microsoft_integration(self) -> Optional[Integration]:
        return self._microsoft

    # ----------------------------------------------------------------- routes

    def _microsoft_ready(self) -> Optional[str]:
        """Why the tenant's Microsoft integration cannot execute anything now, or ``None``."""
        if self._microsoft is None:
            return "the tenant has no Microsoft integration"
        if not self._microsoft.enabled:
            return "the Microsoft integration is disabled"
        return self._problem

    def _raw_capability(self, action_type: str) -> Optional[str]:
        """An enabled capability named in a stored config that no longer validates (so it is not silently skipped)."""
        if self._microsoft is None:
            return None
        caps = self._microsoft.config.get("capabilities") if isinstance(self._microsoft.config, Mapping) else None
        catalog = capabilities()
        for key, entry in (caps or {}).items():
            if isinstance(entry, Mapping) and entry.get("enabled") is True and key in catalog:
                if action_type in catalog[key].actions:
                    return str(key)
        return None

    def _capability_route(self, action_type: str, source: RouteSource) -> Optional[Route]:
        not_ready = self._microsoft_ready()
        if self._config is None or not_ready:
            if self._microsoft is not None and self._microsoft.enabled and self._problem:
                key = self._raw_capability(action_type)
                if key is not None:
                    return Route(MICROSOFT, source, capability=key, problem=self._problem)
            if source == "explicit":
                return Route(MICROSOFT, source, problem=not_ready or "no Microsoft capability executes this type")
            return None
        spec = executor(self._config, action_type)
        if spec is None:
            if source == "explicit":
                return Route(MICROSOFT, source, problem=f"no enabled Microsoft capability executes {action_type}")
            return None
        return Route(MICROSOFT, source, capability=spec.key, live=is_live(self._config, spec.key))

    def _base_route(self, action_type: str) -> Route:
        explicit = self._routes.get(action_type)
        if explicit is not None:
            if not isinstance(explicit, str) or explicit not in ROUTE_NAMES:
                return Route(str(explicit)[:32], "explicit", problem=f"response.routes.{action_type} is invalid")
            if explicit == MICROSOFT:
                route = self._capability_route(action_type, "explicit")
                assert route is not None
                return route
            if explicit == TICKETING:
                if action_type != TICKET_ACTION:
                    return Route(TICKETING, "explicit", problem="ticketing executes create_ticket only")
                if self._tickets is None:
                    return Route(TICKETING, "explicit", problem="no enabled ticketing integration handles create_ticket")
                return Route(TICKETING, "explicit")
            return Route(explicit, "explicit")
        if action_type == TICKET_ACTION and self._tickets is not None:
            return Route(TICKETING, "ticketing")
        route = self._capability_route(action_type, "capability")
        if route is not None:
            return route
        return Route(self._registry.selected_name(self._settings), "default")

    def route(self, action_type: str, *, sample: bool = False) -> Route:
        """The route of an action type (unpinned). ``sample``: the action belongs to an onboarding sample alert."""
        if self._install_dry_run:
            return Route("dry_run", "kill_switch")
        if self._tenant_dry_run:
            return Route("dry_run", "tenant_dry_run")
        base = self._base_route(action_type)
        if sample and base.connector in EXTERNAL_ROUTES:
            return Route("dry_run", "sample")
        return base

    def routes(self) -> Dict[str, Route]:
        """Every catalog action type's route (not a sample)."""
        from lg_sotf.services.response import ACTION_CATALOG

        return {action_type: self.route(action_type) for action_type in ACTION_CATALOG}

    # ------------------------------------------------------------- connectors

    @staticmethod
    def pinned(action: ResponseAction) -> bool:
        """Whether the row keeps its recorded connector (re-run, rollback, retry, scheduler row)."""
        return action.connector is not None and (
            action.status == "executing" or action.rollback_of is not None or action.execution_owner == "scheduler"
        )

    def needs_sample_check(self, actions: Iterable[ResponseAction]) -> bool:
        """Whether any action would reach Microsoft or ticketing (only then is the alert's source looked up)."""
        if self.dry_run_forced:
            return False
        for action in actions:
            name = action.connector if self.pinned(action) else self.route(action.action_type).connector
            if name in EXTERNAL_ROUTES:
                return True
        return False

    def _pinned_microsoft(self, action: ResponseAction) -> Connector:
        if self._microsoft is None or action.integration_id is None or action.integration_id != self._microsoft.id:
            return MisconfiguredConnector(
                MICROSOFT, "the Microsoft integration this action is pinned to no longer exists"
            )
        if not self._microsoft.enabled:
            return MisconfiguredConnector(MICROSOFT, "the Microsoft integration this action is pinned to is disabled")
        return self._connector or MisconfiguredConnector(MICROSOFT, "the Microsoft integration is not available")

    def _for_route(self, route: Route) -> Connector:
        if route.problem is not None:
            log.warning("response.route_misconfigured", connector=route.connector, problem=route.problem[:200])
            return MisconfiguredConnector(route.connector, route.problem)
        if route.connector == MICROSOFT:
            return self._connector or MisconfiguredConnector(MICROSOFT, "the Microsoft integration is not available")
        if route.connector == TICKETING:
            return self._tickets or MisconfiguredConnector(TICKETING, "no enabled ticketing integration")
        return self._registry.named(self._tenant_id, self._settings, route.connector)

    def connector_for(self, action: ResponseAction, *, sample: bool) -> Connector:
        """The connector that executes ``action`` now (precedence of the module docstring)."""
        if self.dry_run_forced:
            return self._registry.dry_run
        if self.pinned(action):
            name = str(action.connector)
            if sample and name in EXTERNAL_ROUTES:
                return self._registry.dry_run
            if name == MICROSOFT:
                return self._pinned_microsoft(action)
            if name == TICKETING:
                return self._tickets or MisconfiguredConnector(TICKETING, "no enabled ticketing integration")
            return self._registry.named(self._tenant_id, self._settings, name)
        return self._for_route(self.route(action.action_type, sample=sample))

    def verifier(self, action: ResponseAction) -> Optional[Verifier]:
        """The verifier of an executed action (read path: the dry-run switches do not apply), or ``None``."""
        if action.connector != MICROSOFT or self._microsoft is None or not self._microsoft.enabled:
            return None
        if action.integration_id != self._microsoft.id:
            return None
        return self._connector if isinstance(self._connector, Verifier) else None


__all__ = [
    "ConnectorRouter",
    "MicrosoftConnectorFactory",
    "Route",
    "RouteSource",
    "RoutingSnapshot",
    "TicketConnectorFactory",
]
