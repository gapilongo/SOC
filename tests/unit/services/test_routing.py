"""Connector routing: kill switches, samples, pinned rows, explicit routes, ticketing, capabilities, default."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Callable, Dict, Iterator, List, Optional

import pytest

from lg_sotf.db.repos.integrations import Integration
from lg_sotf.domain.connectors import VerificationResult
from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.services.connectors import ConnectorRegistry, ConnectorResult, DryRunConnector, MisconfiguredConnector
from lg_sotf.services.connectors.routing import ConnectorRouter, RoutingSnapshot
from lg_sotf.services.response import ACTION_CATALOG, ResponsePolicyError, validate_response_settings
from lg_sotf.settings import Settings
from tests.fixtures.microsoft import fake_config, make_action
from tests.unit.integrations.microsoft._support import FAKE_SPECS

ISO = "defender.fake_isolation"


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


class Named:
    def __init__(self, name: str, integration_id: Optional[uuid.UUID] = None) -> None:
        self.name = name
        self.integration_id = integration_id

    async def execute(self, action: Any) -> ConnectorResult:
        return ConnectorResult("succeeded")


class FakeMicrosoftConnector(Named):
    async def verify(self, action: Any) -> VerificationResult:
        return VerificationResult("verified")


def integration(kind: str, *, enabled: bool = True, config: Optional[Dict[str, Any]] = None,
                integration_id: Optional[uuid.UUID] = None) -> Integration:
    now = datetime.now(UTC)
    return Integration.model_validate({
        "id": integration_id or uuid.uuid4(), "tenant_id": "tenant-a", "kind": kind, "name": f"{kind}-x",
        "enabled": enabled, "config": config or {}, "secret_ciphertext": None, "events": [], "min_severity": "low",
        "created_by": None, "created_at": now, "updated_at": now,
    })


def microsoft(live: bool = True, *, enabled: bool = True, key: str = ISO) -> Integration:
    config, _ = fake_config(capabilities={key: {"enabled": True, "live": live}})
    return integration("microsoft", enabled=enabled, config=config)


class Repos:
    def __init__(self, items: List[Integration], *, fail: bool = False) -> None:
        self.integrations = self
        self.items = items
        self.fail = fail

    async def list(self, tenant_id: str, **_: Any) -> List[Integration]:
        if self.fail:
            raise ConnectionError("database down")
        return list(self.items)


def router(settings: Settings, items: List[Integration], *, fail: bool = False,
           microsoft_connector: Optional[Callable[[Integration], Any]] = None) -> ConnectorRouter:
    registry = ConnectorRegistry(settings, overrides={"webhook": Named("webhook")})

    async def build_microsoft(tenant_id: str, found: Integration, tenant_settings: Any) -> Any:
        if microsoft_connector is not None:
            return microsoft_connector(found)
        return FakeMicrosoftConnector("microsoft", found.id)

    return ConnectorRouter(
        registry, Repos(items, fail=fail),  # type: ignore[arg-type]
        tickets=lambda found: Named("ticketing", found.id), microsoft=build_microsoft,
    )


async def snap(settings: Settings, items: List[Integration], tenant: Optional[Dict[str, Any]] = None,
               **kw: Any) -> RoutingSnapshot:
    return await router(settings, items, **kw).snapshot("tenant-a", tenant if tenant is not None else {"response": {"dry_run": False}})


@pytest.fixture
def live(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(response={"dry_run": False})


async def test_kill_switches_win_everywhere(make_settings: Callable[..., Settings], live: Settings) -> None:
    ms = microsoft()
    forced = await snap(make_settings(), [ms])
    assert forced.route("isolate_host").source == "kill_switch" and forced.dry_run_forced
    pinned = make_action("release_host", "ws-1", connector="microsoft", integration_id=ms.id, rollback_of=uuid.uuid4(),
                         execution_owner="scheduler", status="approved")
    assert isinstance(forced.connector_for(pinned, sample=False), DryRunConnector)
    for flag in (True, "yes", 1):
        tenant = await snap(live, [ms], {"response": {"dry_run": flag}})
        assert tenant.route("isolate_host").source == "tenant_dry_run"
        assert isinstance(tenant.connector_for(pinned, sample=False), DryRunConnector)


async def test_capability_route_and_default(live: Settings) -> None:
    ms = microsoft(live=False)
    snapshot = await snap(live, [ms], {"response": {"dry_run": False, "connector": "webhook"}})
    route = snapshot.route("isolate_host")
    assert (route.connector, route.source, route.capability, route.live) == ("microsoft", "capability", ISO, False)
    action = make_action("isolate_host", "ws-1", status="approved", connector=None)
    connector = snapshot.connector_for(action, sample=False)
    assert connector.name == "microsoft" and connector.integration_id == ms.id  # type: ignore[attr-defined]
    assert snapshot.route("block_ip").source == "default" and snapshot.route("block_ip").connector == "webhook"
    assert set(snapshot.routes()) == set(ACTION_CATALOG)


async def test_disabled_integration_is_not_a_route_but_pins_fail(live: Settings) -> None:
    ms = microsoft(enabled=False)
    snapshot = await snap(live, [ms])
    assert snapshot.route("isolate_host").source == "default"
    pinned = make_action("isolate_host", "ws-1", connector="microsoft", integration_id=ms.id)
    refused = snapshot.connector_for(pinned, sample=False)
    assert isinstance(refused, MisconfiguredConnector) and "disabled" in refused.reason
    assert snapshot.verifier(pinned) is None


async def test_pinned_rows(live: Settings) -> None:
    ms = microsoft()
    snapshot = await snap(live, [ms, integration("jira")])
    executing = make_action("isolate_host", "ws-1", connector="microsoft", integration_id=ms.id)
    assert snapshot.connector_for(executing, sample=False).name == "microsoft"
    deleted = make_action("isolate_host", "ws-1", connector="microsoft", integration_id=None)
    assert "no longer exists" in snapshot.connector_for(deleted, sample=False).reason  # type: ignore[attr-defined]
    replaced = make_action("isolate_host", "ws-1", connector="microsoft", integration_id=uuid.uuid4())
    assert isinstance(snapshot.connector_for(replaced, sample=False), MisconfiguredConnector)
    webhook_rollback = make_action("release_host", "ws-1", connector="webhook", rollback_of=uuid.uuid4(),
                                   execution_owner="scheduler", status="approved")
    assert snapshot.connector_for(webhook_rollback, sample=False).name == "webhook"  # not the capability
    ticket = make_action("create_ticket", "alert:a", connector="ticketing")
    assert snapshot.connector_for(ticket, sample=False).name == "ticketing"
    no_tickets = await snap(live, [ms])
    assert isinstance(no_tickets.connector_for(ticket, sample=False), MisconfiguredConnector)


async def test_samples_never_reach_microsoft_or_ticketing(live: Settings) -> None:
    ms = microsoft()
    snapshot = await snap(live, [ms, integration("servicenow")], {"response": {"dry_run": False, "connector": "webhook"}})
    assert snapshot.route("isolate_host", sample=True).source == "sample"
    assert snapshot.route("create_ticket", sample=True).source == "sample"
    assert snapshot.route("block_ip", sample=True).connector == "webhook"
    pinned = make_action("isolate_host", "ws-1", connector="microsoft", integration_id=ms.id)
    assert isinstance(snapshot.connector_for(pinned, sample=True), DryRunConnector)
    assert snapshot.needs_sample_check([pinned]) and not snapshot.needs_sample_check([make_action("block_ip", "1.2.3.4", status="approved", connector=None)])


async def test_explicit_routes(live: Settings) -> None:
    ms = microsoft()
    routes = {"isolate_host": "webhook", "disable_user": "microsoft", "block_ip": "ticketing", "create_ticket": "dry_run"}
    snapshot = await snap(live, [ms, integration("jira")], {"response": {"dry_run": False, "routes": routes}})
    assert snapshot.route("isolate_host").connector == "webhook"
    assert snapshot.route("create_ticket").connector == "dry_run" and snapshot.route("create_ticket").source == "explicit"
    disabled = snapshot.route("disable_user")
    assert disabled.connector == "microsoft" and "no enabled Microsoft capability" in (disabled.problem or "")
    refused = snapshot.connector_for(make_action("disable_user", "a@b.example", status="approved", connector=None), sample=False)
    assert isinstance(refused, MisconfiguredConnector)
    assert "create_ticket only" in (snapshot.route("block_ip").problem or "")
    no_integration = await snap(live, [], {"response": {"dry_run": False, "routes": {"isolate_host": "microsoft"}}})
    assert no_integration.route("isolate_host").problem == "the tenant has no Microsoft integration"


async def test_ticketing_route(live: Settings) -> None:
    snapshot = await snap(live, [integration("servicenow")])
    assert snapshot.route("create_ticket").connector == "ticketing"
    off = await snap(live, [integration("jira", config={"response_actions": False})])
    assert off.route("create_ticket").source == "default"


async def test_config_and_decryption_problems_never_fall_back(live: Settings) -> None:
    ms = microsoft()
    snapshot = await snap(live, [ms], microsoft_connector=lambda found: MisconfiguredConnector("microsoft", "cannot decrypt"))
    connector = snapshot.connector_for(make_action("isolate_host", "ws-1", status="approved", connector=None), sample=False)
    assert isinstance(connector, MisconfiguredConnector) and connector.reason == "cannot decrypt"
    broken = integration("microsoft", config={**ms.config, "capabilities": {ISO: {"enabled": True, "bogus": 1}}})
    snapshot = await snap(live, [broken])
    route = snapshot.route("isolate_host")
    assert route.connector == "microsoft" and route.problem and "invalid" in route.problem


async def test_database_errors_propagate(live: Settings) -> None:
    with pytest.raises(ConnectionError):
        await snap(live, [], fail=True)


async def test_verifier_ignores_the_dry_run_switches(make_settings: Callable[..., Settings]) -> None:
    ms = microsoft()
    snapshot = await snap(make_settings(), [ms])  # install dry run on
    executed = make_action("isolate_host", "ws-1", connector="microsoft", integration_id=ms.id, status="succeeded")
    assert snapshot.verifier(executed) is not None
    assert snapshot.verifier(make_action("block_ip", "1.2.3.4", connector="webhook")) is None


def test_routes_setting_validation() -> None:
    assert validate_response_settings({"response": {"routes": {"isolate_host": "microsoft"}}})
    for bad in ({"nope": "webhook"}, {"block_ip": "ticketing"}, {"block_ip": "carrier_pigeon"},
                {"block_sender": "microsoft"}):
        with pytest.raises(ResponsePolicyError):
            validate_response_settings({"response": {"routes": bad}})


def test_the_documented_switch_defaults_match_the_routing(live: Settings) -> None:
    from pathlib import Path

    registry = ConnectorRegistry(live, overrides={"webhook": Named("webhook")})
    assert registry.forced_dry_run({}) is False  # an unset tenant switch is off
    assert registry.forced_dry_run({"response": {"dry_run": "yes"}}) is True  # malformed counts as on
    doc = (Path(__file__).resolve().parents[3] / "docs" / "microsoft.md").read_text(encoding="utf-8")
    row = next(line for line in doc.splitlines() if line.startswith("| Tenant kill switch"))
    assert "off when unset" in row and "on until changed" not in row
    assert "an action of a sample alert is always a dry run" not in doc
