"""The proof-of-value (PoV) profile refuses response execution, by policy (GTM3.2 acceptance test).

The settings are read from the shipped profile files themselves (the compose
overlay ``docker/docker-compose.pov.yml`` and the Helm ``values-pov.yaml``), so
loosening a profile file fails here. A tenant admin who turns every tenant-level
knob towards execution (autonomy ``auto``, ``dry_run: false``, a webhook
connector and routes) still gets nothing executed: every attempted execution is
blocked or recorded ``dry_run``, and the response connector is never called.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List
from uuid import UUID

import pytest
import yaml

from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.llm.endpoint import resolve_base_url
from lg_sotf.llm.errors import LLMUnavailable
from lg_sotf.net.egress import DestinationRefused, egress_policy
from lg_sotf.services.connectors import ConnectorResult
from lg_sotf.services.response import PlanContext, ResponsePolicy, ResponseService, approval_allowed
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeRepos, FakeTenants

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker" / "docker-compose.pov.yml"
HELM = REPO / "deploy" / "helm" / "lg-sotf" / "values-pov.yaml"
HOSTS = "wazuh.prospect.example,ollama"
SECURITY = {
    "encryption_keys": "bGctc290Zi10ZXN0LXN1aXRlLW9ubHkta2V5LTAwMDA=",
    "indicator_hmac_key": "lg-sotf-test-suite-only-indicator-hmac-key",
}
# Everything a tenant admin can set to try to make actions run.
LOOSENED: Dict[str, Any] = {
    "autonomy": {"low": "auto", "medium": "auto", "high": "auto", "critical": "auto"},
    "response": {"dry_run": False, "connector": "webhook", "routes": {"block_ip": "webhook", "isolate_host": "webhook"}},
}


class Recording:
    """The response connector a PoV must never reach."""

    name = "webhook"

    def __init__(self) -> None:
        self.calls: List[str] = []

    async def execute(self, action: Any) -> ConnectorResult:
        self.calls.append(str(action.id))
        return ConnectorResult("succeeded")


def plan_ctx(title: str) -> PlanContext:
    entities = {"ip": ["185.220.101.44"], "host": ["ws-042"], "user": ["jdoe"],
                "hash": ["44d88612fea8a8f36de82e1278abb02f"]}
    return PlanContext(severity="high", evidence="rules", title=title, entities=entities)


def _interpolate(value: str) -> str:
    variables = {"POV_EGRESS_HOSTS": HOSTS, "POV_ALLOW_PRIVATE": "false"}
    return re.sub(r"\$\{(\w+)(?::[-?][^}]*)?\}", lambda m: variables[m.group(1)], value)


@pytest.fixture(params=["compose", "helm"])
def pov(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Settings:
    if request.param == "compose":
        overlay = yaml.safe_load(COMPOSE.read_text())
        env = overlay["x-pov-environment"]
        for service in ("migrate", "api", "worker", "scheduler"):
            assert overlay["services"][service]["environment"] == env, service
        for key, value in env.items():
            monkeypatch.setenv(key, _interpolate(str(value)))
        return Settings(_env_file=None, environment="test", security=SECURITY)
    values = yaml.safe_load(HELM.read_text())["settings"]
    assert values["ingestion"]["allowed_destination_hosts"] == []  # fail closed until the operator fills it
    values["ingestion"]["allowed_destination_hosts"] = HOSTS.split(",")
    return Settings(_env_file=None, environment="test", security=SECURITY, **values)


async def test_pov_profile_blocks_every_response_execution(pov: Settings) -> None:
    assert pov.response.dry_run is True
    assert set(pov.response.default_autonomy.values()) == {"disabled"} and len(pov.response.default_autonomy) == 4
    assert not pov.response.webhook_url

    # The tenant as installed: every proposed action is blocked, none can be approved.
    webhook = Recording()
    repos = FakeRepos()
    service = ResponseService(repos, pov, None, connectors={"webhook": webhook})  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx("Cobalt Strike beacon"))
    assert plan.auto == [] and plan.awaiting == [] and plan.blocked
    assert {r.blocked_reason for r in repos.actions.rows.values()} <= {"autonomy_disabled", "non_public_ip", "unroutable_ip"}
    policy = ResponsePolicy.resolve({}, pov)
    assert not any(approval_allowed(risk, "admin", mode) for risk, mode in policy.autonomy.items())
    assert set((await service.execute("t1", "a1", plan.blocked)).values()) == {"blocked"}

    # A tenant admin loosens everything and an action is forced to approved: still never executed.
    repos = FakeRepos(tenants=FakeTenants(LOOSENED))
    service = ResponseService(repos, pov, None, connectors={"webhook": webhook})  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx("malware"))
    forced, _ = await repos.actions.propose("t1", "a1", "isolate_host", "ws-7", "high", status="approved")
    attempted = [*plan.auto, str(forced.id)]
    assert plan.auto
    result = await service.execute("t1", "a1", attempted)
    assert set(result.values()) == {"dry_run"}, result
    assert all(repos.actions.rows[UUID(i)].connector == "dry_run" for i in attempted)
    assert webhook.calls == []
    assert service.connector_for("t1", LOOSENED["response"]).name == "dry_run"


def test_pov_profile_restricts_egress_and_sources(pov: Settings) -> None:
    policy = egress_policy(pov)
    assert policy.check_url("https://wazuh.prospect.example:9200")[0] == "wazuh.prospect.example"
    with pytest.raises(DestinationRefused):
        policy.check_url("https://hooks.example.com/soar")
    deepseek = pov.model_copy(update={"llm": pov.llm.model_copy(
        update={"provider": "openai_compatible", "base_url": "https://api.deepseek.com/v1"})})
    with pytest.raises(LLMUnavailable, match="allowed_destination_hosts"):
        resolve_base_url(deepseek)
    local = pov.model_copy(update={"llm": pov.llm.model_copy(update={"provider": "ollama", "base_url": None})})
    assert resolve_base_url(local) == "http://ollama:11434/v1"
    assert IngestionOptions.from_settings(pov).read_only_sources is True
    assert pov.integrations.enabled is False and pov.llm.allow_fake is False
