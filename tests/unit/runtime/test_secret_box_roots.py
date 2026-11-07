"""The worker and scheduler roots build the process's SecretBox once and inject it (D7)."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.agents.registry import AgentSet
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.runtime import scheduler as scheduler_module
from lg_sotf.runtime import worker as worker_module
from lg_sotf.security.crypto import SecretBox, generate_key
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit

INVALID_KEYS = "test-only-not-a-fernet-key"


class Stop(Exception):
    pass


class _NoRedis:
    async def aclose(self) -> None:
        return None


@pytest.fixture
def no_services(monkeypatch: pytest.MonkeyPatch) -> None:
    async def nothing(self: Database) -> None:
        return None

    monkeypatch.setattr(Database, "open", nothing)
    monkeypatch.setattr(Database, "close", nothing)
    monkeypatch.setattr("lg_sotf.queue.redis.create_redis", lambda settings: _NoRedis())


async def _worker_box(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Any:
    seen: Dict[str, Any] = {}

    async def create(**kwargs: Any) -> Any:
        seen.update(kwargs)
        raise Stop

    monkeypatch.setattr(WorkflowEngine, "create", create)
    with pytest.raises(Stop):
        await worker_module.run_worker(settings, metrics_host="127.0.0.1", metrics_port=0)
    return seen["secret_box"]


async def _scheduler_box(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Any:
    seen: Dict[str, Any] = {}

    def build(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        raise Stop

    monkeypatch.setattr(scheduler_module, "Scheduler", build)
    with pytest.raises(Stop):
        await scheduler_module.run_scheduler(settings, metrics_host="127.0.0.1", metrics_port=0)
    return seen["secret_box"]


@pytest.mark.usefixtures("no_services")
async def test_the_worker_injects_the_box_it_built(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isinstance(await _worker_box(make_settings(), monkeypatch), SecretBox)
    assert await _worker_box(make_settings(security={"encryption_keys": None}), monkeypatch) is None


@pytest.mark.usefixtures("no_services")
async def test_the_scheduler_injects_the_box_it_built(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isinstance(await _scheduler_box(make_settings(), monkeypatch), SecretBox)
    assert await _scheduler_box(make_settings(security={"encryption_keys": None}), monkeypatch) is None


async def test_invalid_keys_stop_the_worker_and_scheduler_before_they_connect(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0006: every role refuses to start on invalid encryption keys, as the API does."""
    settings = make_settings(security={"encryption_keys": INVALID_KEYS})
    opened: List[str] = []

    async def record_open(self: Database) -> None:
        opened.append(self._application_name)

    monkeypatch.setattr(Database, "open", record_open)
    monkeypatch.setattr("lg_sotf.queue.redis.create_redis", lambda settings: _NoRedis())
    with pytest.raises(SecurityConfigError, match="not a valid Fernet key"):
        await worker_module.run_worker(settings, metrics_host="127.0.0.1", metrics_port=0)
    with pytest.raises(SecurityConfigError, match="not a valid Fernet key"):
        await scheduler_module.run_scheduler(settings, metrics_host="127.0.0.1", metrics_port=0)
    assert opened == []


def test_the_scheduler_forwards_its_box_to_the_services_it_builds(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    box = SecretBox([generate_key()])
    db = Database(settings.database, application_name="test-only")
    built = scheduler_module.Scheduler(
        settings, db, _NoRedis(), lambda: None, None, None, secret_box=box  # type: ignore[arg-type,return-value]
    )
    assert built.responses().secret_box() is box
    assert built.delivery()._box is box and built.delivery().tickets._box is box


def test_the_workflow_agents_get_the_box(make_settings: Callable[..., Settings]) -> None:
    box = SecretBox([generate_key()])
    agents = AgentSet.build(make_settings(), secret_box=box)
    assert agents.analysis.enrichment.credentials._box is box
