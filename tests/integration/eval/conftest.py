"""Evaluation harness fixtures: the real ingestion service and workflow engine on the test services.

Uses the shared, migrated test database (``LG_SOTF_TEST_DATABASE_URL``), the
test Redis (``LG_SOTF_TEST_REDIS_URL``) and the fake LLM; skipped when either
variable is unset.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable

import pytest
import pytest_asyncio

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.eval.runner import EvalRunner, event_time_settings
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.settings import Settings
from tests.integration.eval._support import EVAL_TENANT


@pytest.fixture
def eval_settings(
    checkpointed_database_url: str, redis_url: str, make_settings: Callable[..., Settings], unique_prefix: str
) -> Settings:
    # Correlation on each alert's own time, as ``lg-sotf eval`` runs (``event_time_settings``).
    return event_time_settings(
        make_settings(
            database={"url": checkpointed_database_url, "pool_min": 1, "pool_max": 6},
            redis={"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            worker={"node_timeout_s": 20.0, "analysis_timeout_s": 20.0, "run_timeout_s": 60.0},
            observability={"log_level": "WARNING"},
        )
    )


@pytest_asyncio.fixture
async def eval_runner(
    eval_settings: Settings, db: Database, repos: Repositories, redis_client: Any
) -> AsyncIterator[EvalRunner]:
    await repos.tenants.create(EVAL_TENANT, "Evaluation")
    ingestion = IngestionService(db, eval_settings)
    engine = await WorkflowEngine.create(
        settings=eval_settings, db=db, redis=redis_client, events=None, checkpoint_pool_size=3
    )
    try:
        yield EvalRunner(
            tenant_id=EVAL_TENANT,
            repos=repos,
            ingestion=ingestion,
            engine=engine,
            run_timeout_s=eval_settings.worker.run_timeout_s,
        )
    finally:
        await engine.close()
        await ingestion.close()
