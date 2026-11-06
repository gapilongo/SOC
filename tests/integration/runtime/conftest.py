"""Runtime tests use the shared Postgres/Redis fixtures from tests/integration/conftest.py.

Helpers (the scripted engine, worker builders, ``eventually``) live in ``_support.py``.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

import pytest

from lg_sotf.settings import Settings


@pytest.fixture
def runtime_settings(
    make_settings: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> Callable[..., Settings]:
    def build(worker: Optional[Dict[str, Any]] = None, scheduler: Optional[Dict[str, Any]] = None) -> Settings:
        return make_settings(
            database={"url": migrated_database_url, "pool_min": 1, "pool_max": 8},
            redis={"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            worker={
                "concurrency": 4,
                "per_tenant_concurrency": 4,
                "visibility_timeout_s": 60,
                "block_ms": 100,
                "max_deliveries": 3,
                "run_timeout_s": 10.0,
                "drain_timeout_s": 5.0,
                **(worker or {}),
            },
            scheduler={"tick_s": 0.1, **(scheduler or {})},
        )

    return build
