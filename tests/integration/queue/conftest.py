"""Queue tests use the shared ``redis_url``/``redis_client`` fixtures (tests/integration/conftest.py)."""

from __future__ import annotations

from typing import Any, Callable

import pytest

from lg_sotf.settings import Settings


@pytest.fixture
def queue_settings(
    make_settings: Callable[..., Settings], redis_url: str, unique_prefix: str
) -> Callable[..., Settings]:
    def build(**worker: Any) -> Settings:
        return make_settings(
            redis={"url": redis_url, "key_prefix": unique_prefix, "socket_timeout_s": 5.0},
            worker={"visibility_timeout_s": 60, "block_ms": 100, "max_deliveries": 3, **worker},
        )

    return build
