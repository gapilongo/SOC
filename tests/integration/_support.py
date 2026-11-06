"""Per-worker test services for the parallel integration tier (``pytest -n 4 --dist loadfile``).

Under pytest-xdist every worker process (``PYTEST_XDIST_WORKER=gw<N>``) gets
its own PostgreSQL database, ``<name>_gw<N>`` (created when missing; the role
needs CREATEDB, as the CI role has), and its own Redis database, the base
index plus ``N``. Redis pub/sub ignores database indexes, so every Redis
user in a test is also namespaced by ``unique_prefix``
(:func:`require_unique_prefix`). Without xdist the URLs are used as given.
"""

from __future__ import annotations

import os
import re
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql

from lg_sotf.db.urls import database_name, to_libpq_url
from lg_sotf.settings import Settings

MAX_REDIS_DB = 15


def xdist_worker_index() -> Optional[int]:
    """``N`` for the xdist worker ``gw<N>``; None outside xdist."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    match = re.fullmatch(r"gw(\d+)", worker)
    return int(match.group(1)) if match else None


def worker_database_url(url: str, index: Optional[int]) -> str:
    """``url`` with its database renamed to ``<name>_gw<index>`` (unchanged when ``index`` is None)."""
    if index is None:
        return url
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{database_name(url)}_gw{index}"))


def worker_redis_url(url: str, index: Optional[int]) -> str:
    """``url`` with its database index raised by ``index``; refuses an index above 15."""
    if index is None:
        return url
    parts = urlsplit(url)
    base = int(parts.path.strip("/") or 0)
    db = base + index
    if db > MAX_REDIS_DB:
        pytest.fail(
            f"xdist worker gw{index} would use Redis database {db} (base {base}); Redis has 0-{MAX_REDIS_DB}. "
            "Lower the base index in LG_SOTF_TEST_REDIS_URL or run fewer workers."
        )
    return urlunsplit(parts._replace(path=f"/{db}"))


def ensure_database(base_url: str, url: str) -> None:
    """Create the database of ``url`` (connecting through ``base_url``) when it does not exist yet."""
    name = database_name(url)
    if "test" not in name:
        pytest.fail(f"refusing to create database {name!r}: its name must contain 'test'")
    with psycopg.connect(to_libpq_url(base_url), autocommit=True) as conn:
        if conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone() is None:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))


def require_unique_prefix(settings: Settings, unique_prefix: str) -> Settings:
    """Fail a harness whose Redis keys and pub/sub channels are not namespaced by this test's prefix."""
    if settings.redis.key_prefix != unique_prefix:
        pytest.fail(
            f"redis.key_prefix is {settings.redis.key_prefix!r}, not this test's unique_prefix: "
            "Redis pub/sub ignores database indexes, so parallel workers would see each other's events"
        )
    return settings
