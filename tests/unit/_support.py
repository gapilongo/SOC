"""Helpers for the unit tier's own collection rules (tests/unit/conftest.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Sequence

UNIT_ROOT = Path(__file__).resolve().parent
SERVICE_FIXTURES = frozenset({"db", "repos", "redis_client", "redis_url", "database_url", "migrated_database_url"})


def service_fixture_offenders(items: Sequence[Any]) -> List[str]:
    """``nodeid: fixtures`` for every unit-tier item (a ``pytest.Item``) that requests a real-service fixture."""
    offenders = []
    for item in items:
        if not Path(item.path).is_relative_to(UNIT_ROOT):
            continue
        requested = SERVICE_FIXTURES.intersection(getattr(item, "fixturenames", ()))
        if requested:
            offenders.append(f"{item.nodeid}: {', '.join(sorted(requested))}")
    return offenders
