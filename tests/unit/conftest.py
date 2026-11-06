"""Unit tier: every warning is an error (roadmap G9), and no test reaches a real service.

The ini ``filterwarnings`` makes RuntimeWarning, ResourceWarning and unraisable
exceptions errors for the whole suite. The unit tier is hermetic and under our
control, so here any warning fails the test that raised it; there is no
ignore-list. A warning that a dependency starts emitting is fixed at its
source (or by pinning the dependency), not filtered.

A unit test that requests a real-service fixture (``SERVICE_FIXTURES`` in
``_support.py``) fails collection: the fast CI job has no PostgreSQL or
Redis, so the test would never run there. Such a test belongs in
tests/integration.
"""

from __future__ import annotations

from typing import List

import pytest

from tests.unit._support import UNIT_ROOT, service_fixture_offenders


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    offenders = service_fixture_offenders(items)
    if offenders:
        raise pytest.UsageError(
            "unit tests must not request the real-service fixtures; move them to tests/integration:\n  "
            + "\n  ".join(offenders)
        )
    # The hook sees every collected item, not only this directory's.
    for item in items:
        if item.path.is_relative_to(UNIT_ROOT):
            # Prepended: an explicit filterwarnings mark on a test, class or module still takes precedence.
            item.add_marker(pytest.mark.filterwarnings("error"), append=False)
