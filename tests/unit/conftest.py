"""Unit tier: every warning is an error (roadmap G9).

The ini ``filterwarnings`` makes RuntimeWarning, ResourceWarning and unraisable
exceptions errors for the whole suite. The unit tier is hermetic and under our
control, so here any warning fails the test that raised it; there is no
ignore-list. A warning that a dependency starts emitting is fixed at its
source (or by pinning the dependency), not filtered.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

_UNIT = Path(__file__).parent


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    # The hook sees every collected item, not only this directory's.
    for item in items:
        if item.path.is_relative_to(_UNIT):
            # Prepended: an explicit filterwarnings mark on a test, class or module still takes precedence.
            item.add_marker(pytest.mark.filterwarnings("error"), append=False)
