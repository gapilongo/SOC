"""Invariant tier: proofs of safety invariants that had no test elsewhere (SEC9.1).

Each test here is named by an invariant in ``src/lg_sotf/invariants/registry.py``
(``tests/deploy/test_invariants.py`` fails on an orphan). Like the unit tier it is
hermetic and runs in the fast CI job, and every warning is an error.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

INVARIANTS_ROOT = Path(__file__).resolve().parent


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    # The hook sees every collected item, not only this directory's.
    for item in items:
        if item.path.is_relative_to(INVARIANTS_ROOT):
            item.add_marker(pytest.mark.filterwarnings("error"), append=False)
