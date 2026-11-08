"""INV-09 (pending): shadow mode causes no side effects.

Shadow mode does not exist yet; AI-E1.5a adds it with the test that enumerates
every egress and proves each one is sunk in shadow. Until then this skipped
placeholder keeps the gap visible in every test run. When AI-E1.5a lands,
replace this module's test with a pointer to that test in INV-09's proofs and
mark INV-09 ``enforced`` (src/lg_sotf/invariants/registry.py).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


@pytest.mark.skip(reason="pending AI-E1.5a: shadow mode is not implemented yet")
def test_shadow_mode_has_no_side_effects() -> None:
    raise AssertionError("unreachable until AI-E1.5a")
