"""INV-13 (pending): autonomy is earned per skill and tenant and lost on any miss (ADR-0014 section 6.3).

The invariant is registered now so that its number matches the ADR; AI-E3.10 builds the promotion and
demotion path and replaces this placeholder with the proof.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(reason="INV-13 is pending: AI-E3.10 delivers the earned-autonomy path and this proof")
def test_autonomy_is_earned_per_skill_and_lost_on_a_miss() -> None:
    raise AssertionError("placeholder: AI-E3.10 writes this proof")
