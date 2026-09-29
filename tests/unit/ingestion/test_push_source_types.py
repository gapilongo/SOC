"""The scheduler's due-source query and the ingestion service must agree on which source types are push-only.

Found by the real-process smoke run: a registered ``guardduty`` source (push
only) is returned by ``SourcesRepo.list_due_sources_all_tenants``, so the
scheduler polls it every interval, logs ``scheduler.poll_failed`` with
``SourceNotPullable`` and records the failure as the source's ``last_error``.
"""

from __future__ import annotations

from lg_sotf.db.repos.sources import PUSH_SOURCE_TYPES
from lg_sotf.ingestion.sources import PUSH_ONLY_TYPES


def test_the_scheduler_never_polls_push_only_sources() -> None:
    assert set(PUSH_SOURCE_TYPES) == set(PUSH_ONLY_TYPES)
