"""Helpers for the Wazuh live contract tests (tests/live/wazuh)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from lg_sotf.ingestion.sources import FetchedPage, PullConnector
from tests.fixtures.wazuh_lab import DEMO_HOSTNAME

ADDRESS_ENV = "LG_SOTF_TEST_WAZUH_ADDRESS"
CA_ENV = "LG_SOTF_TEST_WAZUH_CA"
SKIP_REASON = f"no Wazuh lab ({ADDRESS_ENV} unset; `make test-wazuh-up`, docs/testing.md)"

# The sample alerts (tests/fixtures/wazuh_lab/alerts_4_14.json) were raised on 2026-11-02 between 09:00 and 09:25.
NOW = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
BEFORE_SAMPLES = "2026-11-02T08:00:00Z"
AFTER_SAMPLES = "2026-11-02T09:30:00Z"


def lab_address() -> Optional[str]:
    return os.environ.get(ADDRESS_ENV) or None


@dataclass(frozen=True)
class Lab:
    """Where the lab indexer is: its container address (the connector is pinned there) and its CA."""

    address: str
    ca_file: str

    @property
    def admin_url(self) -> str:
        return f"https://{self.address}:9200"

    @property
    def base_url(self) -> str:
        # The demo certificate names only demo.indexer; the connector resolves it to the lab address.
        return f"https://{DEMO_HOSTNAME}:9200"

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        assert host == DEMO_HOSTNAME, host
        return [self.address]


async def collect(
    connector: PullConnector, cursor: Optional[Dict[str, Any]] = None, *, max_pages: Optional[int] = None
) -> Tuple[List[FetchedPage], Optional[BaseException]]:
    """The pages ``connector`` yields from ``cursor`` (at most ``max_pages``), and the error that ended them."""
    pages: List[FetchedPage] = []
    stream = connector.pages(cursor)
    try:
        async for page in stream:
            pages.append(page)
            if max_pages is not None and len(pages) >= max_pages:
                break
    except Exception as exc:  # noqa: BLE001 - the test inspects what was yielded before the failure
        return pages, exc
    finally:
        await stream.aclose()
        await connector.aclose()
    return pages, None


def event_ids(pages: Sequence[FetchedPage]) -> List[Optional[str]]:
    return [event.get("id") for page in pages for event in page.events]
