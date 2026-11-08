"""corpus_v1 through a real Wazuh 4.14 indexer and the real connector (AI-E1.8).

The generated alerts are indexed with the template Wazuh publishes for 4.14,
read back by the production Wazuh connector as the least-privilege reader
(time-ordered ``search_after`` pages of two), and the dataset is rebuilt from
what the connector returned. It must be the committed ``corpus_v1`` byte for
byte: the mapping accepts every document, the connector drops, reorders and
alters nothing, and every alert normalises.

Skipped unless ``LG_SOTF_TEST_WAZUH_ADDRESS`` is set (``make test-wazuh``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

import pytest

from lg_sotf.eval.dataset import load_dataset
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.ingestion.normalizers.wazuh import WazuhNormalizer
from lg_sotf.ingestion.sources import PullConnector
from tests.fixtures.attack_corpus import build_corpus, dataset_text, sha256_text
from tests.fixtures.wazuh_lab import WazuhLab
from tests.live.wazuh._support import SKIP_REASON, collect, lab_address

pytestmark = [pytest.mark.live, pytest.mark.skipif(lab_address() is None, reason=SKIP_REASON)]

COMMITTED = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "corpus_v1.jsonl.gz"


async def test_corpus_v1_round_trips_through_the_indexer_and_the_real_connector(
    wazuh: Callable[..., PullConnector], lab_admin: WazuhLab, alert_index: str
) -> None:
    corpus = build_corpus()
    indexed, rejected = lab_admin.load(corpus.alerts, alert_index)
    assert (indexed, rejected) == (len(corpus.alerts), [])

    pages, error = await collect(wazuh(), {"v": 1, "since": "2026-10-18T00:00:00Z"})
    assert error is None
    events = [event for page in pages for event in page.events]
    assert [e["id"] for e in events] == [a["id"] for a in corpus.alerts]
    assert events == corpus.alerts

    rebuilt = dataset_text(events, corpus.labels)
    assert sha256_text(rebuilt) == load_dataset(COMMITTED).sha256
    normalizer = WazuhNormalizer()
    ctx = NormalizeContext(source_id="src-1", source_type="wazuh", now=datetime(2026, 11, 2, tzinfo=UTC))
    assert all(normalizer.normalize(event, ctx).title for event in events)
