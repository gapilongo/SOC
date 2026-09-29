"""Fixtures for deployment packaging tests (Dockerfile, compose, Helm, scripts).

These tests read files and, when the binaries exist, run ``helm template`` and
``docker compose config``; they need no cluster, daemon or network.
"""

from __future__ import annotations

from typing import List

import pytest

from tests.deploy._support import FULL_VALUES, Manifest, helm_binary, render


@pytest.fixture(scope="session")
def default_manifests() -> List[Manifest]:
    if helm_binary() is None:
        pytest.skip("helm is not installed")
    return render()


@pytest.fixture(scope="session")
def full_manifests() -> List[Manifest]:
    if helm_binary() is None:
        pytest.skip("helm is not installed")
    return render("-f", str(FULL_VALUES))
