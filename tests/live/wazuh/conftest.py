"""Fixtures for the Wazuh live contract tests: the lab, a reader user, a per-test alert index.

Every test gets its own ``wazuh-alerts-4.x-lgsotf-<hex>`` index, which the
lab's ``wazuh`` template maps exactly as a real 4.14 alert index, so extra
alerts loaded into the lab (``python -m tests.fixtures.wazuh_lab load``)
never change what a test sees.
"""

from __future__ import annotations

import os
import secrets
import uuid
from typing import Any, Callable, Dict, Iterator, Optional

import pytest

from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import ConnectorDeps, PullConnector, create_connector
from lg_sotf.settings import Settings
from tests.fixtures.wazuh_lab import INDEX_PREFIX, WazuhLab
from tests.live.wazuh._support import CA_ENV, NOW, Lab, lab_address
from tests.unit.ingestion._support import make_source

Credentials = Dict[str, str]


def lab_password() -> str:
    # Built at run time: a fresh lab user per session, never a committed value.
    return f"test-only-{secrets.token_hex(12)}-Lab9!"


@pytest.fixture(scope="session")
def lab() -> Lab:
    address = lab_address()
    if address is None:
        pytest.skip("no Wazuh lab")
    ca_file = os.environ.get(CA_ENV)
    if not ca_file or not os.path.isfile(ca_file):
        pytest.fail(f"{CA_ENV} must name the lab's root CA (make test-wazuh-up copies it to build/wazuh-lab)")
    return Lab(address, ca_file)


@pytest.fixture(scope="session")
def lab_admin(lab: Lab) -> Iterator[WazuhLab]:
    with WazuhLab(lab.admin_url, ca_file=lab.ca_file) as admin:
        admin.wait_ready(timeout_s=30)
        if not admin.has_template():
            pytest.fail("the lab has no wazuh template; run `make test-wazuh-up` (it seeds the lab)")
        yield admin


def _user(lab_admin: WazuhLab, kind: str, reader: bool) -> Iterator[Credentials]:
    username = f"lgsotf-{kind}-{uuid.uuid4().hex[:8]}"
    password = lab_password()
    if reader:
        lab_admin.put_reader(username, password)
    else:
        lab_admin.put_user(username, password)
    yield {"username": username, "password": password}
    lab_admin.delete_user(username)


@pytest.fixture(scope="session")
def reader(lab_admin: WazuhLab) -> Iterator[Credentials]:
    """May search ``wazuh-alerts-*`` and nothing else."""
    yield from _user(lab_admin, "reader", reader=True)


@pytest.fixture(scope="session")
def no_access_user(lab_admin: WazuhLab) -> Iterator[Credentials]:
    """Authenticates, but holds no role."""
    yield from _user(lab_admin, "norole", reader=False)


@pytest.fixture
def alert_index(lab_admin: WazuhLab) -> Iterator[str]:
    index = f"{INDEX_PREFIX}lgsotf-{uuid.uuid4().hex[:12]}"
    yield index
    lab_admin.delete_index(index)


@pytest.fixture
def lab_settings(make_settings: Callable[..., Settings]) -> Settings:
    # Pages of 2, no overlap, private destinations allowed: the lab sits on a Docker bridge network.
    return make_settings(
        ingestion={"page_size": 2, "overlap_s": 0, "allow_private_destinations": True, "http_max_retries": 1}
    )


@pytest.fixture
def wazuh(lab: Lab, lab_settings: Settings, reader: Credentials, alert_index: str) -> Callable[..., PullConnector]:
    """``wazuh(**config)`` builds the real connector for the lab: real HTTP, TLS verified against the lab CA,
    pinned to the lab address by the egress policy; reads ``alert_index`` as ``reader`` unless overridden."""
    with open(lab.ca_file, encoding="utf-8") as fh:
        ca_pem = fh.read()

    def build(credentials: Optional[Credentials] = None, **config: Any) -> PullConnector:
        source_config = {
            "base_url": lab.base_url,
            "ca_cert_pem": ca_pem,
            "index": alert_index,
            "max_event_lag_s": 0,
            **config,
        }
        deps = ConnectorDeps(resolver=lab.resolve, now=lambda: NOW)
        return create_connector(
            make_source("wazuh", source_config),
            credentials or reader,
            settings=lab_settings,
            options=IngestionOptions.from_settings(lab_settings),
            deps=deps,
        )

    return build
