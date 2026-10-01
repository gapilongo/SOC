"""Clouds: fixed hosts and token scopes; nothing configurable."""

from __future__ import annotations

import pytest

from lg_sotf.integrations.microsoft.clouds import (
    ALL_CLOUDS,
    CLOUDS,
    DEFENDER_GEOS,
    GLOBAL_ONLY,
    cloud_profile,
    fixed_hosts,
)


def test_cloud_table_is_exactly_the_documented_hosts() -> None:
    table = {name: (p.login_host, p.graph_host, p.graph_scope, p.defender_supported) for name, p in CLOUDS.items()}
    assert table == {
        "global": ("login.microsoftonline.com", "graph.microsoft.com", "https://graph.microsoft.com/.default", True),
        "usgov_gcc_high": ("login.microsoftonline.us", "graph.microsoft.us", "https://graph.microsoft.us/.default", False),
        "usgov_dod": ("login.microsoftonline.us", "dod-graph.microsoft.us", "https://dod-graph.microsoft.us/.default", False),
    }
    assert ALL_CLOUDS == frozenset(CLOUDS) and GLOBAL_ONLY == frozenset({"global"})


def test_defender_hosts_and_scope() -> None:
    profile = CLOUDS["global"]
    # The legacy audience: some MDE APIs refuse tokens for api.security.microsoft.com (403).
    assert profile.defender_scope == "https://api.securitycenter.microsoft.com/.default"
    assert profile.defender_host(None) == "api.security.microsoft.com"
    assert [profile.defender_host(g) for g in DEFENDER_GEOS] == [f"{g}.api.security.microsoft.com" for g in DEFENDER_GEOS]
    with pytest.raises(ValueError):
        profile.defender_host("evil.example.com/")
    with pytest.raises(ValueError):
        CLOUDS["usgov_gcc_high"].defender_host(None)
    with pytest.raises(ValueError):
        CLOUDS["usgov_dod"].scope("defender")
    assert profile.host("graph") == "graph.microsoft.com" and profile.host("defender", "eu") == "eu.api.security.microsoft.com"


def test_token_url_is_tenant_specific() -> None:
    assert CLOUDS["usgov_dod"].token_url("d") == "https://login.microsoftonline.us/d/oauth2/v2.0/token"


def test_unknown_cloud_and_host_list() -> None:
    with pytest.raises(ValueError):
        cloud_profile("china")
    hosts = fixed_hosts()
    assert "graph.microsoft.com" in hosts and "eu.api.security.microsoft.com" in hosts
    assert not any("chinacloudapi" in h or "securitycenter.microsoft.us" in h for h in hosts)
