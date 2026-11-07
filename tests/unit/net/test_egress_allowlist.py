"""The install's egress allow-list (``ingestion.allowed_destination_hosts``) and read-only sources (PoV profile)."""

from __future__ import annotations

from typing import Callable

import pytest

from lg_sotf.errors import SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import CONNECTORS
from lg_sotf.integrations.http import IntegrationHttp
from lg_sotf.integrations.microsoft.http import MicrosoftHttpFactory
from lg_sotf.llm.endpoint import base_url_problem, resolve_base_url
from lg_sotf.llm.errors import LLMUnavailable
from lg_sotf.net.egress import DestinationPolicy, DestinationRefused, allowed_hosts, egress_policy, host_on_list
from lg_sotf.services.connectors.registry import ConnectorRegistry
from lg_sotf.settings import IngestionSection, Settings
from lg_sotf.tools.enrichment.service import EnrichmentService
from tests.unit.ingestion._support import MapResolver, make_source

LISTED = DestinationPolicy(require_https=True, allowed_hosts=frozenset({"wazuh.prospect.example", "*.siem.example"}))


def test_only_listed_hosts_and_subdomains_pass() -> None:
    assert LISTED.check_url("https://wazuh.prospect.example:9200") == ("wazuh.prospect.example", 9200)
    assert LISTED.check_url("https://WAZUH.Prospect.Example./x")[0] == "wazuh.prospect.example."
    assert LISTED.check_url("https://a.b.siem.example")[0] == "a.b.siem.example"
    for url in ("https://siem.example", "https://evil.example.com", "https://wazuh.prospect.example.evil.test",
                "https://93.184.216.34"):
        with pytest.raises(DestinationRefused):
            LISTED.check_url(url)
    assert DestinationPolicy(require_https=True).host_allowed("anything.example")
    assert not DestinationPolicy(require_https=True, allowed_hosts=frozenset()).host_allowed("wazuh.prospect.example")
    assert host_on_list("[2001:db8::1]", frozenset({"2001:db8::1"}))


async def test_resolved_connections_are_checked_too() -> None:
    # The IMAP source connects with resolve_allowed only (no URL); the list applies there as well.
    resolver = MapResolver({})
    assert await LISTED.resolve_allowed("wazuh.prospect.example", 993, resolver)
    with pytest.raises(DestinationRefused):
        await LISTED.resolve_allowed("mail.evil.example", 993, resolver)
    assert resolver.lookups == ["wazuh.prospect.example"]


def test_the_setting_accepts_a_list_or_an_env_string() -> None:
    assert IngestionSection().allowed_destination_hosts is None
    section = IngestionSection.model_validate({"allowed_destination_hosts": " Wazuh.Prospect.Example., ollama  *.eu.example"})
    assert section.allowed_destination_hosts == ["wazuh.prospect.example", "ollama", "*.eu.example"]
    assert IngestionSection.model_validate({"allowed_destination_hosts": []}).allowed_destination_hosts == []
    for bad in (["https://wazuh.example"], ["wazuh.example:9200"], ["*"], ["a/b"]):
        with pytest.raises(ValueError, match="allowed_destination_hosts"):
            IngestionSection.model_validate({"allowed_destination_hosts": bad})


def test_egress_policy_reads_the_list_and_fails_closed(make_settings: Callable[..., Settings]) -> None:
    assert egress_policy(make_settings()).allowed_hosts is None
    listed = make_settings(ingestion={"allowed_destination_hosts": "wazuh.prospect.example"})
    assert egress_policy(listed).allowed_hosts == frozenset({"wazuh.prospect.example"})
    # An unrelated invalid key does not drop the list; an invalid list refuses everything.
    unrelated = make_settings(ingestion={"allowed_destination_hosts": ["wazuh.prospect.example"], "batch_size": 0})
    assert egress_policy(unrelated).allowed_hosts == frozenset({"wazuh.prospect.example"})
    assert allowed_hosts(make_settings(ingestion={"allowed_destination_hosts": ["http://x"]})) == frozenset()
    assert allowed_hosts(make_settings(ingestion={"allowed_destination_hosts": 7})) == frozenset()
    # Every outbound client of a tenant-controlled destination carries it.
    assert IntegrationHttp(listed).policy.allowed_hosts == frozenset({"wazuh.prospect.example"})
    assert ConnectorRegistry(listed)._policy.allowed_hosts == frozenset({"wazuh.prospect.example"})
    assert MicrosoftHttpFactory(listed)._policy.allowed_hosts == frozenset({"wazuh.prospect.example"})


def test_pull_sources_use_the_list(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(ingestion={"allowed_destination_hosts": ["wazuh.prospect.example"]})
    options = IngestionOptions.from_settings(settings)
    listed = make_source("splunk", {"base_url": "https://wazuh.prospect.example:8089"})
    connector = CONNECTORS["splunk"](listed, {"token": "test-only-token"}, settings=settings, options=options)
    assert connector.policy.allowed_hosts == frozenset({"wazuh.prospect.example"})
    other = make_source("splunk", {"base_url": "https://splunk.other.example:8089"})
    with pytest.raises(DestinationRefused):
        CONNECTORS["splunk"](other, {"token": "test-only-token"}, settings=settings, options=options)


def test_the_llm_endpoint_must_be_on_the_list(make_settings: Callable[..., Settings]) -> None:
    def llm(provider: str, base_url: str | None = None, hosts: object = ("ollama", "api.mistral.ai")) -> Settings:
        return make_settings(llm={"provider": provider, "base_url": base_url, "api_key": "test-only-key"},
                             ingestion={"allowed_destination_hosts": hosts})

    assert resolve_base_url(llm("ollama")) == "http://ollama:11434/v1"
    assert resolve_base_url(llm("openai_compatible", "https://api.mistral.ai/v1")) == "https://api.mistral.ai/v1"
    for refused in (llm("openai_compatible", "https://api.deepseek.com/v1"), llm("anthropic"), llm("openai"),
                    llm("gemini"), llm("ollama", hosts=["http://bad"])):
        with pytest.raises(LLMUnavailable, match="allowed_destination_hosts"):
            resolve_base_url(refused)
        assert base_url_problem(refused) is not None
    assert resolve_base_url(llm("anthropic", hosts=["api.anthropic.com"])) is None
    assert resolve_base_url(make_settings(llm={"provider": "anthropic", "api_key": "test-only-key"})) is None


def test_enrichment_providers_off_the_list_are_left_out(make_settings: Callable[..., Settings]) -> None:
    assert {"virustotal", "abuseipdb", "history"} <= set(EnrichmentService.from_settings(make_settings()).provider_names)
    listed = make_settings(ingestion={"allowed_destination_hosts": ["www.virustotal.com", "wazuh.prospect.example"]})
    assert EnrichmentService.from_settings(listed).provider_names == ["virustotal", "history"]
    nothing = make_settings(ingestion={"allowed_destination_hosts": ["wazuh.prospect.example"]})
    assert EnrichmentService.from_settings(nothing).provider_names == ["history"]


def test_read_only_installs_refuse_sources_that_write_back(make_settings: Callable[..., Settings]) -> None:
    assert {t for t, c in CONNECTORS.items() if c.writes_back} == {"m365_mailbox", "imap"}
    settings = make_settings(ingestion={"read_only_sources": "true"})
    options = IngestionOptions.from_settings(settings)
    for source_type in ("m365_mailbox", "imap"):
        with pytest.raises(SourceConfigError, match="read_only_sources"):
            CONNECTORS[source_type](make_source(source_type), {}, settings=settings, options=options)
    source = make_source("splunk", {"base_url": "https://splunk.example:8089"})
    assert CONNECTORS["splunk"](source, {"token": "test-only-token"}, settings=settings, options=options)
