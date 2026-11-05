"""The shipped ``configs/*.yaml`` set only keys the code reads.

``agents``, ``routing``, ``tools`` and ``ingestion`` are free-form sections
(``Dict[str, Any]`` in Settings), so a misspelled or obsolete key there is
silently ignored. This test fails on such a key instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set

import pytest
import yaml

from lg_sotf.core.routing import RoutingThresholds
from lg_sotf.ingestion.email.parser import EmailLimits
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.services.escalation import ReviewPolicy

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = sorted((ROOT / "configs").glob("*.yaml"))
AGENTS_SRC = ROOT / "src" / "lg_sotf" / "agents"

# Keys read with raw ``.get`` outside a typed model.
ROUTING_RAW_KEYS = {"triage_llm_min", "triage_llm_max"}  # agents/triage/base.py llm_band
TOOLS_KEYS = {"internal_domains", "cache", "lookup_timeout_s", "virustotal", "abuseipdb", "history"}
# tools/enrichment/service.py (credentials) and providers.py / history.py (provider tuning).
_CREDENTIAL_KEYS = {"enabled", "api_key", "share_with_tenants"}
_HTTP_PROVIDER_KEYS = {"base_url", "requests_per_minute", "cache_ttl_s", "ca_bundle", "timeout_s"}
PROVIDER_KEYS = {
    "virustotal": _CREDENTIAL_KEYS | _HTTP_PROVIDER_KEYS | {"malicious_threshold"},
    "abuseipdb": _CREDENTIAL_KEYS
    | _HTTP_PROVIDER_KEYS
    | {"max_age_days", "malicious_threshold", "suspicious_threshold"},
    "history": {"enabled", "lookback_days", "max_alerts", "cache_ttl_s"},
}
_GET_CONFIG = re.compile(r"""get_config\(\s*["'](\w+)["']""")


def _agent_keys(name: str) -> Set[str]:
    """Keys an agent reads through ``BaseAgent.get_config``, scanned from its package."""
    return {m for path in (AGENTS_SRC / name).rglob("*.py") for m in _GET_CONFIG.findall(path.read_text())}


def _load(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict), path
    return data


def _unknown(section: Any, allowed: Set[str], where: str) -> List[str]:
    if not isinstance(section, Mapping):
        return []
    return [f"{where}.{key}" for key in section if key not in allowed]


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_free_form_sections_use_only_keys_the_code_reads(path: Path) -> None:
    data = _load(path)
    problems: List[str] = []

    agents = data.get("agents") or {}
    readers = {"triage", "correlation", "analysis"}
    problems += _unknown(agents, readers | {"human_loop"}, "agents")
    for name in readers & set(agents):
        problems += _unknown(agents[name], _agent_keys(name), f"agents.{name}")
    problems += _unknown(agents.get("human_loop"), set(ReviewPolicy.model_fields), "agents.human_loop")

    problems += _unknown(data.get("routing"), set(RoutingThresholds.model_fields) | ROUTING_RAW_KEYS, "routing")

    tools = data.get("tools") or {}
    problems += _unknown(tools, TOOLS_KEYS, "tools")
    for provider, keys in PROVIDER_KEYS.items():
        problems += _unknown(tools.get(provider), keys, f"tools.{provider}")

    ingestion = data.get("ingestion") or {}
    problems += _unknown(ingestion, set(IngestionOptions.model_fields) | {"email"}, "ingestion")
    problems += _unknown(ingestion.get("email"), set(EmailLimits.model_fields), "ingestion.email")

    assert problems == [], f"{path.name} sets keys nothing reads: {problems}"


def test_agent_key_scan_finds_the_known_readers() -> None:
    # Guards the regex: if get_config's call shape changes, the scan must not silently find nothing.
    assert {"enable_llm_scoring", "llm_weight"} <= _agent_keys("triage")
    assert {"correlation_window_minutes", "burst_threshold", "max_correlations"} <= _agent_keys("correlation")
    assert {"max_iterations", "enable_llm_reasoning"} <= _agent_keys("analysis")
