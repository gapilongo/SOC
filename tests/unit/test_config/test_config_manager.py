"""ConfigManager keeps the legacy dotted-key API on top of typed Settings."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Callable

import pytest
from pydantic import SecretStr

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import ConfigError
from lg_sotf.llm.errors import LLMUnavailable
from lg_sotf.llm.fake import FakeChatModel
from lg_sotf.settings import (
    DatabaseSettings,
    LLMSettings,
    ObservabilitySettings,
    RedisSettings,
    SecuritySettings,
    Settings,
    get_settings,
)
from lg_sotf.utils.llm import get_llm_client

REPO_ROOT = Path(__file__).resolve().parents[3]
DEV_CONFIG = str(REPO_ROOT / "configs" / "development.yaml")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("LG_SOTF_CONFIG_FILE", "LG_SOTF_ENVIRONMENT", "LG_SOTF_ENV", "LG_SOTF_LLM__PROVIDER", "ANTHROPIC_API_KEY",
                "LG_SOTF_LLM__API_KEY", "DATABASE_URL", "REDIS_URL"):
        monkeypatch.delenv(var, raising=False)


def test_dotted_get_over_free_form_sections() -> None:
    cm = ConfigManager(DEV_CONFIG)
    assert cm.get("routing.analysis_threshold") == 40
    assert cm.get("agents.triage.llm_weight") == 0.4
    assert cm.get("agents.correlation.burst_threshold") == 5
    assert cm.get("tools.virustotal.timeout_s") == 10
    assert cm.get("llm.fast.model") == "claude-haiku-4-5"
    assert cm.get("worker.concurrency") == 4


def test_missing_keys_return_default() -> None:
    cm = ConfigManager(DEV_CONFIG)
    assert cm.get("workflow.enable_llm_routing", True) is True
    assert cm.get("monitoring", {}) == {}
    assert cm.get("routing.analysis_threshold.deeper", "d") == "d"
    assert cm.get("agents.unknown") is None
    assert not cm.has("agents.unknown")
    assert cm.has("routing.response_threshold")


def test_empty_key_rejected() -> None:
    with pytest.raises(ConfigError):
        ConfigManager(DEV_CONFIG).get("")


def test_returned_containers_are_copies() -> None:
    cm = ConfigManager(DEV_CONFIG)
    triage = cm.get_agent_config("triage")
    triage["llm_weight"] = 1
    triage.setdefault("injected", True)
    assert cm.get("agents.triage.llm_weight") == 0.4
    assert "injected" not in cm.get_agent_config("triage")


def test_agent_and_tool_config() -> None:
    cm = ConfigManager(DEV_CONFIG)
    assert cm.get_agent_config("analysis")["max_iterations"] == 5
    assert cm.get_agent_config("nope") == {}
    assert cm.get_tool_config("virustotal")["timeout_s"] == 10
    assert cm.get_tool_config("virustotal")["requests_per_minute"] == 4
    assert cm.get_tool_config("virustotal.timeout_s") == {}


def test_typed_section_getters() -> None:
    cm = ConfigManager(DEV_CONFIG)
    assert isinstance(cm.get_database_config(), DatabaseSettings)
    assert isinstance(cm.get_redis_config(), RedisSettings)
    assert isinstance(cm.get_llm_config(), LLMSettings)
    assert isinstance(cm.get_security_config(), SecuritySettings)
    assert isinstance(cm.get_logging_config(), ObservabilitySettings)
    assert cm.get_llm_config().deep.model == "claude-opus-5-5"


def test_secrets_stay_wrapped() -> None:
    cm = ConfigManager(DEV_CONFIG)
    secret = cm.get("auth.jwt_secret")
    assert isinstance(secret, SecretStr)
    assert "development" not in repr(secret)


def test_default_instance_wraps_process_settings() -> None:
    assert ConfigManager().settings is get_settings()


def test_environment_overrides_yaml(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_SOTF_ROUTING__ANALYSIS_THRESHOLD", "55")
    monkeypatch.setenv("LG_SOTF_AGENTS__TRIAGE__CONFIDENCE_THRESHOLD", "81")
    cm = ConfigManager(DEV_CONFIG)
    assert int(cm.get("routing.analysis_threshold")) == 55
    assert int(cm.get("agents.triage.confidence_threshold")) == 81


def test_missing_file_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        ConfigManager(str(tmp_path / "missing.yaml"))


def test_invalid_file_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("llm:\n  provider: not-a-provider\n")
    with pytest.raises(ConfigError):
        ConfigManager(str(bad))


def test_validate_development_ok_and_production_rejects() -> None:
    assert ConfigManager(DEV_CONFIG).validate() is True
    with pytest.raises(ConfigError) as exc:
        ConfigManager(str(REPO_ROOT / "configs" / "production.yaml")).validate()
    assert "jwt_secret" in str(exc.value)


def test_reload_rereads_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("routing:\n  analysis_threshold: 10\n")
    cm = ConfigManager(str(path))
    assert cm.get("routing.analysis_threshold") == 10
    path.write_text("routing:\n  analysis_threshold: 20\n")
    cm.reload()
    assert cm.get("routing.analysis_threshold") == 20

    shared = ConfigManager()
    monkeypatch.setenv("LG_SOTF_WORKER__CONCURRENCY", "7")
    shared.reload()
    assert shared.get("worker.concurrency") == 7
    assert get_settings().worker.concurrency == 7


def test_either_path_or_settings(make_settings: Callable[..., Settings]) -> None:
    s = make_settings()
    assert ConfigManager(settings=s).settings is s
    with pytest.raises(ValueError):
        ConfigManager(DEV_CONFIG, settings=s)


def test_legacy_llm_client_shim(make_settings: Callable[..., Settings]) -> None:
    client = get_llm_client(ConfigManager(settings=make_settings()))
    assert isinstance(client, FakeChatModel)
    assert client.model_name == "fake-fast"

    with pytest.raises(LLMUnavailable):
        get_llm_client(ConfigManager(DEV_CONFIG))


def test_importing_package_has_no_side_effects() -> None:
    code = (
        "import sys, lg_sotf;"
        "mods = sorted(m for m in sys.modules if m.startswith('lg_sotf'));"
        "print(mods)"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert proc.stdout.strip() == "['lg_sotf']"
    assert proc.stderr == ""


def test_package_is_marked_typed() -> None:
    import lg_sotf

    assert (Path(lg_sotf.__file__).parent / "py.typed").is_file()
