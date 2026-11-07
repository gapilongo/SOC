"""The proof-of-value install (scripts/pov.sh, docker/docker-compose.pov.yml, make pov), run against a stub docker."""

from __future__ import annotations

import os
import socket
import stat
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
POV = REPO_ROOT / "scripts" / "pov.sh"
OVERLAY = REPO_ROOT / "docker" / "docker-compose.pov.yml"
STUB_DOCKER = '#!/bin/sh\nprintf "%s\\n" "$*" >> "$STUB_LOG"\nexit 0\n'


def free_port() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return str(sock.getsockname()[1])


@pytest.fixture
def stub(tmp_path: Path) -> Tuple[Dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(STUB_DOCKER)
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "docker.log"
    log.touch()
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path), "STUB_LOG": str(log),
        "POV_DIR": str(tmp_path / "pov"), "POV_UI_PORT": free_port(), "POV_API_PORT": free_port(),
        "POV_WORKER_PORT": free_port(), "POV_SCHEDULER_PORT": free_port(),
        # Must not reach the stack: the PoV has no response connector.
        "LG_SOTF_RESPONSE__WEBHOOK_URL": "https://hooks.example.com/soar",
    }
    return env, log


def run(env: Dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(POV), *args], capture_output=True, text=True, env=env, timeout=120, cwd=REPO_ROOT)


def env_file(env: Dict[str, str]) -> Dict[str, str]:
    lines = (Path(env["POV_DIR"]) / "stack.env").read_text().splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))


def test_one_command_installs_the_profile_and_prints_the_next_steps(stub: Tuple[Dict[str, str], Path]) -> None:
    env, log = stub
    proc = run(env, "--siem-host", "Wazuh.Prospect.Example")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    state = Path(env["POV_DIR"])
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    for private in ("stack.env", "admin-credentials.txt"):
        assert stat.S_IMODE((state / private).stat().st_mode) == 0o600
    values = env_file(env)
    assert values["POV_EGRESS_HOSTS"] == "wazuh.prospect.example,ollama"
    assert values["LG_SOTF_LLM__PROVIDER"] == "ollama" and values["OLLAMA_MODEL"] == "qwen3:8b"
    assert "LG_SOTF_RESPONSE__WEBHOOK_URL" not in values
    password = (state / "admin-credentials.txt").read_text().split("PASSWORD=", 1)[1].strip()
    assert password and password not in proc.stdout + proc.stderr + log.read_text()
    calls = log.read_text()
    assert "-f docker/docker-compose.pov.yml" in calls and "-f docker/docker-compose.prod.yml" in calls
    assert "up -d --no-build" in calls and "create-tenant --id pov" in calls and "--password-stdin" in calls
    out = proc.stdout
    assert "Connect a source" in out and "--backtest 90" in out and "lg-sotf eval --from-history" in out
    assert "dry-run only" in out and "wazuh.prospect.example,ollama" in out

    # Adding a host later keeps the earlier ones; an EU endpoint replaces the local model.
    proc = run({**env, "POV_LLM_API_KEY": "test-only-key"}, "--allow-host", "misp.prospect.example",
               "--llm-url", "https://api.mistral.ai/v1", "--llm-model", "mistral-small-latest")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    values = env_file(env)
    assert values["POV_EGRESS_HOSTS"] == "wazuh.prospect.example,misp.prospect.example,api.mistral.ai"
    assert values["LG_SOTF_LLM__PROVIDER"] == "openai_compatible" and "OLLAMA_MODEL" not in values
    assert "docker-compose.ollama.yml" not in log.read_text().splitlines()[-1]


@pytest.mark.parametrize(
    "args, message",
    [
        (["--llm-url", "https://api.deepseek.com/v1", "--llm-model", "deepseek-chat", "--siem-host", "s.example"],
         "DeepSeek"),
        (["--llm-url", "http://llm.example/v1", "--llm-model", "m", "--siem-host", "s.example"], "https URL"),
        (["--ollama", "qwen3:8b"], "--siem-host"),
        (["--siem-host", "https://wazuh.example:9200"], "not a host name"),
    ],
)
def test_refusals_happen_before_anything_is_written(stub: Tuple[Dict[str, str], Path], args: list, message: str) -> None:
    env, log = stub
    proc = run(env, *args)
    assert proc.returncode != 0 and message in proc.stderr, proc.stderr
    assert not Path(env["POV_DIR"]).exists()
    assert "compose" not in log.read_text().replace("compose version", "")


def test_the_overlay_pins_the_policy_for_every_app_service() -> None:
    overlay = yaml.safe_load(OVERLAY.read_text())
    env = overlay["x-pov-environment"]
    assert env["LG_SOTF_RESPONSE__DRY_RUN"] == "true" and env["LG_SOTF_INTEGRATIONS__ENABLED"] == "false"
    assert env["LG_SOTF_INGESTION__READ_ONLY_SOURCES"] == "true" and env["LG_SOTF_LLM__ALLOW_FAKE"] == "false"
    assert env["LG_SOTF_INGESTION__ALLOWED_DESTINATION_HOSTS"].startswith("${POV_EGRESS_HOSTS:?")
    assert set(overlay["services"]) == {"migrate", "api", "worker", "scheduler"}


def test_make_targets_and_state_dir() -> None:
    text = (REPO_ROOT / "Makefile").read_text()
    assert "pov: ##" in text and "pov-down: ##" in text and "scripts/pov.sh --down" in text
    assert ".pov/" in (REPO_ROOT / ".gitignore").read_text().splitlines()
    assert os.access(POV, os.X_OK) and "set -euo pipefail" in POV.read_text()
