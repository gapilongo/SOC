""".env.example coverage of the settings model, and scripts/generate_secrets.py."""

from __future__ import annotations

import importlib.util
import os
import re
import stat
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Set

import pytest
from cryptography.fernet import Fernet
from pydantic import BaseModel

from lg_sotf.security.insecure import is_insecure_secret
from lg_sotf.settings import Settings
from tests.deploy._support import REPO_ROOT

ENV_EXAMPLE = REPO_ROOT / ".env.example"
_VAR = re.compile(r"^#?\s*(LG_SOTF_[A-Z0-9_]+)=", re.MULTILINE)


def documented_vars() -> Set[str]:
    return set(_VAR.findall(ENV_EXAMPLE.read_text()))


def resolves(var: str) -> bool:
    """Whether LG_SOTF_<SECTION>__<KEY>[__<SUB>] names a real Settings field."""
    parts = [p.lower() for p in var[len("LG_SOTF_"):].split("__")]
    model: Any = Settings
    for i, part in enumerate(parts):
        fields = model.model_fields
        if part not in fields:
            return False
        annotation = fields[part].annotation
        if i < len(parts) - 1:
            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                model = annotation
            else:
                return False
    return True


def test_every_documented_variable_is_a_real_setting() -> None:
    unknown = sorted(v for v in documented_vars() if not resolves(v))
    assert unknown == []


@pytest.mark.parametrize(
    "var",
    [
        "LG_SOTF_DATABASE__URL",
        "LG_SOTF_DATABASE__MIGRATION_URL",
        "LG_SOTF_DATABASE__RUNTIME_ROLE",
        "LG_SOTF_REDIS__URL",
        "LG_SOTF_LLM__PROVIDER",
        "LG_SOTF_LLM__API_KEY",
        "LG_SOTF_AUTH__JWT_SECRET",
        "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL",
        "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD",
        "LG_SOTF_SECURITY__ENCRYPTION_KEYS",
        "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY",
        "LG_SOTF_API__METRICS_TOKEN",
        "LG_SOTF_RESPONSE__WEBHOOK_SECRET",
        "LG_SOTF_WORKER__CONCURRENCY",
    ],
)
def test_important_variables_are_documented(var: str) -> None:
    assert var in documented_vars()


def test_env_example_documents_key_generation() -> None:
    text = ENV_EXAMPLE.read_text()
    assert "Fernet.generate_key()" in text
    assert "secrets.token_urlsafe" in text
    for provider_key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
        assert provider_key in text


def test_env_example_defaults_to_the_offline_llm() -> None:
    active = dict(
        line.split("=", 1) for line in ENV_EXAMPLE.read_text().splitlines() if line and not line.startswith("#")
    )
    assert active["LG_SOTF_LLM__PROVIDER"] == "fake"


def load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_secrets", REPO_ROOT / "scripts" / "generate_secrets.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = load_generator()


def parse_env(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def test_generated_secrets_are_valid_and_strong() -> None:
    values = gen.generate()
    Fernet(values["LG_SOTF_SECURITY__ENCRYPTION_KEYS"].encode())
    assert len(values["LG_SOTF_AUTH__JWT_SECRET"].encode()) >= 32
    assert len(values["LG_SOTF_SECURITY__INDICATOR_HMAC_KEY"].encode()) >= 16
    for key, value in values.items():
        assert not is_insecure_secret(value), key
        if "PASSWORD" in key:
            assert re.fullmatch(r"[A-Za-z0-9_-]{24,}", value), "URL-safe so it embeds in a DSN unescaped"
    again = gen.generate()
    assert all(values[k] != again[k] for k in values), "values must be random per run"


def test_generated_secrets_satisfy_production_checks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in list(os.environ):
        if var.startswith("LG_SOTF_") or var in ("DATABASE_URL", "REDIS_URL", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    values = gen.generate()
    settings = Settings(
        environment="production",
        database={"url": f"postgresql://lgsotf_app:{values['LGSOTF_APP_PASSWORD']}@db:5432/lgsotf"},
        llm={"provider": "anthropic", "api_key": "sk-ant-not-a-real-key-0000000000"},
        auth={"jwt_secret": values["LG_SOTF_AUTH__JWT_SECRET"]},
        security={
            "encryption_keys": values["LG_SOTF_SECURITY__ENCRYPTION_KEYS"],
            "indicator_hmac_key": values["LG_SOTF_SECURITY__INDICATOR_HMAC_KEY"],
        },
        api={"metrics_token": values["LG_SOTF_API__METRICS_TOKEN"], "cors_origins": []},
    )
    assert settings.production_problems() == []


def test_append_adds_only_missing_keys_and_creates_private_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    target = tmp_path / ".env"
    assert gen.main(["--append", str(target)]) == 0
    first = parse_env(target.read_text())
    assert set(first) == set(gen.generate())
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    for value in first.values():
        assert value not in out, "secrets must never be printed in append mode"

    assert gen.main(["--append", str(target)]) == 0
    assert parse_env(target.read_text()) == first, "re-running must not rotate existing secrets"

    partial = tmp_path / "partial.env"
    partial.write_text("LG_SOTF_AUTH__JWT_SECRET=keep-this-one-it-is-long-enough-0000000\n")
    partial.chmod(0o640)
    gen.main(["--append", str(partial)])
    merged = parse_env(partial.read_text())
    assert merged["LG_SOTF_AUTH__JWT_SECRET"] == "keep-this-one-it-is-long-enough-0000000"
    assert set(merged) == set(first)
    assert stat.S_IMODE(partial.stat().st_mode) == 0o640, "an existing file keeps its mode"


def _secret_blocks(text: str) -> Dict[str, Dict[str, str]]:
    """Parse `kubectl create secret generic NAME --from-env-file=/dev/stdin <<'EOF'` blocks."""
    blocks: Dict[str, Dict[str, str]] = {}
    pattern = re.compile(
        r"^kubectl create secret generic (\S+) --from-env-file=/dev/stdin <<'(\w+)'\n(.*?)^\2$",
        re.MULTILINE | re.DOTALL,
    )
    for name, _, body in pattern.findall(text):
        blocks[name] = parse_env(body)
    return blocks


K8S_ENV = {
    "LG_SOTF_DATABASE__URL": "postgresql://lgsotf_app:p$w0rd@db:5432/lgsotf",
    "LG_SOTF_REDIS__URL": "rediss://:r3dis@redis:6380/0",
    "ANTHROPIC_API_KEY": "sk-ant-fixture-not-a-key",
    "LG_SOTF_DATABASE__MIGRATION_URL": "postgresql://lgsotf_owner:o$wner@db:5432/lgsotf",
}


def test_k8s_runtime_secret_never_carries_the_bootstrap_admin() -> None:
    values = gen.generate()
    text = gen.render_k8s(values, "lg-sotf", environ=K8S_ENV, admin_email="admin@example.com")
    blocks = _secret_blocks(text)
    assert set(blocks) == {"lg-sotf", "lg-sotf-owner", "lg-sotf-bootstrap"}

    runtime = blocks["lg-sotf"]
    assert not any(k.startswith("LG_SOTF_AUTH__BOOTSTRAP_ADMIN") for k in runtime), "would reach every pod"
    assert values["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD"] not in runtime.values()
    assert not any(k in runtime for k in ("POSTGRES_SUPERUSER_PASSWORD", "LGSOTF_OWNER_PASSWORD", "LGSOTF_APP_PASSWORD"))
    assert "LG_SOTF_DATABASE__MIGRATION_URL" not in runtime, "the owner DSN belongs in the owner Secret"
    for key in ("LG_SOTF_AUTH__JWT_SECRET", "LG_SOTF_SECURITY__ENCRYPTION_KEYS",
                "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY", "LG_SOTF_API__METRICS_TOKEN"):
        assert runtime[key] == values[key]
    for key in ("LG_SOTF_DATABASE__URL", "LG_SOTF_REDIS__URL", "ANTHROPIC_API_KEY"):
        assert runtime[key] == K8S_ENV[key]

    assert blocks["lg-sotf-owner"] == {"LG_SOTF_DATABASE__MIGRATION_URL": K8S_ENV["LG_SOTF_DATABASE__MIGRATION_URL"]}
    assert blocks["lg-sotf-bootstrap"] == {
        "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL": "admin@example.com",
        "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD": values["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD"],
    }
    assert "--from-literal" not in text, "values must not be passed as command-line arguments"


def test_k8s_format_lists_what_is_still_missing() -> None:
    text = gen.render_k8s(gen.generate(), "lg-sotf", environ={})
    assert set(_secret_blocks(text)) == {"lg-sotf"}
    assert "LG_SOTF_DATABASE__URL, LG_SOTF_REDIS__URL" in text
    assert "LLM provider key" in text
    assert "--admin-email" in text and "lg-sotf-owner" in text


def test_k8s_output_feeds_values_through_stdin_not_argv(tmp_path: Path) -> None:
    """Piping the output to sh delivers each Secret on stdin, unexpanded by the shell."""
    import subprocess

    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    fake = bindir / "kubectl"
    fake.write_text(f'#!/bin/sh\nprintf "ARGV %s\\n" "$*" >> {log}\ncat >> {log}\n')
    fake.chmod(0o755)
    text = gen.render_k8s(gen.generate(), "lg-sotf", environ=K8S_ENV, admin_email="admin@example.com")
    subprocess.run(
        ["/bin/sh"], input=text, text=True, check=True, timeout=30,
        env={"PATH": f"{bindir}:/usr/bin:/bin"},
    )
    calls = log.read_text()
    argv_lines = [line for line in calls.splitlines() if line.startswith("ARGV ")]
    assert len(argv_lines) == 3
    assert all(line.endswith("--from-env-file=/dev/stdin") for line in argv_lines)
    assert "p$w0rd" in calls and "o$wner" in calls, "quoted here-document: no shell expansion"


def test_k8s_cli_prints_no_bootstrap_in_runtime_secret(
    capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    for var in (*gen.K8S_RUNTIME_PASSTHROUGH, "LG_SOTF_DATABASE__MIGRATION_URL", "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL"):
        monkeypatch.delenv(var, raising=False)
    assert gen.main(["--format", "k8s", "--secret-name", "acme"]) == 0
    blocks = _secret_blocks(capsys.readouterr().out)
    assert set(blocks) == {"acme"}
    keys: List[str] = list(blocks["acme"])
    assert keys and all(k.startswith("LG_SOTF_") for k in keys)
    assert "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY" in keys
    assert not any("BOOTSTRAP" in k for k in keys)


def test_only_useful_scripts_remain() -> None:
    scripts = sorted(p.relative_to(REPO_ROOT / "scripts").as_posix() for p in (REPO_ROOT / "scripts").rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts)
    assert scripts == [
        "airgap/bundle.sh",
        "airgap/load.sh",
        "ci/bandit-baseline.json",
        "ci/coverage_floors.py",
        "ci/gitleaks-history.ignore",
        "ci/gitleaks.toml",
        "demo/alerts.json",
        "demo/seed_demo.py",
        "e2e_ui_stack.sh",
        "export_openapi.py",
        "generate_secrets.py",
        "load_test.py",
        "make_tour_media.sh",
        "quickstart.sh",
        "record_tour.mjs",
        "smoke_stack.py",
        "smoke_stack.sh",
    ]


def test_tour_scripts_keep_the_admin_password_out_of_output() -> None:
    """The README tour signs in with the demo stack's bootstrap password; it is read, never printed."""
    tour = (REPO_ROOT / "scripts" / "record_tour.mjs").read_text()
    media = REPO_ROOT / "scripts" / "make_tour_media.sh"
    assert "BOOTSTRAP_ADMIN_PASSWORD" in tour
    logged = [line for line in tour.splitlines() if "console." in line]
    assert logged and not any("password" in line.lower() for line in logged), logged
    assert os.access(media, os.X_OK) and "set -euo pipefail" in media.read_text()


def test_smoke_script_is_strict_private_and_cleans_up() -> None:
    path = REPO_ROOT / "scripts" / "smoke_stack.sh"
    text = path.read_text()
    assert os.access(path, os.X_OK) and os.access(REPO_ROOT / "scripts" / "smoke_stack.py", os.X_OK)
    assert "set -euo pipefail" in text
    # Secrets live in a private temp dir and reach the driver through the environment only.
    assert 'chmod 700 "$WORK"' in text and 'install -m 600 /dev/null "$ENV_FILE"' in text
    assert "--password-stdin" in text and "--password " not in text
    assert "trap cleanup EXIT" in text and "down -v" in text
    # The production-like override is what customers run; the stack must be exercised with it.
    assert "docker/docker-compose.prod.yml" in text
    for phase in ("drive flow", "kill -s SIGKILL worker",
        "queue already drained", "restart worker", "stop redis", "drive unready", "drive ready"):
        assert phase in text
