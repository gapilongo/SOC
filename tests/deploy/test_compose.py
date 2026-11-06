"""docker/docker-compose.yml (dev/eval) and docker-compose.prod.yml (two-role override)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from tests.deploy._support import (
    COMPOSE,
    DOCKER_DIR,
    PROD,
    PROD_SECRETS,
    REPO_ROOT,
    ComposeLoader,
    compose_config,
    load,
    requires_compose,
)

APP_SERVICES = ("migrate", "api", "worker", "scheduler")
LONG_RUNNING = ("postgres", "redis", "api", "worker", "scheduler", "frontend")
DB_PASSWORD_VARS = ("POSTGRES_SUPERUSER_PASSWORD", "LGSOTF_OWNER_PASSWORD", "LGSOTF_APP_PASSWORD")
@pytest.fixture(scope="module")
def compose() -> Dict[str, Any]:
    return load(COMPOSE)


def test_every_service_declares_a_healthcheck(compose: Dict[str, Any]) -> None:
    services = compose["services"]
    assert set(services) == {"postgres", "redis", "migrate", "api", "worker", "scheduler", "frontend"}
    for name, svc in services.items():
        assert "healthcheck" in svc, f"{name} has no healthcheck"
        if name in LONG_RUNNING:
            check = svc["healthcheck"]
            assert not check.get("disable"), name
            assert check["test"], name
            assert check.get("interval") and check.get("retries"), name
    # The one-shot job reports through its exit code instead.
    assert services["migrate"]["healthcheck"] == {"disable": True}
    assert services["migrate"]["restart"] == "no"


def test_datastores(compose: Dict[str, Any]) -> None:
    services = compose["services"]
    assert services["postgres"]["image"].endswith("postgres:16-alpine}")
    assert "pgdata:/var/lib/postgresql/data" in services["postgres"]["volumes"]
    redis_cmd = services["redis"]["command"]
    assert redis_cmd[redis_cmd.index("--appendonly") + 1] == "yes"
    assert services["redis"]["image"].endswith("redis:7-alpine}")
    assert "redisdata:/data" in services["redis"]["volumes"]
    assert set(compose["volumes"]) == {"pgdata", "redisdata"}


def test_startup_ordering(compose: Dict[str, Any]) -> None:
    services = compose["services"]
    assert services["migrate"]["depends_on"] == {"postgres": {"condition": "service_healthy"}}
    for name in ("api", "worker", "scheduler"):
        deps = services[name]["depends_on"]
        assert deps["migrate"] == {"condition": "service_completed_successfully"}, name
        assert deps["redis"] == {"condition": "service_healthy"}, name


def test_app_containers_are_hardened_and_share_one_image(compose: Dict[str, Any]) -> None:
    services = compose["services"]
    images = {services[name]["image"] for name in APP_SERVICES}
    assert images == {"${APP_IMAGE:-lg-sotf:dev}"}
    for name in APP_SERVICES:
        svc = services[name]
        assert svc["read_only"] is True, name
        assert svc["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert any(t.startswith("/tmp") for t in svc["tmpfs"]), name
        assert svc["command"] == [name], name
    assert services["migrate"]["build"]["dockerfile"] == "docker/Dockerfile"
    assert services["migrate"]["build"]["args"]["BASE_IMAGE"] == "${PYTHON_BASE_IMAGE:-python:3.11-slim}"


def test_fake_llm_is_the_default_and_ports_bind_locally(compose: Dict[str, Any]) -> None:
    env = compose["services"]["worker"]["environment"]
    assert env["LG_SOTF_LLM__PROVIDER"] == "${LG_SOTF_LLM__PROVIDER:-fake}"
    assert env["LG_SOTF_REDIS__URL"] == "redis://redis:6379/0"
    for name in ("api", "worker", "scheduler"):
        for port in compose["services"][name]["ports"]:
            assert port.startswith("127.0.0.1:") or port.startswith("${API_BIND:-127.0.0.1}"), port
    for name in ("postgres", "redis"):
        assert "ports" not in compose["services"][name], f"{name} must not be published by default"


def test_frontend_is_an_optional_profile(compose: Dict[str, Any]) -> None:
    frontend = compose["services"]["frontend"]
    assert frontend["profiles"] == ["frontend"]
    assert frontend["build"]["context"] == "../src/lg_front"
    assert frontend["read_only"] is True


def test_prod_override_separates_database_roles() -> None:
    prod = load(PROD)
    services = prod["services"]
    for name in ("api", "worker"):
        env = services[name]["environment"]
        assert "LG_SOTF_DATABASE__MIGRATION_URL" not in env, f"{name} must not receive owner credentials"
        assert env["LG_SOTF_DATABASE__URL"].startswith("postgresql://lgsotf_app:")
        assert env["LG_SOTF_DATABASE__RUNTIME_ROLE"] == "lgsotf_app"
    for name in ("migrate", "scheduler"):
        env = services[name]["environment"]
        assert env["LG_SOTF_DATABASE__MIGRATION_URL"].startswith("postgresql://lgsotf_owner:")
    for name in ("api", "worker", "migrate", "scheduler"):
        env = services[name]["environment"]
        assert env["LG_SOTF_ENVIRONMENT"] == "staging"
        assert env["LG_SOTF_CONFIG_FILE"] == "", "the dev YAML with published keys must not load"
        assert env["LG_SOTF_AUTH__COOKIE_SECURE"] == "true"
        for key in ("LG_SOTF_AUTH__JWT_SECRET", "LG_SOTF_SECURITY__ENCRYPTION_KEYS",
                    "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY"):
            assert env[key].startswith("${" + key + ":?"), f"{key} must be required, not defaulted"
    pg = services["postgres"]
    assert "./postgres/init-roles.sh:/docker-entrypoint-initdb.d/10-init-roles.sh:ro" in pg["volumes"]


def test_prod_override_never_loads_env_file_into_app_containers() -> None:
    """.env holds the superuser/owner/app passwords; it may only feed interpolation."""
    services = load(PROD)["services"]
    for name in APP_SERVICES:
        assert services[name]["env_file"] == [], f"{name} must reset env_file"
    for name in ("api", "worker", "scheduler", "migrate"):
        env = services[name]["environment"]
        leaked = [k for k in env if k in DB_PASSWORD_VARS]
        assert leaked == [], f"{name} receives {leaked}"
    for name in ("api", "worker", "scheduler"):
        assert not any(k.startswith("LG_SOTF_AUTH__BOOTSTRAP_ADMIN") for k in services[name]["environment"]), name


def test_init_roles_script_passes_passwords_as_psql_variables() -> None:
    script = (DOCKER_DIR / "postgres" / "init-roles.sh").read_text()
    assert script.startswith("#!/bin/sh\n")
    assert "set -eu" in script
    assert "<<'SQL'" in script, "quoted heredoc: the shell must not interpolate into SQL"
    sql = script.split("<<'SQL'", 1)[1]
    assert "$" not in sql
    assert "PASSWORD :'owner_pw'" in sql and "PASSWORD :'app_pw'" in sql
    assert "NOBYPASSRLS" in sql and "NOSUPERUSER" in sql
    assert os.access(DOCKER_DIR / "postgres" / "init-roles.sh", os.X_OK)


@requires_compose
def test_compose_config_resolves_with_defaults() -> None:
    cfg = compose_config(str(COMPOSE), env={})
    services = cfg["services"]
    assert "frontend" not in services, "profile services are excluded by default"
    worker_env = services["worker"]["environment"]
    assert worker_env["LG_SOTF_LLM__PROVIDER"] == "fake"
    assert worker_env["LG_SOTF_CONFIG_FILE"] == "/app/configs/development.yaml"
    assert services["api"]["healthcheck"]["test"][-1] == "/usr/local/lib/lg-sotf/healthcheck.py"


@requires_compose
def test_prod_override_requires_secrets() -> None:
    argv = ["docker", "compose", "-f", str(COMPOSE), "-f", str(PROD), "config", "-q"]
    proc = subprocess.run(
        argv, capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")}, timeout=60
    )
    if "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin is not installed")
    assert proc.returncode != 0
    assert "required variable" in proc.stderr.lower() or "set " in proc.stderr


@requires_compose
def test_prod_override_resolves_with_secrets() -> None:
    cfg = compose_config(str(COMPOSE), str(PROD), env=PROD_SECRETS)
    services = cfg["services"]
    assert "LG_SOTF_DATABASE__MIGRATION_URL" not in services["api"]["environment"]
    assert "LG_SOTF_DATABASE__MIGRATION_URL" not in services["worker"]["environment"]
    assert services["scheduler"]["environment"]["LG_SOTF_DATABASE__MIGRATION_URL"] == (
        "postgresql://lgsotf_owner:compose-test-owner@postgres:5432/lgsotf"
    )
    assert services["postgres"]["environment"]["POSTGRES_USER"] == "postgres"


def _generated_env_file(tmp_path: Path) -> Dict[str, str]:
    """The documented flow: .env.example plus `generate_secrets.py --append .env`."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("generate_secrets", REPO_ROOT / "scripts" / "generate_secrets.py")
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    target = tmp_path / ".env"
    target.write_text((REPO_ROOT / ".env.example").read_text() + "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL=a@example.com\n")
    assert gen.main(["--append", str(target)]) == 0
    values: Dict[str, str] = {}
    for line in target.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


@requires_compose
def test_prod_override_with_generated_env_file_isolates_credentials(tmp_path: Path) -> None:
    values = _generated_env_file(tmp_path)
    cfg = compose_config(str(COMPOSE), str(PROD), env={}, env_file=tmp_path / ".env")
    services = cfg["services"]
    superuser, owner_pw, app_pw = (values[k] for k in DB_PASSWORD_VARS)
    admin_pw = values["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD"]

    for name in ("migrate", "api", "worker", "scheduler"):
        env = services[name]["environment"]
        assert not set(DB_PASSWORD_VARS) & set(env), f"{name} received a raw database password"
        blob = json.dumps(env)
        assert superuser not in blob, f"{name} can see the PostgreSQL superuser password"
        if name in ("api", "worker"):
            assert owner_pw not in blob, f"{name} can see the schema-owner password"
            assert "LG_SOTF_DATABASE__MIGRATION_URL" not in env
            assert env["LG_SOTF_DATABASE__URL"] == f"postgresql://lgsotf_app:{app_pw}@postgres:5432/lgsotf"
        if name != "migrate":
            assert admin_pw not in blob, f"{name} can see the bootstrap admin password"
        # Secrets still arrive through explicit, interpolated keys.
        assert env["LG_SOTF_AUTH__JWT_SECRET"] == values["LG_SOTF_AUTH__JWT_SECRET"]
        assert env["LG_SOTF_API__METRICS_TOKEN"] == values["LG_SOTF_API__METRICS_TOKEN"]

    migrate = services["migrate"]["environment"]
    assert migrate["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD"] == admin_pw
    assert migrate["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL"] == "a@example.com"
    assert migrate["LG_SOTF_DATABASE__MIGRATION_URL"] == f"postgresql://lgsotf_owner:{owner_pw}@postgres:5432/lgsotf"
    # Only postgres needs the role passwords.
    pg = services["postgres"]["environment"]
    assert pg["POSTGRES_PASSWORD"] == superuser and pg["LGSOTF_OWNER_PASSWORD"] == owner_pw
    # Optional pass-through keys that are unset in .env stay unset (not empty strings).
    assert services["api"]["environment"].get("ANTHROPIC_API_KEY") is None


def test_api_trusts_exactly_the_frontend_proxy() -> None:
    """WSC-1: behind the bundled nginx every request would otherwise carry the proxy's address,
    so one client could exhaust the per-address login cap for everyone."""
    base = yaml.load(COMPOSE.read_text(), Loader=ComposeLoader)  # noqa: S506 - SafeLoader subclass
    prod = yaml.load(PROD.read_text(), Loader=ComposeLoader)  # noqa: S506
    services = base["services"]
    frontend_ip = services["frontend"]["networks"]["edge"]["ipv4_address"]
    assert frontend_ip == "${EDGE_FRONTEND_IP:-172.31.250.2}"
    assert services["api"]["environment"]["LG_SOTF_API__FORWARDED_ALLOW_IPS"] == frontend_ip
    assert "edge" in services["api"]["networks"]
    assert base["networks"]["edge"]["ipam"]["config"][0]["subnet"] == "${EDGE_SUBNET:-172.31.250.0/29}"
    prod_api = prod["services"]["api"]["environment"]["LG_SOTF_API__FORWARDED_ALLOW_IPS"]
    assert prod_api.endswith("${EDGE_FRONTEND_IP:-172.31.250.2}}")
