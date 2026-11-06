"""The test services: docker/docker-compose.test.yml and CI create the same plain role from one SQL file."""

from __future__ import annotations

import re
from typing import Any, Dict, List

import yaml

from tests.deploy._support import DOCKER_DIR, REPO_ROOT, compose_config, requires_compose

TEST_COMPOSE = DOCKER_DIR / "docker-compose.test.yml"
ROLE_SQL = "scripts/ci/create_test_role.sql"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _compose() -> Dict[str, Any]:
    data = yaml.safe_load(TEST_COMPOSE.read_text())
    assert isinstance(data, dict)
    return data


def _role_steps(workflow: str) -> List[Dict[str, Any]]:
    jobs = yaml.safe_load((WORKFLOWS / workflow).read_text())["jobs"]
    return [
        step | {"job": name}
        for name, job in jobs.items()
        for step in job.get("steps", [])
        if step.get("name") == "Create the non-superuser test role"
    ]


def test_the_role_is_plain_and_may_create_the_per_worker_databases() -> None:
    sql = (REPO_ROOT / ROLE_SQL).read_text()
    statements = [s.strip() for s in re.sub(r"--[^\n]*", "", sql).split(";") if s.strip()]
    assert statements == [
        "CREATE ROLE soc LOGIN PASSWORD 'ci_only_password' NOSUPERUSER NOBYPASSRLS CREATEDB",
        "CREATE DATABASE soc_test OWNER soc",
    ]


def test_ci_and_the_compose_file_run_the_same_sql_file() -> None:
    steps = _role_steps("ci.yml") + _role_steps("nightly.yml")
    assert {s["job"] for s in steps} == {"test", "test-parallel", "random-order"}
    for step in steps:
        assert step["run"].strip() == f"psql -h 127.0.0.1 -U postgres -v ON_ERROR_STOP=1 -f {ROLE_SQL}", step["job"]
    mounts = _compose()["services"]["postgres"]["volumes"]
    assert f"../{ROLE_SQL}:/docker-entrypoint-initdb.d/10-create-test-role.sql:ro" in mounts


def test_the_compose_file_uses_ci_images_local_ports_and_tmpfs() -> None:
    services = _compose()["services"]
    ci = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())["jobs"]["test"]["services"]
    assert services["postgres"]["image"] == ci["postgres"]["image"]
    assert services["redis"]["image"] == ci["redis"]["image"]
    for name, service in services.items():
        assert service["tmpfs"], name
        assert all(port.startswith("127.0.0.1:") for port in service["ports"]), name
        assert "healthcheck" in service, name
        assert "volumes" not in service or all(v.endswith(":ro") for v in service["volumes"]), name


def test_make_test_integration_points_at_the_compose_services() -> None:
    make = (REPO_ROOT / "Makefile").read_text()
    ports = {name: s["ports"][0].split(":")[1] for name, s in _compose()["services"].items()}
    assert f"postgresql://soc:ci_only_password@127.0.0.1:{ports['postgres']}/soc_test" in make
    assert f"redis://127.0.0.1:{ports['redis']}/5" in make
    for target in ("test-services:", "test-integration:", "test-services-down:", "test-serial:", "test-parallel:"):
        assert target in make, target


@requires_compose
def test_the_compose_file_resolves() -> None:
    cfg = compose_config(str(TEST_COMPOSE), env={})
    assert set(cfg["services"]) == {"postgres", "redis"}
