"""Local model overlay (docker/docker-compose.ollama.yml), air-gapped bundle scripts
(scripts/airgap), the quickstart (scripts/quickstart.sh, scripts/demo) and their docs."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterator, List, Tuple

import pytest

from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.ingestion.normalizers.canonical import CanonicalNormalizer
from lg_sotf.llm.client import get_chat_model, provider_of
from lg_sotf.llm.endpoint import check_base_url
from tests.deploy._support import DOCKER_DIR, REPO_ROOT
from tests.deploy.test_compose import COMPOSE, PROD, PROD_SECRETS, compose_config, load, requires_compose

OLLAMA = DOCKER_DIR / "docker-compose.ollama.yml"
BUNDLE = REPO_ROOT / "scripts" / "airgap" / "bundle.sh"
LOAD = REPO_ROOT / "scripts" / "airgap" / "load.sh"
QUICKSTART = REPO_ROOT / "scripts" / "quickstart.sh"
SEED = REPO_ROOT / "scripts" / "demo" / "seed_demo.py"
ALERTS = REPO_ROOT / "scripts" / "demo" / "alerts.json"
SHELL_SCRIPTS = (BUNDLE, LOAD, QUICKSTART)
PINNED = re.compile(r"^ollama/ollama:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$")


# --------------------------------------------------------------------------
# Compose overlay
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def overlay() -> Dict[str, Any]:
    return load(OLLAMA)


def _pinned_image() -> str:
    match = re.search(r"^x-ollama-image: &ollama-image \$\{OLLAMA_IMAGE:-(.+)\}$", OLLAMA.read_text(), re.MULTILINE)
    assert match, "the Ollama image pin must be the x-ollama-image anchor (bundle.sh reads it)"
    return match.group(1)


def test_ollama_image_is_pinned_by_tag_and_digest() -> None:
    assert PINNED.match(_pinned_image())


def test_ollama_service_is_isolated_and_hardened(overlay: Dict[str, Any]) -> None:
    svc = overlay["services"]["ollama"]
    assert svc["networks"] == ["llm"], "ollama must be reachable only on the internal llm network"
    assert overlay["networks"]["llm"]["internal"] is True
    assert "ports" not in svc and "expose" not in svc
    assert "ollama-models:/root/.ollama" in svc["volumes"] and "ollama-models" in overlay["volumes"]
    assert svc["cap_drop"] == ["ALL"] and "no-new-privileges:true" in svc["security_opt"]
    check = svc["healthcheck"]
    assert check["test"] == ["CMD", "ollama", "list"] and check["interval"] and check["retries"]
    assert svc["environment"]["OLLAMA_CONTEXT_LENGTH"].startswith("${OLLAMA_CONTEXT_LENGTH:-16384")


def test_model_pull_is_an_opt_in_one_shot(overlay: Dict[str, Any]) -> None:
    pull = overlay["services"]["ollama-pull"]
    assert pull["profiles"] == ["ollama-pull"] and pull["restart"] == "no"
    assert pull["networks"] == ["default"], "only the one-shot puller may have egress"
    assert "ollama-models:/root/.ollama" in pull["volumes"]
    assert 'ollama pull "$$model"' in pull["command"][0]


def test_app_services_use_the_local_model(overlay: Dict[str, Any], make_settings: Any) -> None:
    services = overlay["services"]
    for name in ("api", "worker"):
        env = services[name]["environment"]
        assert env["LG_SOTF_LLM__PROVIDER"] == "ollama"
        check_base_url(env["LG_SOTF_LLM__BASE_URL"])
        assert "llm" in services[name]["networks"]
    assert set(services["worker"]["networks"]) == {"default", "llm"}, "the worker keeps its default network"
    assert services["worker"]["depends_on"]["ollama"]["condition"] == "service_healthy"
    env = services["worker"]["environment"]
    settings = make_settings(
        environment="production",
        llm={
            "provider": env["LG_SOTF_LLM__PROVIDER"],
            "base_url": env["LG_SOTF_LLM__BASE_URL"],
            "structured_output": "json_schema",
            "fast": {"model": "qwen3:8b"},
        },
    )
    assert not any(p.startswith("llm.") for p in settings.production_problems())
    assert provider_of(get_chat_model("fast", settings)) == "ollama"


@requires_compose
def test_overlay_resolves_on_the_dev_stack() -> None:
    cfg = compose_config(str(COMPOSE), str(OLLAMA), env={"OLLAMA_MODEL": "qwen3:8b", "OLLAMA_DEEP_MODEL": "qwen3:14b"})
    services = cfg["services"]
    assert "ollama-pull" not in services
    worker = services["worker"]["environment"]
    assert worker["LG_SOTF_LLM__FAST__MODEL"] == "qwen3:8b" and worker["LG_SOTF_LLM__DEEP__MODEL"] == "qwen3:14b"
    assert set(services["api"]["networks"]) == {"default", "edge", "llm"}
    assert set(services["ollama"]["networks"]) == {"llm"}
    assert cfg["networks"]["llm"]["internal"] is True
    for name in ("scheduler", "migrate", "postgres", "redis"):
        assert "llm" not in services[name].get("networks", {}), name


@requires_compose
def test_overlay_resolves_on_the_production_stack() -> None:
    cfg = compose_config(str(COMPOSE), str(PROD), str(OLLAMA), env=PROD_SECRETS)
    api = cfg["services"]["api"]["environment"]
    assert api["LG_SOTF_LLM__PROVIDER"] == "ollama", "the overlay must win over the production passthrough"
    assert api["LG_SOTF_LLM__DEEP__MODEL"] == "qwen3:8b"
    assert cfg["services"]["ollama"]["image"] == _pinned_image()


def test_prod_passthrough_forwards_the_local_llm_settings() -> None:
    passthrough = load(PROD)["x-passthrough"]
    for key in ("LG_SOTF_LLM__BASE_URL", "LG_SOTF_LLM__STRUCTURED_OUTPUT", "LG_SOTF_LLM__DEEP__TIMEOUT_S"):
        assert key in passthrough


# --------------------------------------------------------------------------
# Shell scripts
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_scripts_are_strict_and_executable(path: Path) -> None:
    text = path.read_text()
    assert os.access(path, os.X_OK)
    assert text.startswith("#!/usr/bin/env bash\n") and "set -euo pipefail" in text


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_scripts_pass_shellcheck() -> None:
    proc = subprocess.run(
        ["shellcheck", "-x", *map(str, SHELL_SCRIPTS)], capture_output=True, text=True, timeout=120  # noqa: S607
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


STUB_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_LOG"
case "$1" in
  save) shift; printf 'image-archive:%s\n' "$*" ;;
  load) cat >/dev/null; echo "Loaded image" ;;
  run) case "$*" in *" ls "*) ;; *) ;; esac ;;
  *) ;;
esac
exit 0
"""


@pytest.fixture
def stub_docker(tmp_path: Path) -> Iterator[Tuple[Dict[str, str], Path]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(STUB_DOCKER)
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "docker.log"
    log.touch()
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path), "STUB_LOG": str(log)}
    yield env, log


def run_script(path: Path, *args: str, env: Dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(path), *args], capture_output=True, text=True, env=env, timeout=120, cwd=REPO_ROOT
    )


def _make_bundle(stub_docker: Tuple[Dict[str, str], Path], out: Path, *extra: str) -> str:
    env, _ = stub_docker
    proc = run_script(BUNDLE, "--ollama", "--output", str(out), *extra, env={**env, "APP_IMAGE": "lg-sotf:1.0.0"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    match = re.search(r"SHA-256 of SHA256SUMS: ([0-9a-f]{64})", proc.stdout)
    assert match, proc.stdout
    return match.group(1)


def test_bundle_saves_images_and_writes_a_manifest(stub_docker: Tuple[Dict[str, str], Path], tmp_path: Path) -> None:
    models = tmp_path / "ollama-home" / "models" / "manifests"
    models.mkdir(parents=True)
    (models / "qwen3").write_text("{}")
    out = tmp_path / "bundle"
    manifest_sum = _make_bundle(stub_docker, out, "--models-dir", str(tmp_path / "ollama-home"))
    _, log = stub_docker
    calls = log.read_text().splitlines()
    pinned = _pinned_image()
    tag = pinned.split("@", 1)[0]
    assert f"tag {pinned} {tag}" in calls, "a digest-pinned image is saved under its tag"
    save = next(c for c in calls if c.startswith("save "))
    assert save.split()[1:] == ["lg-sotf:1.0.0", "lg-sotf-frontend:dev", "postgres:16-alpine", "redis:7-alpine", tag]
    assert (out / "images.env").read_text().splitlines() == [
        "APP_IMAGE=lg-sotf:1.0.0",
        "FRONTEND_IMAGE=lg-sotf-frontend:dev",
        "POSTGRES_IMAGE=postgres:16-alpine",
        "REDIS_IMAGE=redis:7-alpine",
        f"OLLAMA_IMAGE={tag}",
    ]
    listed = {line.split("  ", 1)[1] for line in (out / "SHA256SUMS").read_text().splitlines()}
    assert listed == {"images.tar.gz", "images.env", "ollama-models.tar", "deploy.tar.gz"}
    for name in listed:
        digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
        assert f"{digest}  {name}" in (out / "SHA256SUMS").read_text()
    assert manifest_sum == hashlib.sha256((out / "SHA256SUMS").read_bytes()).hexdigest()
    members = subprocess.run(
        ["tar", "-tzf", str(out / "deploy.tar.gz")], capture_output=True, text=True, check=True  # noqa: S607
    ).stdout.split()
    for needed in ("docker/docker-compose.ollama.yml", "scripts/airgap/load.sh", "docs/air-gapped.md", "configs/production.yaml"):
        assert any(m.startswith(needed) for m in members), needed
    assert not any(m.startswith((".env", ".quickstart")) and m != ".env.example" for m in members)


def test_bundle_refuses_a_non_empty_output(stub_docker: Tuple[Dict[str, str], Path], tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "old").write_text("x")
    proc = run_script(BUNDLE, "--output", str(out), env=stub_docker[0])
    assert proc.returncode != 0 and "not empty" in proc.stderr


def test_load_verifies_then_loads(stub_docker: Tuple[Dict[str, str], Path], tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    manifest_sum = _make_bundle(stub_docker, out)
    env, log = stub_docker
    log.write_text("")
    proc = run_script(LOAD, "--expect", manifest_sum, str(out), env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "manifest matches" in proc.stdout and "APP_IMAGE=lg-sotf:1.0.0" in proc.stdout
    assert "load" in log.read_text().splitlines()


@pytest.mark.parametrize("tamper", ["file", "extra", "expect", "traversal", "unlisted-images"])
def test_load_refuses_a_tampered_bundle(stub_docker: Tuple[Dict[str, str], Path], tmp_path: Path, tamper: str) -> None:
    out = tmp_path / "bundle"
    manifest_sum = _make_bundle(stub_docker, out)
    env, log = stub_docker
    expect = manifest_sum
    manifest = out / "SHA256SUMS"
    if tamper == "file":
        (out / "images.env").write_text("APP_IMAGE=evil/lg-sotf:latest\n")
        expect = ""
    elif tamper == "extra":
        (out / "run-me.sh").write_text("echo hi\n")
    elif tamper == "expect":
        expect = "0" * 64
    elif tamper == "traversal":
        manifest.write_text(manifest.read_text() + f"{'a' * 64}  ../../etc/passwd\n")
        expect = ""
    elif tamper == "unlisted-images":
        manifest.write_text("".join(line for line in manifest.read_text().splitlines(True) if "images.tar.gz" not in line))
        (out / "images.tar.gz").unlink()
        expect = ""
    log.write_text("")
    args = ["--expect", expect] if expect else []
    proc = run_script(LOAD, *args, str(out), env=env)
    assert proc.returncode != 0, proc.stdout
    assert "FAIL" in proc.stderr
    assert "load" not in log.read_text().splitlines(), "nothing may be loaded from a refused bundle"


def test_load_protects_an_existing_model_volume() -> None:
    text = LOAD.read_text()
    assert "--network none" in text and "--force-models" in text and "is not empty" in text


# --------------------------------------------------------------------------
# Quickstart
# --------------------------------------------------------------------------


def test_quickstart_keeps_secrets_private() -> None:
    text = QUICKSTART.read_text()
    assert 'chmod 700 "$QS_DIR"' in text and 'install -m 600 /dev/null "$ENV_FILE"' in text
    assert 'install -m 600 /dev/null "$CREDS"' in text
    assert "scripts/generate_secrets.py --append" in text
    # The admin password reaches the CLI on stdin and is written only to the credentials file.
    assert "--password-stdin" in text and "--password " not in text
    uses = [line for line in text.splitlines() if "$ADMIN_PASSWORD" in line]
    assert len(uses) == 2 and any("printf '%s\\n' \"$ADMIN_PASSWORD\" |" in u for u in uses)
    assert any('echo "PASSWORD=$ADMIN_PASSWORD"' in u for u in uses)
    assert "docker/docker-compose.prod.yml" in text and "--wait" in text
    assert "down -v" in text and "--profile ollama-pull" in text
    assert "scripts/demo/seed_demo.py" in text and "--started-at" in text


def test_quickstart_state_is_ignored_by_git() -> None:
    ignored = (REPO_ROOT / ".gitignore").read_text().splitlines()
    assert ".quickstart/" in ignored and "lg-sotf-airgap-*/" in ignored


def test_make_targets() -> None:
    text = (REPO_ROOT / "Makefile").read_text()
    assert "quickstart: ##" in text and "scripts/quickstart.sh $(if $(OLLAMA),--ollama $(OLLAMA),)" in text
    assert "quickstart-down: ##" in text


def test_seed_script_needs_only_the_standard_library() -> None:
    tree = ast.parse(SEED.read_text())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
    }
    import sys

    assert {m.split(".")[0] for m in modules} <= set(sys.stdlib_module_names) | {"__future__"}
    assert os.access(SEED, os.X_OK)


# --------------------------------------------------------------------------
# Demo alerts
# --------------------------------------------------------------------------

RESERVED_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
RESERVED_SUFFIXES = (".test", "example.com", "example.net", "example.org")


def demo_alerts() -> List[Dict[str, Any]]:
    data = json.loads(ALERTS.read_text())
    assert "synthetic" in data["_synthetic"].lower() or "Synthetic" in data["_synthetic"]
    alerts: List[Dict[str, Any]] = data["alerts"]
    return alerts


def test_demo_alerts_are_valid_canonical_events() -> None:
    alerts = demo_alerts()
    assert 14 <= len(alerts) <= 20
    ids = [a["source_alert_id"] for a in alerts]
    assert len(set(ids)) == len(ids)
    ctx = NormalizeContext(source_id="api", source_type="canonical", now=datetime(2026, 10, 1, tzinfo=UTC))
    for alert in alerts:
        canonical = CanonicalNormalizer().normalize(alert, ctx)
        assert canonical.title == alert["title"]


def test_demo_alerts_use_only_reserved_names_and_addresses() -> None:
    for alert in demo_alerts():
        entities = alert.get("entities", {})
        for ip in entities.get("ips", []):
            assert any(ipaddress.ip_address(ip) in net for net in RESERVED_NETS), ip
        for domain in entities.get("domains", []):
            assert domain.endswith(RESERVED_SUFFIXES), domain
        for value in entities.get("emails", []) + [u for u in entities.get("users", []) if "@" in u]:
            assert value.split("@", 1)[1].endswith(RESERVED_SUFFIXES), value
        for url in entities.get("urls", []):
            host = re.sub(r"^https?://([^/:]+).*$", r"\1", url)
            assert host.endswith(RESERVED_SUFFIXES), url
        for host in entities.get("hosts", []):
            assert "." not in host or host.endswith(RESERVED_SUFFIXES), host
        text = json.dumps(alert)
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
            if all(0 <= int(p) <= 255 for p in ip.split(".")) and not ip.startswith("1.419"):
                assert any(ipaddress.ip_address(ip) in net for net in RESERVED_NETS), ip


def test_demo_alerts_cover_the_scenarios() -> None:
    text = json.dumps(demo_alerts()).lower()
    for needle in (
        "encodedcommand", "lsass", "impossible travel", "mfa", "brute force", "outsideaws",
        "bucketblockpublicaccessdisabled", "beacon", "phishing", "definitions update", "patch compliance",
    ):
        assert needle in text, needle
    categories = {a.get("category") for a in demo_alerts()}
    assert {"identity", "cloud", "phishing", "command_and_control", "maintenance"} <= categories


# --------------------------------------------------------------------------
# seed_demo.py against a stub API
# --------------------------------------------------------------------------


def load_seed() -> ModuleType:
    spec = importlib.util.spec_from_file_location("seed_demo", SEED)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shifted_moves_timestamps_and_suffixes_ids() -> None:
    seed = load_seed()
    now = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    alerts = demo_alerts()
    out = seed.shifted(alerts, now, "qs1")
    stamps = [datetime.fromisoformat(a["occurred_at"].replace("Z", "+00:00")) for a in out]
    assert max(stamps) == now - timedelta(minutes=2)
    original = [datetime.fromisoformat(a["occurred_at"].replace("Z", "+00:00")) for a in alerts]
    assert [s - original[0] for s in stamps][1] == original[1] - original[0] + (stamps[0] - original[0])
    assert all(a["source_alert_id"].endswith("-qs1") for a in out)
    assert alerts[0]["source_alert_id"] == "demo-edr-001", "the input is not modified"


class _FakeApi(BaseHTTPRequestHandler):
    state: Dict[str, Any] = {}

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, status: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> Any:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"null")

    def do_GET(self) -> None:
        s = self.state
        if self.path == "/readyz":
            self._send(200, {"status": "ok"})
        elif self.path.startswith("/api/v1/alerts"):
            assert self.headers["Authorization"] == "Bearer access-1"
            s["polls"] += 1
            status = "queued" if s["polls"] < 2 else "closed"
            items = [
                {"id": i, "status": status, "severity": "high", "title": f"alert {i}", "disposition": "benign"}
                for i in s["ids"]
            ]
            self._send(200, {"items": items, "next_cursor": None})
        else:
            self._send(404, {})

    def do_POST(self) -> None:
        s = self.state
        body = self._body()
        if self.path == "/api/v1/auth/login":
            s["login"] = body
            self._send(200, {"access_token": "access-1"})
        elif self.path == "/api/v1/api-keys":
            assert body["scopes"] == ["ingest"]
            self._send(201, {"key": s["key"], "prefix": "lgs_x"})
        elif self.path == "/api/v1/ingest/alerts":
            assert self.headers["X-API-Key"] == s["key"]
            s["posted"] = body["alerts"]
            s["ids"] = [f"a{n}" for n in range(len(body["alerts"]))]
            items = [{"alert_id": i, "status": "inserted"} for i in s["ids"]]
            self._send(202, {"items": items, "inserted": len(items), "rejected": 0})
        else:
            self._send(404, {})


def test_seed_flow_against_a_stub_api(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    seed = load_seed()
    password = "pw-" + "z" * 16
    key = "lgs_" + "k" * 24
    _FakeApi.state = {"polls": 0, "key": key}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        creds = tmp_path / "creds"
        creds.write_text(f"# comment\nTENANT=demo\nEMAIL=admin@demo.example.com\nPASSWORD={password}\n")
        key_file = tmp_path / "key"
        timing = tmp_path / "timing.json"
        rc = seed.main(
            [
                "--base-url", f"http://127.0.0.1:{server.server_port}",
                "--credentials", str(creds), "--api-key-file", str(key_file),
                "--timing-out", str(timing), "--started-at", "1", "--timeout", "30", "--provider", "fake",
            ]
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    out = capsys.readouterr().out
    assert rc == 0, out
    assert _FakeApi.state["login"] == {"email": "admin@demo.example.com", "password": password, "tenant": "demo"}
    assert len(_FakeApi.state["posted"]) == len(demo_alerts())
    assert key_file.read_text().strip() == key and stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert password not in out and key not in out
    result = json.loads(timing.read_text())
    assert result["alerts"] == result["triaged"] == len(demo_alerts()) and result["failed"] == 0
    assert result["first_verdict_after_ingest_s"] is not None and result["first_verdict_after_start_s"] > 0
    assert "time to first verdict" in out
