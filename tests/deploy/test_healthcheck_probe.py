"""docker/healthcheck.py: role detection from PID 1's argv and the probe result."""

from __future__ import annotations

import importlib.util
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import ModuleType
from typing import Iterator, Tuple

import pytest

from tests.deploy._support import DOCKER_DIR


def load_probe() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lg_sotf_healthcheck", DOCKER_DIR / "healthcheck.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load_probe()


@pytest.fixture(autouse=True)
def _no_probe_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HEALTHCHECK_URL", raising=False)
    monkeypatch.delenv("LG_SOTF_API__PORT", raising=False)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["dumb-init", "--", "lg-sotf", "api"], "http://127.0.0.1:8000/healthz"),
        (["dumb-init", "--", "/opt/venv/bin/lg-sotf", "api", "--port", "9000"], "http://127.0.0.1:9000/healthz"),
        (["dumb-init", "--", "lg-sotf", "api", "--port=9001"], "http://127.0.0.1:9001/healthz"),
        (["dumb-init", "--", "lg-sotf", "worker"], "http://127.0.0.1:9100/healthz"),
        (["dumb-init", "--", "lg-sotf", "worker", "--metrics-port", "9200"], "http://127.0.0.1:9200/healthz"),
        (["dumb-init", "--", "lg-sotf", "scheduler", "--metrics-port", "9300"], "http://127.0.0.1:9300/healthz"),
        (["dumb-init", "--", "lg-sotf", "migrate"], None),
        (["dumb-init", "--", "lg-sotf", "dlq", "list"], None),
        (["dumb-init", "--", "lg-sotf"], None),
        (["python", "/usr/local/lib/lg-sotf/healthcheck.py"], None),
        ([], None),
    ],
)
def test_role_url(argv: list, expected: object) -> None:
    assert probe.role_url(argv) == expected


def test_api_port_falls_back_to_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_SOTF_API__PORT", "8080")
    assert probe.role_url(["dumb-init", "--", "lg-sotf", "api"]) == "http://127.0.0.1:8080/healthz"
    # An explicit flag wins over the environment.
    assert probe.role_url(["lg-sotf", "api", "--port", "8081"]) == "http://127.0.0.1:8081/healthz"


class _Handler(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.send_response(self.server.status)  # type: ignore[attr-defined]
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture
def server() -> Iterator[Tuple[HTTPServer, str]]:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.status = 200  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd, f"http://127.0.0.1:{httpd.server_address[1]}/healthz"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_main_healthy_on_200(server: Tuple[HTTPServer, str], monkeypatch: pytest.MonkeyPatch) -> None:
    _, url = server
    monkeypatch.setenv("HEALTHCHECK_URL", url)
    assert probe.main() == 0


def test_main_unhealthy_on_503(server: Tuple[HTTPServer, str], monkeypatch: pytest.MonkeyPatch) -> None:
    httpd, url = server
    httpd.status = 503  # type: ignore[attr-defined]
    monkeypatch.setenv("HEALTHCHECK_URL", url)
    assert probe.main() == 1


def test_main_unhealthy_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    httpd.server_close()
    monkeypatch.setenv("HEALTHCHECK_URL", f"http://127.0.0.1:{port}/healthz")
    assert probe.main() == 1


def test_main_healthy_for_one_shot_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe, "pid1_argv", lambda: ["dumb-init", "--", "lg-sotf", "migrate"])
    assert probe.main() == 0
