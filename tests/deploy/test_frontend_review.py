"""Regression checks for the web app's review findings (FE-2, FE-3, FE-6).

* FE-2: the WebSocket carries the access token in its query string, so the
  generated nginx proxy must not print that request line in its error log.
* FE-3: the chart warns when the Ingress host is missing from
  ``settings.api.cors_origins`` (the API refuses the UI's WebSocket then).
* FE-6: every OIDC override the container understands can be set through
  Helm and compose.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Set

import pytest
import yaml

from tests.deploy._support import (
    CHART_DIR,
    DOCKER_DIR,
    REPO_ROOT,
    find,
    helm_binary,
    render,
    requires_helm,
    run_helm_template,
)

FRONT = REPO_ROOT / "src" / "lg_front"
NGINX_CONF = FRONT / "docker" / "nginx.conf"
ENTRYPOINT = FRONT / "docker" / "entrypoint.sh"

needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")


def _run_entrypoint(tmp_path: Path, env: Dict[str, str]) -> subprocess.CompletedProcess[str]:
    full = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LG_SOTF_RUNTIME_DIR": str(tmp_path / "out"),
        "LG_SOTF_NGINX_TMP": str(tmp_path / "nginx"),
        **env,
    }
    sh = shutil.which("sh")
    assert sh is not None
    return subprocess.run(  # noqa: S603 - fixed argv, no shell string
        [sh, str(ENTRYPOINT), "true"], env=full, capture_output=True, text=True, timeout=30, check=False
    )


def _blocks(conf: str) -> Dict[str, str]:
    """Top-level ``location`` blocks of a generated snippet, keyed by their matcher."""
    return {
        m.group(1).strip(): m.group(2) for m in re.finditer(r"location\s+([^{]+)\{(.*?)\n\}", conf, flags=re.DOTALL)
    }


# --------------------------------------------------------------------------- FE-2


@needs_sh
def test_websocket_location_does_not_log_the_token_bearing_request_line(tmp_path: Path) -> None:
    proc = _run_entrypoint(tmp_path, {"LG_SOTF_API_UPSTREAM": "http://api:8000"})
    assert proc.returncode == 0, proc.stderr
    blocks = _blocks((tmp_path / "out" / "api-proxy.conf").read_text())
    assert set(blocks) == {"= /api/v1/ws", "/api/"}
    ws = blocks["= /api/v1/ws"]
    # connect()/timeout failures are logged at "error" and would print "GET /api/v1/ws?token=...".
    levels = re.findall(r"error_log\s+\S+\s+(\w+);", ws)
    assert levels == ["crit"], ws
    assert "proxy_pass http://api:8000;" in ws
    assert "proxy_set_header Upgrade $http_upgrade;" in ws
    assert "proxy_set_header Connection $connection_upgrade;" in ws
    assert "proxy_read_timeout 3600s;" in ws
    # REST keeps normal error logging.
    assert "error_log" not in blocks["/api/"]


def test_access_log_never_records_query_strings() -> None:
    conf = NGINX_CONF.read_text()
    formats = re.findall(r"log_format\s+\w+.*?;", conf, flags=re.DOTALL)
    assert formats
    for fmt in formats:
        for variable in ("$request_uri", "$args", "$query_string", "$request ", '$request"', "$arg_"):
            assert variable not in fmt, f"{variable} would log the WebSocket token"


@needs_sh
@pytest.mark.parametrize("upstream", ["http://api:8000/", "http://api:8000/prefix", "http://api:8000/api/"])
def test_api_upstream_is_origin_only(tmp_path: Path, upstream: str) -> None:
    proc = _run_entrypoint(tmp_path, {"LG_SOTF_API_UPSTREAM": upstream})
    if upstream == "http://api:8000/":
        # A trailing slash is tolerated and dropped (a URI part would make nginx strip /api/).
        assert proc.returncode == 0, proc.stderr
        assert "proxy_pass http://api:8000;" in (tmp_path / "out" / "api-proxy.conf").read_text()
    else:
        assert proc.returncode == 64
        assert "LG_SOTF_API_UPSTREAM" in proc.stderr


def test_docs_do_not_claim_the_token_never_appears_in_urls() -> None:
    readme = (FRONT / "README.md").read_text()
    assert "/api/v1/ws?token=" in readme
    store = (FRONT / "src" / "auth" / "store.ts").read_text()
    assert "sessionStorage, cookies or the URL" not in store


# --------------------------------------------------------------------------- FE-6


def _entrypoint_oidc_vars() -> Set[str]:
    return set(re.findall(r"\$\{(LG_SOTF_OIDC_[A-Z_]+):-", ENTRYPOINT.read_text()))


def test_compose_passes_every_oidc_setting_the_container_reads() -> None:
    expected = _entrypoint_oidc_vars()
    assert {
        "LG_SOTF_OIDC_ISSUER",
        "LG_SOTF_OIDC_END_SESSION_ENDPOINT",
        "LG_SOTF_OIDC_AUTHORIZATION_ENDPOINT",
    } <= expected
    env = yaml.safe_load((DOCKER_DIR / "docker-compose.yml").read_text())["services"]["frontend"]["environment"]
    assert expected <= set(env), expected - set(env)
    assert "LG_SOTF_CSP_CONNECT_SRC" in env


@requires_helm
def test_helm_passes_every_oidc_setting_the_container_reads() -> None:
    manifests = render(
        "--set", "frontend.config.oidc.issuer=https://tenant.auth0.example/",
        "--set", "frontend.config.oidc.clientId=web",
        "--set", "frontend.config.oidc.authorizationEndpoint=https://tenant.auth0.example/authorize",
        "--set", "frontend.config.oidc.endSessionEndpoint=https://tenant.auth0.example/v2/logout",
    )  # fmt: skip
    c = find(manifests, "Deployment", "-frontend")[0]["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e["value"] for e in c["env"]}
    assert _entrypoint_oidc_vars() <= set(env), _entrypoint_oidc_vars() - set(env)
    # The issuer is passed through unchanged (trailing slash included).
    assert env["LG_SOTF_OIDC_ISSUER"] == "https://tenant.auth0.example/"
    assert env["LG_SOTF_OIDC_AUTHORIZATION_ENDPOINT"] == "https://tenant.auth0.example/authorize"
    assert env["LG_SOTF_OIDC_END_SESSION_ENDPOINT"] == "https://tenant.auth0.example/v2/logout"


@requires_helm
@pytest.mark.parametrize("key", ["authorizationEndpoint", "endSessionEndpoint"])
def test_helm_schema_validates_oidc_endpoint_overrides(key: str) -> None:
    proc = run_helm_template("--set", f"frontend.config.oidc.{key}=javascript:alert(1)", check=False)
    assert proc.returncode != 0
    assert key in proc.stderr


# --------------------------------------------------------------------------- FE-3


def _render_notes(tmp_path: Path, *args: str) -> str:
    """Render templates/NOTES.txt (``helm template`` skips it) through a copy of the chart."""
    chart = tmp_path / "chart"
    shutil.copytree(CHART_DIR, chart)
    notes = (chart / "templates" / "NOTES.txt").read_text()
    (chart / "templates" / "_notes_render.tpl").write_text('{{- define "test.notes" }}' + notes + "{{- end }}")
    (chart / "templates" / "notes-render.yaml").write_text('notes: {{ include "test.notes" . | toJson }}\n')
    helm = helm_binary()
    assert helm is not None
    out = subprocess.run(  # noqa: S603 - fixed argv
        [helm, "template", "t", str(chart), "--show-only", "templates/notes-render.yaml", *args],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    return str(yaml.safe_load(out)["notes"])


@requires_helm
def test_notes_warn_when_the_ui_origin_is_not_an_allowed_websocket_origin(tmp_path: Path) -> None:
    notes = _render_notes(tmp_path, "--set", "ingress.enabled=true", "--set", "ingress.hosts={soc.example.com}")
    assert "WARNING: http://soc.example.com is not in settings.api.cors_origins" in notes
    assert "--set 'settings.api.cors_origins={http://soc.example.com}'" in notes


@requires_helm
def test_notes_are_quiet_when_the_origin_is_allowed(tmp_path: Path) -> None:
    args: List[str] = [
        "--set", "ingress.enabled=true",
        "--set", "ingress.hosts={soc.example.com}",
        "--set", "ingress.tls[0].secretName=tls",
        "--set", "ingress.tls[0].hosts={soc.example.com}",
        "--set", "settings.api.cors_origins={https://soc.example.com/}",
    ]  # fmt: skip
    notes = _render_notes(tmp_path, *args)
    assert "cors_origins" not in notes
    # And no warning without the frontend.
    assert "cors_origins" not in _render_notes(
        tmp_path / "b", "--set", "ingress.enabled=true", "--set", "frontend.enabled=false"
    )
