"""Packaging and hardening checks for the analyst web app (src/lg_front).

Cheap, file-level checks: the container runs as a non-root user, nginx sends
the security headers on every static response, the runtime configuration is
generated from validated environment values, and the browser code never
persists credentials. The Helm checks run when ``helm`` is installed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

import pytest
import yaml

from tests.deploy._support import DOCKER_DIR, REPO_ROOT, find, render, requires_helm, run_helm_template

FRONT = REPO_ROOT / "src" / "lg_front"
DOCKERFILE = FRONT / "Dockerfile"
NGINX_CONF = FRONT / "docker" / "nginx.conf"
ENTRYPOINT = FRONT / "docker" / "entrypoint.sh"
SRC = FRONT / "src"


def _code(path: Path) -> str:
    """Source text without comments (documentation may name what the code avoids)."""
    text = re.sub(r"/\*.*?\*/", "", path.read_text(), flags=re.DOTALL)
    return re.sub(r"(^|[^:])//.*$", r"\1", text, flags=re.MULTILINE)


def _source_files() -> List[Path]:
    return [
        p
        for p in SRC.rglob("*")
        if p.suffix in {".ts", ".tsx", ".js", ".jsx"} and ".test." not in p.name and "test" not in p.parts
    ]


# --------------------------------------------------------------------------- Dockerfile


def _stages(text: str) -> List[str]:
    return re.findall(r"^FROM\s+(\S+)(?:\s+AS\s+\S+)?", text, flags=re.MULTILINE | re.IGNORECASE)


def test_dockerfile_is_multi_stage_with_overridable_base_images() -> None:
    text = DOCKERFILE.read_text()
    assert re.search(r"^ARG NODE_IMAGE=node:22", text, re.MULTILINE)
    assert re.search(r"^ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:", text, re.MULTILINE)
    stages = _stages(text)
    assert stages == ["${NODE_IMAGE}", "${NGINX_IMAGE}"]
    assert "COPY --from=build /app/dist /usr/share/nginx/html" in text
    # Reproducible install from the lockfile, with no install scripts.
    assert "npm ci --ignore-scripts" in text
    assert (FRONT / "package-lock.json").is_file()


def test_runtime_stage_runs_as_non_root() -> None:
    text = DOCKERFILE.read_text()
    runtime = text[text.index("FROM ${NGINX_IMAGE}") :]
    users = re.findall(r"^USER\s+(\S+)", runtime, re.MULTILINE)
    assert users, "the runtime stage must set USER"
    final = users[-1]
    assert final not in {"root", "0", "0:0"}
    assert final.split(":")[0].isdigit(), "a numeric uid lets Kubernetes verify runAsNonRoot"
    assert "EXPOSE 8080" in runtime
    assert 'ENTRYPOINT ["/usr/local/bin/lg-sotf-frontend-entrypoint"]' in runtime


def test_build_ca_is_a_secret_mount_never_a_layer() -> None:
    text = DOCKERFILE.read_text()
    assert "--mount=type=secret,id=build_ca,required=false" in text
    assert not re.search(r"^(COPY|ADD)\s+.*\.(crt|pem)\b", text, re.MULTILINE)
    assert not re.search(r"^ENV\s+.*(SECRET|TOKEN|PASSWORD|KEY)=", text, re.MULTILINE | re.IGNORECASE)


def test_build_refuses_inline_scripts_in_index_html() -> None:
    text = DOCKERFILE.read_text()
    assert "! grep -Eq '<script>|<script[^>]*>[^<]' dist/index.html" in text
    index = (FRONT / "index.html").read_text()
    for tag in re.findall(r"<script\b[^>]*>(.*?)</script>", index, flags=re.DOTALL):
        assert tag.strip() == "", "index.html must not contain inline scripts (CSP script-src 'self')"
    assert 'src="/config.js"' in index


# --------------------------------------------------------------------------- nginx


def _locations(conf: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in re.finditer(r"location\s+([=~^]*\s*\S+)\s*\{(.*?)\n\s*\}", conf, flags=re.DOTALL):
        out[m.group(1).strip()] = m.group(2)
    return out


def test_nginx_writes_only_under_tmp_and_hides_version() -> None:
    conf = NGINX_CONF.read_text()
    assert "pid /tmp/nginx.pid;" in conf
    for key in ("client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path", "uwsgi_temp_path", "scgi_temp_path"):
        assert re.search(rf"{key}\s+/tmp/", conf), key
    assert "server_tokens off;" in conf
    assert re.search(r"listen\s+8080;", conf)
    # Query strings (OIDC authorization codes) must not reach the access log.
    log_format = conf[conf.index("log_format") : conf.index(";", conf.index("log_format"))]
    assert "$request_uri" not in log_format and "$args" not in log_format and "$query_string" not in log_format


def test_nginx_sends_security_headers_on_every_static_response() -> None:
    conf = NGINX_CONF.read_text()
    locations = _locations(conf)
    for loc in ("= /config.js", "/assets/", "= /favicon.svg", "/"):
        assert loc in locations, loc
        # add_header in a location replaces inherited ones, so each includes the set.
        assert "include /tmp/lg-sotf/headers.conf;" in locations[loc], loc


def test_nginx_caching_and_spa_fallback() -> None:
    locations = _locations(NGINX_CONF.read_text())
    assert 'Cache-Control "public, max-age=31536000, immutable"' in locations["/assets/"]
    assert "try_files $uri =404;" in locations["/assets/"], "missing hashed assets must 404, not serve index.html"
    assert 'Cache-Control "no-store"' in locations["= /config.js"]
    assert "try_files $uri /index.html;" in locations["/"]
    assert 'Cache-Control "no-cache"' in locations["/"]
    conf = NGINX_CONF.read_text()
    assert "gzip on;" in conf and "application/javascript" in conf


# --------------------------------------------------------------------------- entrypoint


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


@needs_sh
def test_entrypoint_generates_same_origin_config_and_strict_csp(tmp_path: Path) -> None:
    proc = _run_entrypoint(tmp_path, {})
    assert proc.returncode == 0, proc.stderr
    config = (tmp_path / "out" / "config.js").read_text()
    assert '"apiBaseUrl":""' in config and '"oidc":null' in config
    headers = (tmp_path / "out" / "headers.conf").read_text()
    csp = re.search(r'Content-Security-Policy "([^"]+)"', headers)
    assert csp, headers
    policy = csp.group(1)
    assert "default-src 'none'" in policy
    assert "script-src 'self';" in policy
    assert "frame-ancestors 'none'" in policy
    assert "object-src 'none'" in policy
    assert "connect-src 'self';" in policy
    assert "unsafe-inline" not in policy and "unsafe-eval" not in policy
    for header in (
        'X-Content-Type-Options "nosniff"',
        'X-Frame-Options "DENY"',
        'Referrer-Policy "no-referrer"',
        "Permissions-Policy",
    ):
        assert header in headers, header
    assert "Strict-Transport-Security" not in headers
    assert (tmp_path / "out" / "api-proxy.conf").read_text() == ""


@needs_sh
def test_entrypoint_allows_configured_api_ws_and_idp_origins(tmp_path: Path) -> None:
    proc = _run_entrypoint(
        tmp_path,
        {
            "LG_SOTF_API_BASE_URL": "https://api.soc.example.com",
            "LG_SOTF_OIDC_ISSUER": "https://idp.example.com/realms/soc",
            "LG_SOTF_OIDC_CLIENT_ID": "lg-sotf-web",
            "LG_SOTF_OIDC_TOKEN_ENDPOINT": "https://tokens.example.net/oauth2/token",
            "LG_SOTF_HSTS_MAX_AGE": "31536000",
            "LG_SOTF_API_UPSTREAM": "http://api:8000",
        },
    )
    assert proc.returncode == 0, proc.stderr
    headers = (tmp_path / "out" / "headers.conf").read_text()
    connect = re.search(r"connect-src ([^;]+);", headers)
    assert connect is not None
    assert connect.group(1).split() == [
        "'self'",
        "https://api.soc.example.com",
        "wss://api.soc.example.com",
        "https://idp.example.com",
        "https://tokens.example.net",
    ]
    assert 'Strict-Transport-Security "max-age=31536000; includeSubDomains"' in headers
    config = (tmp_path / "out" / "config.js").read_text()
    assert '"issuer":"https://idp.example.com/realms/soc"' in config and '"clientId":"lg-sotf-web"' in config
    proxy = (tmp_path / "out" / "api-proxy.conf").read_text()
    assert "location /api/ {" in proxy and "proxy_pass http://api:8000;" in proxy
    assert "proxy_set_header Upgrade $http_upgrade;" in proxy


@needs_sh
@pytest.mark.parametrize(
    "name,value",
    [
        ("LG_SOTF_API_BASE_URL", 'https://x.example/"});alert(1)//'),
        ("LG_SOTF_API_BASE_URL", "javascript:alert(1)"),
        ("LG_SOTF_API_BASE_URL", "https://user:pw@api.example.com"),
        ("LG_SOTF_WS_URL", "https://not-a-socket.example"),
        ("LG_SOTF_API_UPSTREAM", "http://api:8000; return 200"),
        ("LG_SOTF_OIDC_CLIENT_ID", 'web"}'),
        ("LG_SOTF_CSP_CONNECT_SRC", "https://ok.example 'unsafe-inline'"),
        ("LG_SOTF_HSTS_MAX_AGE", "1; preload"),
    ],
)
def test_entrypoint_refuses_values_that_could_inject_config(tmp_path: Path, name: str, value: str) -> None:
    proc = _run_entrypoint(tmp_path, {name: value})
    assert proc.returncode == 64, (proc.stdout, proc.stderr)
    assert name in proc.stderr
    assert not (tmp_path / "out" / "config.js").exists()


# --------------------------------------------------------------------------- browser code


def test_no_token_persistence_in_browser_storage() -> None:
    files = _source_files()
    assert files, "frontend sources not found"
    offenders = [str(p.relative_to(FRONT)) for p in files if re.search(r"\blocalStorage\b", _code(p))]
    assert offenders == [], f"localStorage must not be used: {offenders}"
    session_users = [p for p in files if "sessionStorage" in _code(p)]
    # Only the OIDC redirect keeps its transient PKCE material there.
    assert [p.name for p in session_users] == ["oidc.ts"]
    oidc = (SRC / "auth" / "oidc.ts").read_text()
    stored = re.findall(r"setItem\(([^,]+),", oidc)
    assert stored == ["PENDING_KEY"]
    pending = re.search(r"interface Pending \{(.*?)\}", oidc, flags=re.DOTALL)
    assert pending is not None and "token" not in pending.group(1).lower()
    for p in files:
        assert "document.cookie" not in _code(p), p


def test_lint_config_forbids_local_storage() -> None:
    eslint = (FRONT / "eslint.config.js").read_text()
    assert "name: 'localStorage'" in eslint
    assert "property: 'localStorage'" in eslint


def test_access_token_lives_in_a_private_field() -> None:
    store = _code(SRC / "auth" / "store.ts")
    assert "#token: string | null = null;" in store
    assert "#oidcRefreshToken: string | null = null;" in store
    # Only the private field is ever assigned; nothing exposes it as a property.
    assert not re.search(r"this\.(token|accessToken|refreshToken)\b", store)


def test_package_scripts_and_no_create_react_app() -> None:
    import json

    pkg = json.loads((FRONT / "package.json").read_text())
    for script in ("build", "lint", "test:ci", "typecheck"):
        assert script in pkg["scripts"], script
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    assert "react-scripts" not in deps
    assert deps["react"].startswith("^18")
    assert "vite" in deps and "vitest" in deps
    default_config = (FRONT / "public" / "config.js").read_text()
    assert "window.__LG_SOTF_CONFIG__" in default_config
    assert not re.search(r"(secret|password|api[_-]?key)\s*:", default_config, re.IGNORECASE)


# --------------------------------------------------------------------------- compose


def test_compose_frontend_is_hardened_and_proxies_the_api() -> None:
    compose = yaml.safe_load((DOCKER_DIR / "docker-compose.yml").read_text())
    fe = compose["services"]["frontend"]
    assert fe["read_only"] is True
    assert fe["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in fe["security_opt"]
    assert fe["tmpfs"] == ["/tmp:size=16m,mode=1777"]
    assert fe["build"]["secrets"] == ["build_ca"]
    assert set(fe["build"]["args"]) == {"NODE_IMAGE", "NGINX_IMAGE"}
    env = fe["environment"]
    assert env["LG_SOTF_API_UPSTREAM"] == "http://api:8000"
    assert not any(re.search(r"SECRET|PASSWORD|TOKEN_?KEY|API_KEY", k) for k in env), env
    assert "healthz" in " ".join(fe["healthcheck"]["test"])
    assert all(p.startswith("${FRONTEND_BIND:-127.0.0.1}:") for p in fe["ports"])


# --------------------------------------------------------------------------- helm


@requires_helm
def test_helm_frontend_enabled_by_default_without_secrets() -> None:
    manifests = render()
    deps = find(manifests, "Deployment", "-frontend")
    assert len(deps) == 1
    pod = deps[0]["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert "envFrom" not in c
    assert all("valueFrom" not in e for e in c["env"]), "the static UI gets no secret references"
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["allowPrivilegeEscalation"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert c["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert c["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert any(v["mountPath"] == "/tmp" for v in c["volumeMounts"])
    env = {e["name"]: e["value"] for e in c["env"]}
    assert env["LG_SOTF_API_BASE_URL"] == "" and env["LG_SOTF_OIDC_ISSUER"] == ""
    assert find(manifests, "Service", "-frontend")


@requires_helm
def test_helm_frontend_runtime_config_values() -> None:
    manifests = render(
        "--set",
        "frontend.config.apiBaseUrl=https://api.soc.example.com",
        "--set",
        "frontend.config.oidc.issuer=https://idp.example.com",
        "--set",
        "frontend.config.oidc.clientId=lg-sotf-web",
        "--set",
        "frontend.config.extraConnectSrc={https://a.example,wss://b.example}",
    )
    c = find(manifests, "Deployment", "-frontend")[0]["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e["value"] for e in c["env"]}
    assert env["LG_SOTF_API_BASE_URL"] == "https://api.soc.example.com"
    assert env["LG_SOTF_OIDC_CLIENT_ID"] == "lg-sotf-web"
    assert env["LG_SOTF_CSP_CONNECT_SRC"] == "https://a.example wss://b.example"


@requires_helm
def test_helm_schema_rejects_injectable_frontend_values() -> None:
    proc = run_helm_template("--set", "frontend.config.apiBaseUrl=javascript:alert(1)", check=False)
    assert proc.returncode != 0
    assert "apiBaseUrl" in proc.stderr


@requires_helm
def test_helm_frontend_can_be_disabled() -> None:
    manifests = render("--set", "frontend.enabled=false")
    assert not find(manifests, "Deployment", "-frontend")
