"""deploy/vm/deploy.sh --ingress funnel, driven against a stub `docker` on PATH.

The stub records every docker invocation and answers the calls deploy.sh
makes (compose, volumes, `tailscale status` in the ts container), so these
tests cover argument validation, the first-deploy auth key rule, what is
rendered, that secrets never reach the output, and each Tailscale diagnosis,
without a Docker daemon. A real deploy through the ts network namespace is
described in docs/self-hosting-pc.md.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from tests.deploy._support import REPO_ROOT

DEPLOY_SH = REPO_ROOT / "deploy" / "vm" / "deploy.sh"
DOMAIN = "soc-dev.tail1234.ts.net"
APP = "ghcr.io/gapilongo/lg-sotf@sha256:" + "a" * 64
FRONTEND = "ghcr.io/gapilongo/lg-sotf-frontend@sha256:" + "b" * 64
# Assembled at run time: a key-shaped literal would trip secret scanners.
FAKE_AUTHKEY = "-".join(["tskey", "auth", "kFAKE" + "x" * 11, "y" * 32])
LOGIN_URL = "https://login.tailscale.com/a/" + "f" * 12

_FAKE_SECRET_NAMES = (
    "POSTGRES_SUPERUSER_PASSWORD",
    "LGSOTF_OWNER_PASSWORD",
    "LGSOTF_APP_PASSWORD",
    "LG_SOTF_AUTH__JWT_SECRET",
    "LG_SOTF_SECURITY__ENCRYPTION_KEYS",
    "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY",
    "LG_SOTF_API__METRICS_TOKEN",
    "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD",
)
# Distinct, obviously fake values built at runtime (no credential-shaped literals in source).
SECRETS = {name: "test-suite-only-" + name.lower().replace("_", "-") + "-" + "x" * 12 for name in _FAKE_SECRET_NAMES}
SECRETS["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"

STUB = r"""#!/usr/bin/env bash
# Stub docker for deploy.sh tests. Behaviour comes from files in $STUB_DIR.
all="$*"
printf '%s\n' "${all//$'\n'/\\n}" >> "$STUB_DIR/calls.log"
args=" $* "
case "$1" in
  compose)
    case "$args" in
      *" version "*) exit 0 ;;
      *" config -q "*) exit "$(cat "$STUB_DIR/config_rc" 2>/dev/null || echo 0)" ;;
      *" exec -T api python "*) cat "$STUB_DIR/pending" 2>/dev/null; exit 0 ;;
      *" ps -q api "*) echo api-cid; exit 0 ;;
      *" logs "*) cat "$STUB_DIR/logs" 2>/dev/null; exit 0 ;;
      *) exit 0 ;;
    esac ;;
  volume)
    name="${*: -1}"
    case "$2" in
      inspect) [ -f "$STUB_DIR/volume-$name" ] ;;
      create) touch "$STUB_DIR/volume-$name"; echo "$name" ;;
    esac
    exit ;;
  inspect)
    cat "$STUB_DIR/api_image" 2>/dev/null; exit 0 ;;
  ps)
    [ ! -f "$STUB_DIR/ps_rc" ] || exit "$(cat "$STUB_DIR/ps_rc")"
    case "$args" in *"com.docker.compose.service=ts"*) cat "$STUB_DIR/ts_cid" 2>/dev/null ;; esac
    exit 0 ;;
  exec)
    case "$args" in
      *" status --json --peers=false "*) cat "$STUB_DIR/ts_status.json" 2>/dev/null || exit 1 ;;
      *" funnel status "*) cat "$STUB_DIR/funnel_status" 2>/dev/null ;;
    esac
    exit 0 ;;
  image)
    [ "$2" = inspect ] && exit 1
    exit 0 ;;
  logs)
    cat "$STUB_DIR/ts_logs" 2>/dev/null; exit 0 ;;
  network)
    exit 0 ;;
  info)
    exit "$(cat "$STUB_DIR/info_rc" 2>/dev/null || echo 0)" ;;
esac
exit 0
"""


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path / "root"
        self.stub = tmp_path / "stub"
        self.bin = tmp_path / "bin"
        self.stub.mkdir()
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(STUB)
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        (self.stub / "api_image").write_text(APP + "\n")

    def set(self, name: str, content: str) -> None:
        (self.stub / name).write_text(content)

    def volume_exists(self, name: str = "lgsotf-dev-tailscale") -> None:
        (self.stub / f"volume-{name}").touch()

    def calls(self) -> List[str]:
        log = self.stub / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def run(self, *args: str, values: Optional[Dict[str, str]] = None,
            env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess[str]:
        stdin = "".join(f"{k}={v}\n" for k, v in (values or {}).items())
        argv = ["bash", str(DEPLOY_SH), "--env", "dev", "--root", str(self.root), *args]
        if values is not None:
            argv.append("--secrets-stdin")
        return subprocess.run(  # noqa: S603 - fixed argv
            argv, input=stdin, capture_output=True, text=True, timeout=120,
            env={
                "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
                "HOME": str(self.root.parent),
                "STUB_DIR": str(self.stub),
                "LGSOTF_INGRESS_TIMEOUT": "0",
                "LGSOTF_EXTERNAL_TIMEOUT": "0",
                **(env or {}),
            },
        )

    def env_file(self) -> Dict[str, str]:
        out = {}
        for line in (self.root / "env" / "dev" / ".env").read_text().splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                out[key] = value.strip("'")
        return out


def funnel_deploy(*extra: str) -> List[str]:
    return ["--ingress", "funnel", "--domain", DOMAIN, "--app-image", APP, "--frontend-image", FRONTEND,
            "--version", "sha-1234567", *extra]


def ts_status(state: str = "Running", dns: str = DOMAIN + ".", caps: Optional[List[str]] = None) -> str:
    """`tailscale status --json --peers=false` as tailscaled prints it (Go MarshalIndent, two spaces)."""
    caps = ["https", "funnel"] if caps is None else caps
    return json.dumps({
        "Version": "1.102.5-t0000000-g0000000",
        "TUN": False,
        "BackendState": state,
        "HaveNodeKey": True,
        "AuthURL": LOGIN_URL if state == "NeedsLogin" else "",
        "TailscaleIPs": ["100.101.102.103"] if state == "Running" else None,
        "Self": {
            "ID": "nFAKE", "HostName": "soc-dev", "DNSName": dns if state == "Running" else "",
            "OS": "linux", "Tags": ["tag:soc"],
            "Capabilities": caps, "CapMap": {c: None for c in caps},
        },
        "Health": [],
        "MagicDNSSuffix": "tail1234.ts.net",
        "CertDomains": [DOMAIN] if "https" in caps else None,
        "Peer": None,
        "User": None,
    }, indent=2) + "\n"


def funnel_status(domain: str = DOMAIN) -> str:
    return (f"\n# Funnel on:\n#     - https://{domain}\n\n"
            f"https://{domain} (Funnel on)\n|-- / proxy http://127.0.0.1:8080\n\n")


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def assert_no_secret_printed(proc: subprocess.CompletedProcess[str], *extra: str) -> None:
    output = proc.stdout + proc.stderr
    for name, value in SECRETS.items():
        if name != "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL":
            assert value not in output, name
    for value in (FAKE_AUTHKEY, LOGIN_URL, *extra):
        assert value not in output


# --------------------------------------------------------------------------- arguments


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--ingress", "nginx", "--domain", DOMAIN], "--ingress must be caddy or funnel"),
        (["--ingress", "", "--domain", DOMAIN], "--ingress must be caddy or funnel"),
        (["--ingress", "funnel", "--domain", "soc-dev.example.org"], "<machine name>.<tailnet>.ts.net"),
        (["--ingress", "funnel", "--domain", "tail1234.ts.net"], "<machine name>.<tailnet>.ts.net"),
        (["--ingress", "funnel", "--domain", "a.soc-dev.tail1234.ts.net"], "<machine name>.<tailnet>.ts.net"),
        (["--ingress", "funnel", "--domain", "soc-dev.tail1234.ts.net.evil.org"], "<machine name>.<tailnet>.ts.net"),
        (["--ingress", "funnel", "--domain", DOMAIN, "--tls", "internal"], "apply to --ingress caddy only"),
        (["--ingress", "funnel", "--domain", DOMAIN, "--https-port", "8443"], "apply to --ingress caddy only"),
        # Let's Encrypt cannot issue for *.ts.net, and deploying a Funnel environment
        # as caddy would stop it as an ingress switch.
        (["--ingress", "caddy", "--domain", DOMAIN], "only --ingress funnel can serve *.ts.net"),
        (["--domain", DOMAIN.upper()], "only --ingress funnel can serve *.ts.net"),
        (["--domain", "ts.net"], "only --ingress funnel can serve *.ts.net"),
    ],
)
def test_funnel_arguments_are_validated_before_anything_is_touched(
    h: Harness, args: List[str], message: str
) -> None:
    proc = h.run(*args, "--app-image", APP, "--frontend-image", FRONTEND)
    assert proc.returncode == 2, proc.stderr
    assert message in proc.stderr
    assert not h.root.exists()
    assert h.calls() == []


def test_caddy_accepts_names_that_merely_end_in_ts_net_letters(h: Harness) -> None:
    h.set("config_rc", "1")
    proc = h.run("--domain", "soc-dev.shorts.net", "--app-image", APP, "--frontend-image", FRONTEND, values=SECRETS)
    assert proc.returncode == 1, proc.stderr
    assert "compose configuration is invalid" in proc.stdout


def test_uppercase_ts_net_names_are_accepted_and_lowered(h: Harness) -> None:
    h.set("config_rc", "1")
    proc = h.run("--ingress", "funnel", "--domain", DOMAIN.upper(), "--app-image", APP,
                 "--frontend-image", FRONTEND, values={**SECRETS, "TS_AUTHKEY": FAKE_AUTHKEY})
    assert proc.returncode == 1, proc.stderr
    env = h.env_file()
    assert env["TS_HOSTNAME"] == "soc-dev"
    assert env["LG_SOTF_API__PUBLIC_URL"] == f"https://{DOMAIN}"


# --------------------------------------------------------------------------- first deploy


def test_first_funnel_deploy_without_an_auth_key_fails_early(h: Harness) -> None:
    proc = h.run(*funnel_deploy(), values=SECRETS)
    assert proc.returncode == 2
    assert "no state yet (volume lgsotf-dev-tailscale)" in proc.stderr
    assert "TS_AUTHKEY" in proc.stderr
    calls = h.calls()
    assert not any(c.startswith(("volume create", "pull")) or " up " in f" {c} " for c in calls), calls
    assert_no_secret_printed(proc)


def test_an_unreachable_daemon_is_not_mistaken_for_a_missing_node(h: Harness) -> None:
    h.set("info_rc", "1")
    proc = h.run(*funnel_deploy(), values=SECRETS)
    assert proc.returncode == 2
    assert "cannot reach the Docker daemon" in proc.stderr
    assert "no state yet" not in proc.stderr


def test_malformed_auth_key_is_refused_without_echoing_it(h: Harness) -> None:
    bad = "tskey auth with spaces"
    proc = h.run(*funnel_deploy(), values={**SECRETS, "TS_AUTHKEY": bad})
    assert proc.returncode == 2
    assert "TS_AUTHKEY does not look like a Tailscale auth key" in proc.stderr
    assert bad not in proc.stdout + proc.stderr


def test_existing_node_state_needs_no_auth_key(h: Harness) -> None:
    h.volume_exists()
    h.set("config_rc", "1")
    proc = h.run(*funnel_deploy(), values=SECRETS)
    assert "no state yet" not in proc.stderr
    assert "compose configuration is invalid" in proc.stdout
    assert proc.returncode == 1


def test_funnel_rendering(h: Harness) -> None:
    h.set("config_rc", "1")  # stop right after rendering
    values = {**SECRETS, "TS_AUTHKEY": FAKE_AUTHKEY, "ACME_EMAIL": "ops@example.com"}
    proc = h.run(*funnel_deploy(), values=values)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert_no_secret_printed(proc)

    assert any(c.startswith("volume create") and c.endswith("lgsotf-dev-tailscale") for c in h.calls())
    env_dir = h.root / "env" / "dev"
    serve = env_dir / "tailscale" / "serve.json"
    assert serve.read_text() == (REPO_ROOT / "deploy" / "vm" / "tailscale" / "serve.json").read_text()
    # Readable by tailscaled, which runs as root without capabilities.
    assert stat.S_IMODE(serve.stat().st_mode) == 0o644
    assert stat.S_IMODE(serve.parent.stat().st_mode) == 0o755
    for private in (env_dir / ".env", env_dir / "secrets.env"):
        assert stat.S_IMODE(private.stat().st_mode) == 0o600, private
    assert f"TS_AUTHKEY='{FAKE_AUTHKEY}'" in (env_dir / "secrets.env").read_text()

    env = h.env_file()
    assert env["TS_AUTHKEY"] == FAKE_AUTHKEY
    assert env["TS_HOSTNAME"] == "soc-dev"
    assert env["TS_STATE_VOLUME"] == "lgsotf-dev-tailscale"
    assert env["EDGE_SUBNET"] == "10.202.1.0/29"
    assert env["EDGE_FRONTEND_IP"] == "10.202.1.2"
    assert env["EDGE_API_IP"] == "10.202.1.3"
    assert env["LG_SOTF_API__FORWARDED_ALLOW_IPS"] == "10.202.1.2"
    assert env["FRONTEND_TRUSTED_PROXIES"] == "127.0.0.1"
    assert env["LG_SOTF_API__PUBLIC_URL"] == f"https://{DOMAIN}"
    assert env["LG_SOTF_API__CORS_ORIGINS"] == f'["https://{DOMAIN}"]'
    for caddy_only in ("PROXY_NETWORK", "ACME_EMAIL", "CADDY_IMAGE"):
        assert caddy_only not in env

    compose = [c for c in h.calls() if c.startswith("compose -p lgsotf-dev ")]
    assert compose and all("docker-compose.funnel.yml" in c for c in compose)
    assert not any("docker-compose.caddy.yml" in c for c in compose)
    assert not any(c.startswith(("network create", "compose -p lgsotf-edge")) for c in h.calls()), "no Caddy"


def test_funnel_uses_the_slot_for_its_subnet(h: Harness) -> None:
    h.set("config_rc", "1")
    proc = h.run(*funnel_deploy("--slot", "7"), values={**SECRETS, "TS_AUTHKEY": FAKE_AUTHKEY})
    assert proc.returncode == 1
    env = h.env_file()
    assert (env["EDGE_SUBNET"], env["EDGE_FRONTEND_IP"]) == ("10.202.7.0/29", "10.202.7.2")


def test_caddy_mode_renders_what_it_always_did(h: Harness) -> None:
    h.set("config_rc", "1")
    proc = h.run("--domain", "soc-dev.example.org", "--app-image", APP, "--frontend-image", FRONTEND,
                 values={**SECRETS, "TS_AUTHKEY": FAKE_AUTHKEY})
    assert proc.returncode == 1
    env = h.env_file()
    assert env["EDGE_SUBNET"] == "172.31.250.8/29"
    assert env["LG_SOTF_API__FORWARDED_ALLOW_IPS"] == "172.31.250.10,172.31.251.2"
    assert env["FRONTEND_TRUSTED_PROXIES"] == "172.31.251.2"
    assert env["PROXY_NETWORK"] == "lgsotf-proxy"
    assert not any(k.startswith("TS_") for k in env)
    compose = [c for c in h.calls() if c.startswith("compose -p lgsotf-dev ")]
    assert compose and all("docker-compose.caddy.yml" in c for c in compose)
    assert not any("docker-compose.funnel.yml" in c for c in compose)
    assert not any(c.startswith("volume") for c in h.calls())


# --------------------------------------------------------------------------- after a healthy deploy


def healthy_deploy(h: Harness, status: Optional[str], funnel: str = "",
                   *extra: str) -> subprocess.CompletedProcess[str]:
    h.volume_exists()
    h.set("ts_cid", "ts-cid\n")
    if status is not None:
        h.set("ts_status.json", status)
    h.set("funnel_status", funnel)
    return h.run(*funnel_deploy(*extra), values=SECRETS)


def test_published_deploy_succeeds(h: Harness) -> None:
    proc = healthy_deploy(h, ts_status(), funnel_status())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "healthy inside the stack: http://10.202.1.2:8080" in proc.stdout
    assert f"Funnel publishes https://{DOMAIN}" in proc.stdout
    assert f"DEPLOYED sha-1234567 at https://{DOMAIN}" in proc.stdout
    current = (h.root / "env" / "dev" / "state" / "current.env").read_text()
    assert "INGRESS=funnel" in current
    probe = next(c for c in h.calls() if " exec -T api python " in c)
    assert f"http://10.202.1.2:8080 {DOMAIN}" in probe
    for path in ("/healthz|200|ok", '/api/v1/healthz|200|"status":"ok"', '/api/v1/readyz|200|"status":"ok"',
                 "/api/v1/alerts|401|", '/|200|<div id="root">', "/config.js|200|__LG_SOTF_CONFIG__"):
        assert path in probe, path
    assert_no_secret_printed(proc)


def test_application_failure_is_reported_before_any_ingress_check(h: Harness) -> None:
    h.set("pending", "/api/v1/readyz(503)\n")
    proc = healthy_deploy(h, ts_status(), funnel_status(), "--health-timeout", "0")
    assert proc.returncode == 1
    assert "health checks failed" in proc.stdout and "/api/v1/readyz(503)" in proc.stdout
    assert "no other version to roll back to" in proc.stdout
    assert not any(c.startswith("exec ") for c in h.calls()), "no Tailscale check after an application failure"


# A JWT-shaped access token, as the web app's WebSocket sends it.
WS_TOKEN = ".".join(["eyJhbGciOiJIUzI1NiJ9", "e" * 40, "s" * 43])
OIDC_CODE = "SplxlOBeZQQYbYS6WxSbIA"


@pytest.mark.parametrize("ingress", ["funnel", "caddy"])
def test_failure_logs_never_show_query_string_secrets(h: Harness, ingress: str) -> None:
    # uvicorn logs every WebSocket handshake with its query string; the
    # Deploy workflow streams this output into a public Actions log.
    h.set("logs", "\n".join([
        f'api-1  | {{"event": "10.202.1.2:40000 - \\"WebSocket /api/v1/ws?token={WS_TOKEN}\\" [accepted]", '
        '"logger": "uvicorn.error"}',
        f'api-1  | INFO:     10.202.1.2:40000 - "WebSocket /api/v1/ws?x=1&access_token={WS_TOKEN}" 403',
        f"frontend-1  | GET /api/v1/auth/oidc/callback?code={OIDC_CODE}&state=af0ifjsldkj",
        'api-1  | {"event": "database migrated", "revision": 12}',
    ]) + "\n")
    h.set("pending", "/api/v1/readyz(503)\n")
    if ingress == "funnel":
        proc = healthy_deploy(h, ts_status(), funnel_status(), "--health-timeout", "0")
    else:
        proc = h.run("--domain", "soc-dev.example.org", "--app-image", APP, "--frontend-image", FRONTEND,
                     "--health-timeout", "0", values=SECRETS)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    output = proc.stdout + proc.stderr
    assert "last log lines" in output
    assert WS_TOKEN not in output and OIDC_CODE not in output
    assert '/api/v1/ws?token=[redacted]\\" [accepted]' in output
    assert "&access_token=[redacted]\" 403" in output
    assert "?code=[redacted]&state=af0ifjsldkj" in output
    assert '"revision": 12' in output, "the rest of the log is kept for diagnosis"
    assert_no_secret_printed(proc)


# containerboot with a rejected TS_AUTHKEY (tailscale/tailscale v1.102.5, as seen
# on a real deploy): `tailscale up` fails, containerboot exits and Docker restarts
# it. A run without a key prints a login URL instead.
TS_LOG_REJECTED_KEY = "\n".join([
    "boot: 2026/09/29 23:14:20 Running 'tailscale up'",
    "2026/09/29 23:14:20 localapi: [POST] /localapi/v0/login-interactive",
    "To authenticate, visit:",
    "",
    "\t" + LOGIN_URL,
    "",
    "2026/09/29 23:14:21 Received error: invalid key: API key does not exist",
    "2026/09/29 23:14:21 health(warnable=login-state): error: You are logged out. "
    "The last login error was: invalid key: API key does not exist",
    "backend error: invalid key: API key does not exist",
    "boot: 2026/09/29 23:14:21 failed to auth tailscale: failed to auth tailscale: tailscale up failed: exit status 1",
]) + "\n"


@pytest.mark.parametrize(
    ("ts_log", "shown"),
    [
        (TS_LOG_REJECTED_KEY, "(invalid key: API key does not exist)"),
        (f"invalid key: {FAKE_AUTHKEY} is not valid.\n", "(invalid key: tskey-[redacted] is not valid)"),
        ("boot: failed to auth tailscale: context deadline exceeded\n",
         "(failed to auth tailscale: context deadline exceeded)"),
    ],
    ids=["rejected-key", "key-in-error", "no-key-timeout"],
)
def test_failed_checks_name_a_sidecar_that_cannot_log_in(h: Harness, ts_log: str, shown: str) -> None:
    # Every restart of ts leaves the frontend without a network for a while,
    # so the checks through nginx can fail before any Tailscale check runs.
    h.set("ts_logs", ts_log)
    h.set("pending", "/healthz(0) /api/v1/healthz(0)\n")
    proc = healthy_deploy(h, ts_status("NeedsLogin"), "", "--health-timeout", "0")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"Tailscale: the ts sidecar cannot log in {shown}" in proc.stdout
    assert "fix: create an auth key (admin console > Settings > Keys: tags tag:soc" in proc.stdout
    assert_no_secret_printed(proc)


def test_failed_checks_blame_tailscale_only_on_evidence(h: Harness) -> None:
    h.set("ts_logs", f"boot: 2026/09/29 23:07:10 Running 'tailscale up'\n\t{LOGIN_URL}\n")
    h.set("pending", "/api/v1/readyz(503)\n")
    proc = healthy_deploy(h, ts_status("NeedsLogin"), "", "--health-timeout", "0")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "cannot log in" not in proc.stdout
    assert_no_secret_printed(proc)


def test_looking_for_the_sidecar_never_stops_the_failure_path(h: Harness) -> None:
    h.set("ps_rc", "1")
    h.set("pending", "/api/v1/readyz(503)\n")
    proc = healthy_deploy(h, ts_status("NeedsLogin"), "", "--health-timeout", "0")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "no other version to roll back to" in proc.stdout


def test_caddy_failures_never_read_a_sidecar_log(h: Harness) -> None:
    h.set("ts_logs", TS_LOG_REJECTED_KEY)
    h.set("pending", "/api/v1/readyz(503)\n")
    proc = h.run("--domain", "soc-dev.example.org", "--app-image", APP, "--frontend-image", FRONTEND,
                 "--health-timeout", "0", values=SECRETS)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "cannot log in" not in proc.stdout
    assert not any(c.startswith("logs ") for c in h.calls())


def test_logged_out_node_shows_its_last_login_error(h: Harness) -> None:
    h.set("ts_logs", TS_LOG_REJECTED_KEY)
    proc = healthy_deploy(h, ts_status("NeedsLogin"))
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "last login error: invalid key: API key does not exist" in proc.stdout
    assert_no_secret_printed(proc)


@pytest.mark.parametrize(
    ("status", "funnel", "cause"),
    [
        (None, "", "the ts container is not running"),
        (ts_status("NeedsLogin"), "", "TS_AUTHKEY is missing, invalid, expired or single-use"),
        (ts_status("NeedsMachineAuth"), "", "waits for device approval"),
        (ts_status("Starting"), "", "cannot reach the Tailscale control plane"),
        (ts_status(dns="soc-dev-1.tail1234.ts.net."), "", "registered as 'soc-dev-1.tail1234.ts.net'"),
        (ts_status(caps=["funnel"]), "No serve config\n", "HTTPS certificates are not enabled"),
        (ts_status(caps=["https"]), funnel_status(), "does not grant Funnel"),
        (ts_status(), "No serve config\n", "serve config (<env dir>/tailscale/serve.json) is not active"),
    ],
    ids=["no-container", "logged-out", "approval", "offline", "name-taken", "no-https", "no-funnel-attr",
         "serve-not-applied"],
)
def test_ingress_failures_name_the_likely_cause(h: Harness, status: Optional[str], funnel: str, cause: str) -> None:
    proc = healthy_deploy(h, status, funnel)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "INGRESS FAILED: sha-1234567 is deployed and healthy on this host" in proc.stdout
    assert cause in proc.stdout
    # The version stays deployed: the previous one would face the same ingress.
    assert "rolling back" not in proc.stdout
    assert "VERSION=sha-1234567" in (h.root / "env" / "dev" / "state" / "current.env").read_text()
    assert_no_secret_printed(proc)


# --------------------------------------------------------------------------- status and rollback


def recorded(h: Harness, ingress: str) -> None:
    state = h.root / "env" / "dev" / "state"
    state.mkdir(parents=True)
    for which, version in (("current", "sha-2222222"), ("previous", "sha-1111111")):
        (state / f"{which}.env").write_text(
            f"APP_IMAGE={APP}\nFRONTEND_IMAGE={FRONTEND}\nRELEASE_DIR={REPO_ROOT}\nVERSION={version}\n"
            f"INGRESS={ingress}\nDEPLOYED_AT=2026-01-01T00:00:00Z\n"
        )


def test_status_reports_the_recorded_mode_and_the_node(h: Harness) -> None:
    recorded(h, "funnel")
    h.set("ts_cid", "ts-cid\n")
    h.set("ts_status.json", ts_status("NeedsLogin"))
    proc = h.run("--status")
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0].startswith("current  sha-2222222")
    assert "ingress  funnel" in lines
    assert "tailnet  NeedsLogin " in lines
    assert LOGIN_URL not in proc.stdout, "the pending login URL is never printed"


def test_rollback_keeps_the_recorded_ingress(h: Harness) -> None:
    recorded(h, "funnel")
    h.volume_exists()
    h.set("config_rc", "1")
    env_dir = h.root / "env" / "dev"
    (env_dir / "secrets.env").write_text("".join(f"{k}='{v}'\n" for k, v in SECRETS.items()))
    proc = h.run("--domain", DOMAIN, "--rollback")
    assert "rolling back from sha-2222222 to sha-1111111" in proc.stdout
    assert "funnel ingress" in proc.stdout
    compose = [c for c in h.calls() if c.startswith("compose -p lgsotf-dev ")]
    assert compose and all("docker-compose.funnel.yml" in c for c in compose)


def test_switching_ingress_stops_the_old_stack_first(h: Harness) -> None:
    recorded(h, "caddy")
    h.set("config_rc", "1")
    proc = h.run(*funnel_deploy(), values={**SECRETS, "TS_AUTHKEY": FAKE_AUTHKEY})
    assert "switching ingress from caddy to funnel" in proc.stdout
    down = [c for c in h.calls() if c.startswith("compose -p lgsotf-dev down")]
    assert down == ["compose -p lgsotf-dev down --remove-orphans"], "no -v: data volumes are kept"


def test_backup_uses_the_recorded_overlays(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    recorded(h, "funnel")
    (h.root / "env" / "dev" / ".env").write_text("")
    proc = subprocess.run(  # noqa: S603 - fixed argv
        ["bash", str(REPO_ROOT / "deploy" / "vm" / "backup.sh"), "--root", str(h.root), "--env", "dev"],  # noqa: S607
        capture_output=True, text=True, timeout=60,
        env={"PATH": f"{h.bin}:{os.environ.get('PATH', '')}", "HOME": str(tmp_path), "STUB_DIR": str(h.stub)},
    )
    compose = [c for c in h.calls() if c.startswith("compose -p lgsotf-dev ")]
    assert compose, proc.stderr
    assert all("docker-compose.funnel.yml" in c and "docker-compose.caddy.yml" not in c for c in compose)
