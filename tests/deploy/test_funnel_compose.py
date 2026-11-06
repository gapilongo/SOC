"""Tailscale Funnel ingress: deploy/vm/docker-compose.funnel.yml and deploy/vm/tailscale/serve.json.

YAML-level checks always run; the resolved configuration (``docker compose
config``) is checked when the docker CLI is installed. The runtime behaviour
(a real deploy through the ts network namespace) is described in
docs/self-hosting-pc.md and exercised by deploy.sh's own health checks.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Dict

import pytest

from tests.deploy._support import DOCKER_DIR, PROD_SECRETS, REPO_ROOT, compose_config, load, requires_compose

VM = REPO_ROOT / "deploy" / "vm"
FUNNEL = VM / "docker-compose.funnel.yml"
CADDY = VM / "docker-compose.caddy.yml"
SERVE = VM / "tailscale" / "serve.json"
TS_IMAGE = (
    "tailscale/tailscale:v1.102.5"
    "@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065"
)
BASE_FILES = (
    str(DOCKER_DIR / "docker-compose.yml"),
    str(DOCKER_DIR / "docker-compose.prod.yml"),
    str(VM / "docker-compose.vm.yml"),
)
COMMON_ENV = {
    **PROD_SECRETS,
    "APP_IMAGE": "ghcr.io/gapilongo/lg-sotf@sha256:" + "a" * 64,
    "FRONTEND_IMAGE": "ghcr.io/gapilongo/lg-sotf-frontend@sha256:" + "b" * 64,
    "LGSOTF_ENV": "dev",
    "LGSOTF_ENV_DIR": "/opt/lg-sotf/env/dev",
}
# What deploy.sh renders for --ingress funnel, slot 1.
FUNNEL_ENV = {
    **COMMON_ENV,
    "EDGE_SUBNET": "10.202.1.0/29",
    "EDGE_FRONTEND_IP": "10.202.1.2",
    "EDGE_API_IP": "10.202.1.3",
    "LG_SOTF_API__FORWARDED_ALLOW_IPS": "10.202.1.2",
    "FRONTEND_TRUSTED_PROXIES": "127.0.0.1",
    "TS_HOSTNAME": "soc-dev",
    "TS_STATE_VOLUME": "lgsotf-dev-tailscale",
}
# What deploy.sh renders for --ingress caddy, slot 1.
CADDY_ENV = {
    **COMMON_ENV,
    "LG_SOTF_API__FORWARDED_ALLOW_IPS": "172.31.250.10,172.31.251.2",
    "FRONTEND_TRUSTED_PROXIES": "172.31.251.2",
}


@pytest.fixture(scope="module")
def overlay() -> Dict[str, Any]:
    return load(FUNNEL)


# --------------------------------------------------------------------------- serve.json


def test_serve_config_publishes_one_handler_to_nginx_through_funnel() -> None:
    config = json.loads(SERVE.read_text())
    host = "${TS_CERT_DOMAIN}:443"
    assert config == {
        "TCP": {"443": {"HTTPS": True}},
        "Web": {host: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}}},
        "AllowFunnel": {host: True},
    }
    # Serve strips a handler's mount prefix: /api must reach nginx unchanged,
    # so there is exactly one "/" handler and nginx does the routing.
    assert list(config["Web"][host]["Handlers"]) == ["/"]


# --------------------------------------------------------------------------- the ts sidecar


def test_sidecar_image_is_pinned_to_a_fixed_release(overlay: Dict[str, Any]) -> None:
    image = overlay["services"]["ts"]["image"]
    assert image == "${TS_IMAGE:-" + TS_IMAGE + "}"
    version = re.search(r":v(\d+)\.(\d+)\.(\d+)@", image)
    assert version is not None
    assert tuple(map(int, version.groups())) >= (1, 102, 3), "older releases lack fixes this setup relies on"


def test_sidecar_logs_in_once_and_keeps_its_identity(overlay: Dict[str, Any]) -> None:
    ts = overlay["services"]["ts"]
    env = ts["environment"]
    assert env["TS_AUTHKEY"] == "${TS_AUTHKEY:-}", "optional once the node has state"
    assert env["TS_AUTH_ONCE"] == "true"
    assert env["TS_HOSTNAME"] == "${TS_HOSTNAME:?set TS_HOSTNAME}"
    assert env["TS_STATE_DIR"] == "/var/lib/tailscale"
    assert "tailscale-state:/var/lib/tailscale" in ts["volumes"]
    # External: deploys, rollbacks and `down -v` never delete it (a new state
    # would register soc-dev-1 and request new certificates).
    assert overlay["volumes"]["tailscale-state"] == {
        "external": True,
        "name": "${TS_STATE_VOLUME:?set TS_STATE_VOLUME}",
    }


def test_sidecar_serves_the_mounted_config_directory(overlay: Dict[str, Any]) -> None:
    ts = overlay["services"]["ts"]
    assert ts["environment"]["TS_SERVE_CONFIG"] == "/config/serve.json"
    # A directory, read-only: deploy.sh replaces serve.json atomically.
    assert "${LGSOTF_ENV_DIR:?set LGSOTF_ENV_DIR}/tailscale:/config:ro" in ts["volumes"]


def test_sidecar_is_unprivileged_and_bounded(overlay: Dict[str, Any]) -> None:
    ts = overlay["services"]["ts"]
    env = ts["environment"]
    assert env["TS_USERSPACE"] == "true", "userspace networking: no NET_ADMIN, no /dev/net/tun"
    assert env["TS_ACCEPT_DNS"] == "false"
    assert "cap_add" not in ts and "devices" not in ts and "privileged" not in ts
    assert ts["cap_drop"] == ["ALL"]
    assert ts["security_opt"] == ["no-new-privileges:true"]
    assert ts["read_only"] is True
    assert any(t.startswith("/tmp:") for t in ts["tmpfs"])
    assert ts["restart"] == "unless-stopped"
    assert "ports" not in ts, "Funnel needs no host port"
    limits = ts["deploy"]["resources"]["limits"]
    assert limits == {"cpus": "${TS_CPUS:-0.25}", "memory": "${TS_MEM:-128m}"}
    assert ts["logging"]["options"] == {"max-size": "10m", "max-file": "5"}


def test_sidecar_health_endpoint_is_local_and_not_a_compose_gate(overlay: Dict[str, Any]) -> None:
    ts = overlay["services"]["ts"]
    assert ts["environment"]["TS_ENABLE_HEALTH_CHECK"] == "true"
    assert ts["environment"]["TS_LOCAL_ADDR_PORT"] == "127.0.0.1:9002"
    # A logged-out node answers 503: a compose health check would make
    # `up --wait` fail before the application could be checked without a key.
    assert "healthcheck" not in ts
    # containerboot's 60 s default would restart ts (and detach the frontend)
    # while a slow network or a device approval is pending.
    assert re.fullmatch(r"\d+m", ts["environment"]["TS_BOOT_TIMEOUT"])


def test_sidecar_owns_the_frontend_address_the_api_trusts(overlay: Dict[str, Any]) -> None:
    ts = overlay["services"]["ts"]
    assert ts["networks"] == {"edge": {"ipv4_address": "${EDGE_FRONTEND_IP:?set EDGE_FRONTEND_IP}"}}


# --------------------------------------------------------------------------- the frontend


def test_frontend_runs_in_the_sidecar_namespace(overlay: Dict[str, Any]) -> None:
    fe = overlay["services"]["frontend"]
    assert fe["network_mode"] == "service:ts"
    assert fe["networks"] == {}, "reset: a service in another's namespace declares no networks"
    assert "ports" not in fe
    assert fe["depends_on"]["ts"] == {"condition": "service_started", "restart": True}
    assert fe["environment"]["LG_SOTF_TRUSTED_PROXIES"] == "127.0.0.1", "Funnel connects from loopback"
    assert fe["environment"]["LG_SOTF_HSTS_MAX_AGE"] == "${FRONTEND_HSTS_MAX_AGE:-63072000}"


def test_frontend_leaves_a_stale_namespace(overlay: Dict[str, Any]) -> None:
    """After ts restarts, Docker leaves the frontend with only `lo`; nginx must stop so it restarts."""
    test = overlay["services"]["frontend"]["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL"
    script = test[1]
    assert "/proc/net/dev" in script and "'^ *lo:'" in script
    assert "kill 1" in script
    assert "http://127.0.0.1:8080/healthz" in script
    assert "$" not in script, "compose would interpolate it"


def test_healthcheck_detects_a_namespace_with_only_loopback(tmp_path: Any) -> None:
    script = load(FUNNEL)["services"]["frontend"]["healthcheck"]["test"][1]
    probe = script.split("||", 1)[0].strip()
    header = (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n"
    )
    lo = "    lo:     100       1    0    0    0     0          0         0      100       1\n"
    eth0 = "  eth0:    2000      20    0    0    0     0          0         0     1000      10\n"
    for content, healthy in ((header + lo + eth0, True), (header + lo, False)):
        dev = tmp_path / "dev"
        dev.write_text(content)
        proc = subprocess.run(
            ["sh", "-c", probe.replace("/proc/net/dev", str(dev))],  # noqa: S607
            capture_output=True, text=True, timeout=10,
        )
        assert (proc.returncode == 0) is healthy, content


def test_caddy_overlay_is_not_needed_in_funnel_mode(overlay: Dict[str, Any]) -> None:
    assert "networks" not in overlay, "no external proxy network and no Caddy"
    assert "proxy" not in json.dumps(overlay)


def test_documented_tailnet_policy_reaches_the_sidecars_on_443_only() -> None:
    # tailscaled (userspace) forwards any other port of the node to 127.0.0.1
    # in the shared namespace, where nginx trusts X-Forwarded-For.
    section = (REPO_ROOT / "docs" / "cicd.md").read_text().split("\n## 16.", 1)[1]
    block = re.search(r'```json\n\s*"grants": (\[.*?\])\n\s*```', section, re.S)
    assert block, "docs/cicd.md section 16 shows the grants"
    grants = json.loads(block.group(1))
    for grant in grants:
        if "*" in grant["dst"] or "tag:soc" in grant["dst"]:
            assert grant["dst"] == ["tag:soc"] and grant["ip"] == ["tcp:443"], grant
    assert {"src": ["autogroup:member"], "dst": ["tag:soc"], "ip": ["tcp:443"]} in grants
    assert {"src": ["tag:ci"], "dst": ["tag:lgsotf-host"], "ip": ["tcp:22"]} in grants
    assert "tcp:443" in FUNNEL.read_text().split("\nservices:", 1)[0], "the overlay header explains it"


# --------------------------------------------------------------------------- resolved configuration


@requires_compose
def test_funnel_stack_resolves_without_host_ports() -> None:
    cfg = compose_config(*BASE_FILES, str(FUNNEL), env=FUNNEL_ENV)
    services = cfg["services"]
    assert set(services) == {"postgres", "redis", "migrate", "api", "worker", "scheduler", "frontend", "ts"}
    for name, svc in services.items():
        assert not svc.get("ports"), f"{name} publishes a host port"
        assert "build" not in svc, name
    ts, fe, api = services["ts"], services["frontend"], services["api"]
    assert ts["image"] == TS_IMAGE
    assert ts["networks"] == {"edge": {"ipv4_address": "10.202.1.2"}}
    assert fe["network_mode"] == "service:ts"
    assert not fe.get("networks")
    assert fe["environment"]["LG_SOTF_TRUSTED_PROXIES"] == "127.0.0.1"
    assert fe["environment"]["LG_SOTF_API_UPSTREAM"] == "http://api:8000"
    assert api["environment"]["LG_SOTF_API__FORWARDED_ALLOW_IPS"] == "10.202.1.2"
    assert set(api["networks"]) == {"default", "edge"}
    assert api["networks"]["edge"] == {"ipv4_address": "10.202.1.3"}
    assert cfg["networks"]["edge"]["ipam"]["config"] == [{"subnet": "10.202.1.0/29"}]
    assert "proxy" not in cfg["networks"]
    assert cfg["volumes"]["tailscale-state"] == {"name": "lgsotf-dev-tailscale", "external": True}
    config_mount = next(v for v in ts["volumes"] if v["target"] == "/config")
    assert config_mount["source"] == "/opt/lg-sotf/env/dev/tailscale" and config_mount["read_only"] is True


@requires_compose
def test_both_ingress_modes_share_everything_but_the_ingress() -> None:
    funnel = compose_config(*BASE_FILES, str(FUNNEL), env=FUNNEL_ENV)["services"]
    caddy = compose_config(*BASE_FILES, str(CADDY), env=CADDY_ENV)["services"]
    for services in (funnel, caddy):
        for svc in services.values():
            # Forwarded to every app container by the prod passthrough; differs by design.
            (svc.get("environment") or {}).pop("LG_SOTF_API__FORWARDED_ALLOW_IPS", None)
    for name in ("postgres", "redis", "migrate", "worker", "scheduler"):
        assert funnel[name] == caddy[name], name
    assert funnel["frontend"]["image"] == caddy["frontend"]["image"]
    assert funnel["frontend"]["deploy"] == caddy["frontend"]["deploy"]
    assert "ts" not in caddy


@requires_compose
@pytest.mark.parametrize("missing", ["TS_HOSTNAME", "TS_STATE_VOLUME", "EDGE_FRONTEND_IP", "LGSOTF_ENV_DIR"])
def test_funnel_overlay_refuses_to_resolve_without_its_settings(missing: str) -> None:
    env = {k: v for k, v in FUNNEL_ENV.items() if k != missing}
    argv = ["docker", "compose"]
    for f in (*BASE_FILES, str(FUNNEL)):
        argv += ["-f", f]
    proc = subprocess.run(
        [*argv, "config", "-q"],
        capture_output=True, text=True, timeout=60,
        env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "/tmp"), **env},
    )
    if "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin is not installed")
    assert proc.returncode != 0
    assert missing in proc.stderr
