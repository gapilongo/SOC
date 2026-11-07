"""deploy.yml and ci.yml for the Tailscale Funnel ingress and the deploy route over the tailnet.

Besides structure (pinned action, conditional step, permissions), the
workflow's own `run:` scripts are executed here with bash, the way GitHub
runs them, against stub commands: input validation, what the deploy step
sends on stdin and on the SSH command line, and the job summary.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from tests.deploy._support import REPO_ROOT

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
DEPLOY = WORKFLOWS / "deploy.yml"
CI = WORKFLOWS / "ci.yml"
FAKE_AUTHKEY = "-".join(["tskey", "auth", "kFAKE" + "x" * 11, "y" * 32])


def job() -> Dict[str, Any]:
    data = yaml.safe_load(DEPLOY.read_text())
    return data["jobs"]["deploy"]


def step(name: str) -> Dict[str, Any]:
    return next(s for s in job()["steps"] if s.get("name", "").startswith(name))


def run_step(script: str, env: Dict[str, str], tmp_path: Path, extra_path: str = "") -> subprocess.CompletedProcess[str]:
    path = tmp_path / "step.sh"
    path.write_text(script)
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(path)],  # noqa: S607 - GitHub's bash invocation
        capture_output=True, text=True, timeout=30,
        env={"PATH": f"{extra_path}{os.environ.get('PATH', '')}", "HOME": str(tmp_path), **env},
    )


# --------------------------------------------------------------------------- structure


def test_ingress_and_route_are_environment_variables_with_safe_defaults() -> None:
    env = job()["env"]
    assert env["INGRESS"] == "${{ vars.INGRESS || 'caddy' }}"
    assert env["DEPLOY_VIA_TAILSCALE"] == "${{ vars.DEPLOY_VIA_TAILSCALE || 'false' }}"


def test_tailnet_step_is_pinned_conditional_and_precedes_ssh() -> None:
    steps: List[Dict[str, Any]] = job()["steps"]
    names = [s.get("name", "") for s in steps]
    ts = next(s for s in steps if s.get("uses", "").startswith("tailscale/github-action@"))
    # Pinned to a full commit SHA with its release tag in a comment (Dependabot may move both).
    assert re.fullmatch(r"tailscale/github-action@[0-9a-f]{40}", ts["uses"])
    line = next(text for text in DEPLOY.read_text().splitlines() if ts["uses"] in text)
    assert re.search(r"# v\d+\.\d+\.\d+\s*$", line)
    assert ts["if"] == "env.DEPLOY_VIA_TAILSCALE == 'true'"
    assert ts["with"] == {
        "oauth-client-id": "${{ secrets.TS_OAUTH_CLIENT_ID }}",
        "oauth-secret": "${{ secrets.TS_OAUTH_SECRET }}",
        "tags": "tag:ci",
        "ping": "${{ env.DEPLOY_HOST }}",
        # A cache hit installs the binaries without the download's checksum check.
        "use-cache": "false",
    }, "an OAuth client, ephemeral tag:ci node; no long-lived auth key; no Actions cache"
    assert names.index(ts["name"]) == names.index("Configure SSH (pinned host key)") - 1
    assert names.index(ts["name"]) > names.index("Validate inputs and settings")


def test_permissions_stay_least_privilege() -> None:
    wf = yaml.safe_load(DEPLOY.read_text())
    assert wf["permissions"] == {"contents": "read"}
    assert job()["permissions"] == {"contents": "read", "packages": "read", "attestations": "read"}, (
        "no id-token: OAuth client secret"
    )


def test_auth_key_travels_only_on_stdin() -> None:
    deploy = step("Deploy")
    assert deploy["env"]["TS_AUTHKEY"] == "${{ secrets.TS_AUTHKEY }}"
    remote = deploy["run"].split("| ssh", 1)[1]
    assert "TS_AUTHKEY" not in remote
    assert "$ingress_opt" in remote
    for s in job()["steps"]:
        run = s.get("run", "")
        assert not re.search(r"echo[^\n]*\$\{?TS_(AUTHKEY|OAUTH_SECRET|OAUTH_CLIENT_ID)\b", run), s.get("name")


def test_old_bundles_are_deployed_without_the_ingress_flag() -> None:
    run = step("Resolve image digests")["run"]
    assert 'git cat-file -e "${commit}:deploy/vm/docker-compose.funnel.yml"' in run
    assert "predates the Tailscale Funnel ingress" in run
    assert "ingress_supported=$ingress_supported" in run
    assert step("Deploy")["env"]["INGRESS_SUPPORTED"] == "${{ steps.images.outputs.ingress_supported }}"


# --------------------------------------------------------------------------- validation, executed

VALID = {
    "TARGET_ENV": "dev",
    "IMAGE_TAG": "main",
    "INPUT_COMMIT": "",
    "INPUT_APP_DIGEST": "",
    "INPUT_FRONTEND_DIGEST": "",
    "APP_DOMAIN": "soc-dev.duckdns.org",
    "DEPLOY_HOST": "203.0.113.10",
    "DEPLOY_USER": "deploy",
    "DEPLOY_PORT": "22",
    "HAS_SSH_KEY": "true",
    "HAS_KNOWN_HOSTS": "true",
    "HAS_TS_OAUTH_CLIENT_ID": "false",
    "HAS_TS_OAUTH_SECRET": "false",
    "INGRESS": "caddy",
    "DEPLOY_VIA_TAILSCALE": "false",
}
FUNNEL_PC = {
    **VALID,
    "APP_DOMAIN": "soc-dev.tail1234.ts.net",
    "DEPLOY_HOST": "100.101.102.103",
    "INGRESS": "funnel",
    "DEPLOY_VIA_TAILSCALE": "true",
    "HAS_TS_OAUTH_CLIENT_ID": "true",
    "HAS_TS_OAUTH_SECRET": "true",
}


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({}, None),
        (FUNNEL_PC, None),
        ({**FUNNEL_PC, "APP_DOMAIN": "SOC-DEV.Tail1234.ts.net"}, None),
        ({"INGRESS": "nginx"}, "INGRESS variable must be caddy or funnel"),
        ({"INGRESS": ""}, "INGRESS variable must be caddy or funnel"),
        ({**FUNNEL_PC, "APP_DOMAIN": "soc-dev.duckdns.org"}, "APP_DOMAIN must be <machine name>.<tailnet>.ts.net"),
        ({**FUNNEL_PC, "APP_DOMAIN": "x.soc-dev.tail1234.ts.net"}, "APP_DOMAIN must be <machine name>.<tailnet>.ts.net"),
        # INGRESS unset (caddy) on a Funnel environment must not replace Funnel by Caddy.
        ({**FUNNEL_PC, "INGRESS": "caddy"}, "*.ts.net names are served only by INGRESS=funnel"),
        ({"APP_DOMAIN": "SOC-DEV.Tail1234.TS.NET"}, "*.ts.net names are served only by INGRESS=funnel"),
        ({"APP_DOMAIN": "soc-dev.shorts.net"}, None),
        ({"DEPLOY_VIA_TAILSCALE": "yes"}, "DEPLOY_VIA_TAILSCALE variable must be true or false"),
        ({**FUNNEL_PC, "HAS_TS_OAUTH_CLIENT_ID": "false"}, "needs the secret TS_OAUTH_CLIENT_ID"),
        ({**FUNNEL_PC, "HAS_TS_OAUTH_SECRET": "false"}, "needs the secret TS_OAUTH_SECRET"),
        ({**FUNNEL_PC, "IMAGE_TAG": "latest"}, "image_tag must be"),
    ],
)
def test_validation_step(tmp_path: Path, overrides: Dict[str, str], error: Any) -> None:
    proc = run_step(step("Validate inputs and settings")["run"], {**VALID, **overrides}, tmp_path)
    if error is None:
        assert proc.returncode == 0, proc.stdout + proc.stderr
    else:
        assert proc.returncode == 1
        assert "::error::" in proc.stdout and error in proc.stdout


# --------------------------------------------------------------------------- the deploy step, executed

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
APP_SECRETS = {name: "test-suite-only-" + name.lower().replace("_", "-") + "-" + "x" * 12 for name in _FAKE_SECRET_NAMES}
APP_SECRETS["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"


def run_deploy_step(tmp_path: Path, **env: str) -> Dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ssh = bin_dir / "ssh"
    ssh.write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "{tmp_path}/argv"\ncat > "{tmp_path}/stdin"\n')
    ssh.chmod(ssh.stat().st_mode | stat.S_IXUSR)
    base = {
        **APP_SECRETS,
        "TARGET_ENV": "dev", "APP_DOMAIN": "soc-dev.tail1234.ts.net", "IMAGE_TAG": "sha-1234567",
        "REMOTE_ROOT": "/opt/lg-sotf", "COMMIT": "c" * 40, "SSH_CONFIG": str(tmp_path / "ssh_config"),
        "APP_REF": "ghcr.io/gapilongo/lg-sotf@sha256:" + "a" * 64,
        "FRONTEND_REF": "ghcr.io/gapilongo/lg-sotf-frontend@sha256:" + "b" * 64,
        "ANTHROPIC_API_KEY": "", "LG_SOTF_LLM__PROVIDER": "", "ACME_EMAIL": "", "GHCR_USER": "", "GHCR_TOKEN": "",
        "TS_AUTHKEY": FAKE_AUTHKEY, "INGRESS": "funnel", "INGRESS_SUPPORTED": "true",
    }
    proc = run_step(step("Deploy")["run"], {**base, **env}, tmp_path, extra_path=f"{bin_dir}:")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for value in (*APP_SECRETS.values(), FAKE_AUTHKEY):
        if "@" not in value:
            assert value not in proc.stdout + proc.stderr
    return {"argv": (tmp_path / "argv").read_text(), "stdin": (tmp_path / "stdin").read_text()}


def test_funnel_deploy_sends_the_auth_key_on_stdin_and_the_mode_on_the_command_line(tmp_path: Path) -> None:
    sent = run_deploy_step(tmp_path)
    assert f"TS_AUTHKEY={FAKE_AUTHKEY}\n" in sent["stdin"]
    assert FAKE_AUTHKEY not in sent["argv"]
    remote = sent["argv"].splitlines()[-1]
    assert "--ingress 'funnel'" in remote and "--secrets-stdin" in remote
    assert "--domain 'soc-dev.tail1234.ts.net'" in remote
    for value in APP_SECRETS.values():
        assert value not in sent["argv"]


def test_caddy_deploy_never_forwards_the_auth_key(tmp_path: Path) -> None:
    sent = run_deploy_step(tmp_path, INGRESS="caddy", APP_DOMAIN="soc-dev.duckdns.org")
    assert "TS_AUTHKEY" not in sent["stdin"]
    assert "--ingress 'caddy'" in sent["argv"]


def test_missing_auth_key_is_simply_not_sent(tmp_path: Path) -> None:
    sent = run_deploy_step(tmp_path, TS_AUTHKEY="")
    assert "TS_AUTHKEY" not in sent["stdin"]


def test_bundle_without_the_option_gets_no_ingress_flag(tmp_path: Path) -> None:
    sent = run_deploy_step(tmp_path, INGRESS="caddy", INGRESS_SUPPORTED="false")
    assert "--ingress" not in sent["argv"]


# --------------------------------------------------------------------------- the job summary, executed


def summary(tmp_path: Path, **env: str) -> str:
    out = tmp_path / "summary.md"
    base = {
        "GITHUB_STEP_SUMMARY": str(out), "OUTCOME": "success", "TARGET_ENV": "dev", "IMAGE_TAG": "main",
        "APP_DOMAIN": "soc-dev.tail1234.ts.net", "DEPLOY_HOST": "100.101.102.103", "COMMIT": "c" * 40,
        "APP_REF": "a", "FRONTEND_REF": "f", "INGRESS": "funnel", "DEPLOY_VIA_TAILSCALE": "true",
        "HAS_TS_AUTHKEY": "true",
    }
    proc = run_step(step("Job summary")["run"], {**base, **env}, tmp_path)
    assert proc.returncode == 0, proc.stderr
    return out.read_text()


def test_summary_shows_the_ingress_and_the_route(tmp_path: Path) -> None:
    text = summary(tmp_path)
    assert "| Ingress | `funnel` (Tailscale Funnel) |" in text
    assert "| Deploy route | SSH over the tailnet to 100.101.102.103 |" in text
    assert "TS_AUTHKEY" not in text
    caddy = summary(tmp_path, INGRESS="caddy", DEPLOY_VIA_TAILSCALE="false", HAS_TS_AUTHKEY="false")
    assert "| Ingress | `caddy` (Caddy (Let's Encrypt)) |" in caddy
    assert "| Deploy route | SSH to 100.101.102.103 |" in caddy
    assert "TS_AUTHKEY" not in caddy, "the auth key only matters with Funnel"


def test_summary_warns_when_a_funnel_environment_has_no_auth_key(tmp_path: Path) -> None:
    text = summary(tmp_path, HAS_TS_AUTHKEY="false")
    assert "the `TS_AUTHKEY` secret is not set" in text
    failed = summary(tmp_path, OUTCOME="failure")
    assert "INGRESS FAILED" in failed


# --------------------------------------------------------------------------- ci.yml


def test_ci_lints_every_deploy_script() -> None:
    ci = yaml.safe_load(CI.read_text())
    lint = next(s for j in ci["jobs"].values() for s in j.get("steps", []) if s.get("name") == "Shellcheck")
    assert "deploy/vm/*.sh" in lint["run"] and "deploy/pc/*.sh" in lint["run"]
    assert "shopt -s nullglob" in lint["run"]


def test_ci_validates_both_ingress_overlays() -> None:
    ci = yaml.safe_load(CI.read_text())
    check = next(s for j in ci["jobs"].values() for s in j.get("steps", []) if s.get("name") == "Validate compose files")
    for overlay in ("docker-compose.vm.yml", "docker-compose.caddy.yml", "docker-compose.funnel.yml",
                    "docker-compose.edge.yml"):
        assert f"deploy/vm/{overlay}" in check["run"], overlay


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI is not installed")
def test_ci_compose_validation_step_passes(tmp_path: Path) -> None:
    ci = yaml.safe_load(CI.read_text())
    check = next(s for j in ci["jobs"].values() for s in j.get("steps", []) if s.get("name") == "Validate compose files")
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", check["run"]],  # noqa: S607
        capture_output=True, text=True, timeout=120, cwd=REPO_ROOT,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), **check["env"]},
    )
    if "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin is not installed")
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_every_deploy_script_passes_shellcheck() -> None:
    scripts = sorted([*(REPO_ROOT / "deploy" / "vm").glob("*.sh"), *(REPO_ROOT / "deploy" / "pc").glob("*.sh")])
    assert scripts
    proc = subprocess.run(
        ["shellcheck", *map(str, scripts)],  # noqa: S607
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
