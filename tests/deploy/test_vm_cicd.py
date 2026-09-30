"""CI/CD to the dev and uat VMs: release-images.yml, deploy.yml and deploy/vm (docs/cicd.md).

Structure and policy only (no network, no cloud): environments, permissions,
pinned actions, host-key checking, how secrets travel, the VM compose overlay,
the Caddy templates and the shell scripts. The end-to-end behaviour of
deploy/vm/deploy.sh (fresh deploy, redeploy, automatic rollback) is exercised
against a real Docker host as described in docs/cicd.md.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set, Tuple

import pytest
import yaml

from tests.deploy._support import DOCKER_DIR, REPO_ROOT
from tests.deploy.test_compose import PROD_SECRETS, compose_config, load, requires_compose

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release-images.yml"
DEPLOY = WORKFLOWS / "deploy.yml"
VM = REPO_ROOT / "deploy" / "vm"
DOCS = REPO_ROOT / "docs" / "cicd.md"
SCRIPTS = [VM / "bootstrap.sh", VM / "deploy.sh", VM / "backup.sh"]
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def workflow(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)
    return data


def triggers(wf: Dict[Any, Any]) -> Dict[str, Any]:
    return wf[True] if True in wf else wf["on"]  # PyYAML reads the bare `on` key as boolean true


def steps(wf: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    for name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            yield name, step


# --------------------------------------------------------------------------- release-images.yml


def test_images_are_built_only_after_green_ci_on_main_and_promoted_on_tags() -> None:
    wf = workflow(RELEASE)
    on = triggers(wf)
    assert on["workflow_run"] == {"workflows": ["CI"], "types": ["completed"], "branches": ["main"]}
    assert on["push"] == {"tags": ["v*.*.*"]}
    assert set(on) == {"workflow_run", "push"}, "no pull_request trigger: that would expose packages: write"
    build_if = wf["jobs"]["build"]["if"]
    for cond in (
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        "head_repository.full_name == github.repository",
    ):
        assert cond in build_if
    assert "refs/tags/v" in wf["jobs"]["promote"]["if"]


def test_only_publishing_jobs_may_write_packages() -> None:
    wf = workflow(RELEASE)
    assert wf["permissions"] == {"contents": "read"}
    writers = {name for name, job in wf["jobs"].items() if job.get("permissions", {}).get("packages") == "write"}
    assert writers == {"build", "promote"}
    for name, job in wf["jobs"].items():
        perms = job.get("permissions")
        assert perms is not None, f"{name}: declare job permissions explicitly"
        assert perms.get("contents") == "read", name
        assert set(perms) <= {"contents", "packages"}, name


def test_images_are_multi_arch_tagged_by_sha_and_main_with_attestations() -> None:
    wf = workflow(RELEASE)
    assert wf["env"]["APP_REPO"] == "ghcr.io/gapilongo/lg-sotf"
    assert wf["env"]["FRONTEND_REPO"] == "ghcr.io/gapilongo/lg-sotf-frontend"
    assert set(wf["env"]["PLATFORMS"].split(",")) == {"linux/amd64", "linux/arm64"}
    build = wf["jobs"]["build"]["steps"]
    assert any(s.get("uses", "").startswith("docker/setup-qemu-action@") for s in build)
    assert any(s.get("uses", "").startswith("docker/setup-buildx-action@") for s in build)
    pushes = [s for s in build if s.get("uses", "").startswith("docker/build-push-action@")]
    assert len(pushes) == 2
    for s in pushes:
        w = s["with"]
        assert w["platforms"] == "${{ env.PLATFORMS }}"
        assert w["push"] is True
        assert "${{ steps.meta.outputs.tag }}" in w["tags"] and ":main" in w["tags"]
        assert w["provenance"] == "mode=max" and w["sbom"] is True
        assert w["cache-from"].startswith("type=gha") and w["cache-to"].startswith("type=gha")
        assert "REVISION=${{ steps.meta.outputs.commit }}" in w["build-args"]
    meta = next(s for s in build if s.get("id") == "meta")
    assert 'tag=sha-${HEAD_SHA:0:7}' in meta["run"]


def test_release_tags_reuse_the_main_digest_and_never_rebuild() -> None:
    wf = workflow(RELEASE)
    promote = wf["jobs"]["promote"]
    assert not any(s.get("uses", "").startswith("docker/build-push-action@") for s in promote["steps"])
    run = "\n".join(s.get("run", "") for s in promote["steps"])
    assert "git merge-base --is-ancestor" in run, "only commits on main (which CI built) can be released"
    assert "docker buildx imagetools create" in run
    assert '"$APP_REPO@$app"' in run and '"$FRONTEND_REPO@$fe"' in run, "re-tag by digest"


def test_dev_follows_main_and_uat_follows_release_tags() -> None:
    jobs = workflow(RELEASE)["jobs"]
    for job, needs, env in (("deploy-dev", "build", "dev"), ("deploy-uat", "promote", "uat")):
        call = jobs[job]
        assert call["uses"] == "./.github/workflows/deploy.yml"
        assert call["needs"] == needs
        assert call["with"]["environment"] == env
        assert call["with"]["app_digest"] == f"${{{{ needs.{needs}.outputs.app_digest }}}}"
        assert call["with"]["frontend_digest"] == f"${{{{ needs.{needs}.outputs.frontend_digest }}}}"
        assert call["secrets"] == "inherit"
        assert call["permissions"] == {"contents": "read", "packages": "read"}


# --------------------------------------------------------------------------- deploy.yml


def test_deploy_targets_github_environments_one_at_a_time() -> None:
    wf = workflow(DEPLOY)
    on = triggers(wf)
    assert set(on) == {"workflow_call", "workflow_dispatch"}
    dispatch = on["workflow_dispatch"]["inputs"]
    assert dispatch["environment"]["type"] == "choice"
    assert dispatch["environment"]["options"] == ["dev", "uat"]
    assert dispatch["image_tag"]["required"] is True
    assert on["workflow_call"]["inputs"]["environment"]["required"] is True
    job = wf["jobs"]["deploy"]
    assert job["environment"]["name"] == "${{ inputs.environment }}"
    assert job["environment"]["url"].startswith("https://${{ vars.APP_DOMAIN }}")
    assert job["concurrency"] == {"group": "deploy-${{ inputs.environment }}", "cancel-in-progress": False}
    assert 10 <= job["timeout-minutes"] <= 60
    assert wf["permissions"] == {"contents": "read"}
    assert job["permissions"] == {"contents": "read", "packages": "read"}


def test_deploy_validates_inputs_before_using_them() -> None:
    first = workflow(DEPLOY)["jobs"]["deploy"]["steps"][0]
    run = first["run"]
    assert "^(dev|uat)$" in run
    assert "sha-[0-9a-f]{7,40}" in run and "v[0-9]+" in run
    assert "APP_DOMAIN" in run and "DEPLOY_HOST" in run


def test_deploy_writes_a_job_summary_with_version_and_url() -> None:
    summary = next(s for s in workflow(DEPLOY)["jobs"]["deploy"]["steps"] if s.get("name") == "Job summary")
    assert summary["if"] == "always()"
    assert "GITHUB_STEP_SUMMARY" in summary["run"]
    assert "$IMAGE_TAG" in summary["run"] and "https://$APP_DOMAIN" in summary["run"]


def test_ssh_pins_the_host_key() -> None:
    for path in [*WORKFLOWS.glob("*.y*ml"), *VM.rglob("*")]:
        if path.is_file():
            text = path.read_text()
            assert not re.search(r"StrictHostKeyChecking\s*[= ]\s*(no|off|accept-new)", text, re.I), path
    run = "\n".join(s.get("run", "") for _, s in steps(workflow(DEPLOY)))
    assert "StrictHostKeyChecking yes" in run
    assert "UserKnownHostsFile $dir/known_hosts" in run
    assert "DEPLOY_SSH_KNOWN_HOSTS" in run and "BatchMode yes" in run
    cleanup = workflow(DEPLOY)["jobs"]["deploy"]["steps"][-1]
    assert cleanup["if"] == "always()" and 'rm -rf "$RUNNER_TEMP/ssh"' in cleanup["run"]


@pytest.mark.parametrize("path", [RELEASE, DEPLOY], ids=lambda p: p.name)
def test_no_expression_is_interpolated_into_scripts(path: Path) -> None:
    """Secrets, inputs and event data reach scripts only through env: (no injection, no echo)."""
    for job, step in steps(workflow(path)):
        run = step.get("run", "")
        for ctx in ("secrets.", "inputs.", "github.event", "vars.", "needs.", "steps."):
            assert "${{ " + ctx not in run, f"{path.name}:{job}:{step.get('name')} interpolates {ctx}"


def _secret_env_names(wf: Dict[str, Any]) -> Set[str]:
    names = set()
    for _, step in steps(wf):
        for key, value in (step.get("env") or {}).items():
            if isinstance(value, str) and "secrets." in value:
                names.add(key)
    return names


def test_secrets_are_never_printed_or_passed_as_arguments() -> None:
    wf = workflow(DEPLOY)
    secret_vars = _secret_env_names(wf)
    assert {"DEPLOY_SSH_KEY", "LG_SOTF_AUTH__JWT_SECRET", "LGSOTF_APP_PASSWORD", "GHCR_TOKEN"} <= secret_vars
    for _job, step in steps(wf):
        run = step.get("run", "")
        assert "set -x" not in run and "xtrace" not in run
        for line in run.splitlines():
            for name in secret_vars:
                if re.search(rf"\${{?{name}\b", line):
                    assert "echo" not in line, f"{step.get('name')}: {line.strip()}"
                    assert line.strip().startswith(("printf ", "[ ")), f"{step.get('name')}: {line.strip()}"
    deploy = next(s for _, s in steps(wf) if s.get("name", "").startswith("Deploy"))
    # Values are streamed on stdin with the printf builtin; the remote command
    # line carries only validated, non-secret arguments.
    assert "printf '%s=%s\\n' \"$k\" \"${!k}\"" in deploy["run"]
    remote = deploy["run"].split("| ssh", 1)[1]
    for name in secret_vars:
        assert name not in remote
    assert "--secrets-stdin" in remote


def test_every_value_the_workflow_sends_is_accepted_by_deploy_sh() -> None:
    deploy = next(s for _, s in steps(workflow(DEPLOY)) if s.get("name", "").startswith("Deploy"))
    lists = re.findall(r"keys\+?=\(([^)]*)\)", deploy["run"], re.S)
    assert lists, "the deploy step lists the keys it sends"
    sent = {key for chunk in lists for key in chunk.split()}
    script = (VM / "deploy.sh").read_text()
    accepted = set(re.search(r"ALLOWED_KEYS=\(([^)]*)\)", script, re.S).group(1).split())  # type: ignore[union-attr]
    transient = set(re.search(r"TRANSIENT_KEYS=\(([^)]*)\)", script, re.S).group(1).split())  # type: ignore[union-attr]
    assert sent <= accepted | transient
    assert transient == {"GHCR_USER", "GHCR_TOKEN"}
    required = set(re.search(r"REQUIRED_KEYS=\(([^)]*)\)", script, re.S).group(1).split())  # type: ignore[union-attr]
    assert required <= sent


def test_every_environment_secret_and_variable_is_documented() -> None:
    text = DEPLOY.read_text()
    docs = DOCS.read_text()
    secrets = set(re.findall(r"secrets\.([A-Z0-9_]+)", text)) - {"GITHUB_TOKEN"}
    variables = set(re.findall(r"vars\.([A-Z0-9_]+)", text))
    assert secrets and variables
    missing = sorted(n for n in secrets | variables if f"`{n}`" not in docs)
    assert missing == [], "document these in docs/cicd.md"


def test_docs_are_linked() -> None:
    assert "docs/cicd.md" in (REPO_ROOT / "README.md").read_text()
    assert "cicd.md" in (REPO_ROOT / "docs" / "deployment.md").read_text()


# --------------------------------------------------------------------------- deploy/vm scripts


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_scripts_are_strict_executable_and_quiet_about_secrets(path: Path) -> None:
    text = path.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "\nset -euo pipefail\n" in text
    assert "set -x" not in text
    assert os.access(path, os.X_OK)


def test_deploy_script_keeps_secrets_private_and_rolls_back() -> None:
    text = (VM / "deploy.sh").read_text()
    assert "\numask 077\n" in text
    assert 'atomic_write "$ENV_FILE" 0600' in text and 'atomic_write "$SECRETS_FILE" 0600' in text
    assert not re.search(r"echo[^\n]*\$\{(VALUES|TRANSIENT)\[", text), "never echo stored values"
    assert "--password-stdin" in text, "registry token via stdin, not argv"
    assert 'docker --config "$cfg"' in text, "the GHCR token lives in a throwaway client config"
    assert "flock" in text, "one deploy per VM at a time"
    for path in ("/healthz", "/readyz", "/api/v1/alerts", "/config.js"):
        assert f'"{path}|' in text
    assert "--resolve" in text, "health checks go through Caddy and TLS on this host"
    # Failure of the new version: redeploy the previous one and still fail the job.
    tail = text[text.index('if attempt "$NEW_APP_IMAGE"'):]
    assert 'attempt "$PREV_APP" "$PREV_FRONTEND" "$PREV_RELEASE"' in tail
    assert "ROLLED BACK" in tail and "exit 1" in tail
    assert "run --rm -T migrate" in text and "up -d --wait" in text
    assert "docker image rm" in text, "old images are pruned"


def test_deploy_script_rejects_bad_arguments_before_touching_anything(tmp_path: Path) -> None:
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed argv
            ["bash", str(VM / "deploy.sh"), "--root", str(tmp_path / "root"), *args],  # noqa: S607
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
        )

    for args, message in (
        (["--env", "Bad Name", "--domain", "x.example.org"], "--env"),
        (["--env", "dev", "--domain", "not a host"], "--domain"),
        (["--env", "dev", "--domain", "x.example.org", "--app-image", "evil;rm -rf /",
          "--frontend-image", "a/b:c"], "--app-image"),
        (["--env", "qa", "--domain", "x.example.org"], "--slot"),
        (["--env", "dev", "--domain", "x.example.org", "--tls", "none"], "--tls"),
    ):
        proc = run(*args)
        assert proc.returncode == 2, (args, proc.stderr)
        assert message in proc.stderr
    assert not (tmp_path / "root").exists()


def test_bootstrap_installs_docker_and_opens_only_ssh_and_https() -> None:
    text = (VM / "bootstrap.sh").read_text()
    assert "https://download.docker.com/linux/ubuntu" in text and "dpkg --print-architecture" in text
    assert "docker-compose-plugin" in text and "docker-buildx-plugin" in text
    assert 'usermod -aG docker "$DEPLOY_USER"' in text and 'passwd -l "$DEPLOY_USER"' in text
    # Oracle images: ACCEPT before the stock REJECT rule, persisted, without flushing Docker's chains.
    assert "-A INPUT -j REJECT --reject-with icmp-host-prohibited" in text
    assert "iptables -I INPUT" in text and "netfilter-persistent" in text
    assert "iptables -F" not in text and "iptables-restore" not in text
    for port in ("22/tcp", "80/tcp", "443/tcp"):
        assert f"ufw allow {port}" in text
    assert "ufw default deny incoming" in text
    assert "unattended-upgrades" in text and "/swapfile" in text and "fail2ban" in text
    assert '"max-size": "10m"' in text, "container log rotation"
    assert "PasswordAuthentication no" in text
    assert "lgsotf-backup.timer" in text and "User=$DEPLOY_USER" in text


def test_backup_script_verifies_dumps_and_applies_retention() -> None:
    text = (VM / "backup.sh").read_text()
    assert "pg_dump -U postgres -d lgsotf -Fc" in text
    assert "pg_restore -l" in text and "TABLE DATA" in text
    assert "-mtime +\"$KEEP_DAYS\"" in text and "-delete" in text
    assert "oci os object put" in text, "optional OCI Object Storage upload"
    assert "--yes" in text and "safety copy" in text, "restore needs confirmation and keeps a copy"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_scripts_pass_shellcheck() -> None:
    proc = subprocess.run(  # noqa: S603 - fixed argv
        ["shellcheck", "-x", *map(str, SCRIPTS)],  # noqa: S607
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- compose and Caddy

VM_ENV = {
    **PROD_SECRETS,
    "APP_IMAGE": "ghcr.io/gapilongo/lg-sotf@sha256:" + "a" * 64,
    "FRONTEND_IMAGE": "ghcr.io/gapilongo/lg-sotf-frontend@sha256:" + "b" * 64,
    "LGSOTF_ENV": "dev",
    "LGSOTF_ENV_DIR": "/opt/lg-sotf/env/dev",
    "LG_SOTF_API__FORWARDED_ALLOW_IPS": "172.31.250.10,172.31.251.2",
}


def test_vm_overlay_runs_registry_images_behind_the_shared_edge() -> None:
    overlay = load(VM / "docker-compose.vm.yml")
    services = overlay["services"]
    for name in ("migrate", "api", "worker", "scheduler"):
        assert services[name]["image"].startswith("${APP_IMAGE:?")
    assert services["frontend"]["image"].startswith("${FRONTEND_IMAGE:?")
    assert services["frontend"]["profiles"] == [], "the UI always runs on the VM"
    for name in ("api", "worker", "scheduler", "frontend"):
        assert services[name]["ports"] == [], f"{name} publishes no host port"
        assert services[name]["restart"] == "unless-stopped"
    for name, svc in services.items():
        assert svc["deploy"]["resources"]["limits"]["memory"], name
    # Ingress wiring lives in the per-mode overlays, not in the shared one.
    assert "networks" not in overlay
    assert all("networks" not in svc for svc in services.values())
    caddy = load(VM / "docker-compose.caddy.yml")
    assert caddy["networks"]["proxy"]["external"] is True
    assert caddy["networks"]["proxy"]["name"] == "${PROXY_NETWORK:-lgsotf-proxy}"
    assert caddy["services"]["api"]["networks"]["proxy"]["aliases"] == ["${LGSOTF_ENV:?set LGSOTF_ENV}-api"]
    assert caddy["services"]["frontend"]["networks"]["proxy"]["aliases"] == ["${LGSOTF_ENV:?set LGSOTF_ENV}-frontend"]
    assert set(caddy["services"]) == {"api", "frontend"}, "the Caddy overlay only adds the proxy network"


@requires_compose
def test_vm_overlay_resolves_on_top_of_the_production_override() -> None:
    cfg = compose_config(
        str(DOCKER_DIR / "docker-compose.yml"), str(DOCKER_DIR / "docker-compose.prod.yml"),
        str(VM / "docker-compose.vm.yml"), str(VM / "docker-compose.caddy.yml"), env=VM_ENV,
    )
    services = cfg["services"]
    assert set(services) == {"postgres", "redis", "migrate", "api", "worker", "scheduler", "frontend"}
    for name, svc in services.items():
        assert "build" not in svc, name
        assert not svc.get("ports"), f"{name} must not publish ports on the VM"
    assert services["api"]["image"] == VM_ENV["APP_IMAGE"]
    assert services["frontend"]["image"] == VM_ENV["FRONTEND_IMAGE"]
    assert services["api"]["environment"]["LG_SOTF_API__FORWARDED_ALLOW_IPS"] == "172.31.250.10,172.31.251.2"
    assert services["api"]["environment"]["LG_SOTF_ENVIRONMENT"] == "staging"
    assert "LG_SOTF_DATABASE__MIGRATION_URL" not in services["api"]["environment"]
    init = [v for v in services["postgres"]["volumes"] if v["target"].endswith("10-init-roles.sh")]
    assert [v["source"] for v in init] == ["/opt/lg-sotf/env/dev/postgres/init-roles.sh"]
    assert set(services["api"]["networks"]) == {"default", "edge", "proxy"}
    assert set(services["frontend"]["networks"]) == {"edge", "proxy"}
    assert cfg["networks"]["proxy"] == {"name": "lgsotf-proxy", "ipam": {}, "external": True}


@requires_compose
def test_only_caddy_publishes_ports() -> None:
    cfg = compose_config(str(VM / "docker-compose.edge.yml"), env={})
    caddy = cfg["services"]["caddy"]
    assert {(p["target"], p.get("protocol", "tcp")) for p in caddy["ports"]} == {(80, "tcp"), (443, "tcp"), (443, "udp")}
    assert caddy["cap_drop"] == ["ALL"] and caddy["read_only"] is True


def test_caddy_routes_api_and_ui_on_one_origin_without_logging_tokens() -> None:
    site = (VM / "caddy" / "site.caddy.tmpl").read_text()
    assert "@api path /api/* /healthz /readyz" in site
    assert "reverse_proxy @@ENV@@-api:8000" in site
    assert "reverse_proxy @@ENV@@-frontend:8080" in site
    assert "respond 404" in site.split("handle /metrics", 1)[1].split("}", 1)[0]
    # Defaults only, one per directive (a "?" block applies only if all are absent).
    for header in ("Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"):
        assert re.search(rf"^\theader \?{header} ", site, re.M), header
    assert not re.search(r"^\s*header\b.*Content-Security-Policy", site, re.M), "the frontend owns its CSP"
    main = (VM / "caddy" / "Caddyfile.tmpl").read_text()
    assert "exclude http.log.access http.log.error" in main, "WebSocket URLs carry the access token"
    assert "import sites/*.caddy" in main


def _placeholders(text: str) -> List[str]:
    return sorted(set(re.findall(r"@@[A-Z_]+@@", text)))


def test_templates_use_only_placeholders_that_deploy_sh_fills() -> None:
    script = (VM / "deploy.sh").read_text()
    for name in ("Caddyfile.tmpl", "site.caddy.tmpl"):
        for placeholder in _placeholders((VM / "caddy" / name).read_text()):
            assert f"s|{placeholder}|" in script, placeholder


def test_bundle_contains_what_deploy_sh_needs() -> None:
    deploy = next(s for _, s in steps(workflow(DEPLOY)) if s.get("name") == "Build the deploy bundle")
    for path in ("deploy/vm", "docker/docker-compose.yml", "docker/docker-compose.prod.yml",
                 "docker/postgres/init-roles.sh", "docker/empty-ca.crt"):
        assert path in deploy["run"]
        assert (REPO_ROOT / path).exists(), path
    # Both ingress modes travel inside deploy/vm.
    for path in ("docker-compose.caddy.yml", "docker-compose.funnel.yml", "tailscale/serve.json", "caddy"):
        assert (VM / path).exists(), path
