"""Self-hosting dev/uat on the owner's PC: deploy/pc and docs/self-hosting-pc.md.

Static policy checks (strict mode, privilege checks, idempotency guards, how
secrets travel, the Windows keepalive task definition) plus runs of the
scripts' safe paths with stub commands on PATH:

* configure-github.sh against a fake ``gh`` that keeps the GitHub state in a
  JSON file and records every call: secrets must arrive on stdin (never in
  argv, never printed), re-runs must keep existing secrets, --dry-run must
  change nothing;
* setup-host.sh's help and refusal paths (the rest needs root and a real WSL);
* check-host.sh against stubbed docker/tailscale/ss/df/powershell.exe.

Nothing here touches Windows, Tailscale or GitHub.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tests.deploy._support import REPO_ROOT

PC = REPO_ROOT / "deploy" / "pc"
SETUP = PC / "setup-host.sh"
CONFIGURE = PC / "configure-github.sh"
CHECK = PC / "check-host.sh"
INSTALL_DOCKER = PC / "install-docker.sh"
WINDOWS = PC / "windows-setup.ps1"
SHELL_SCRIPTS = [INSTALL_DOCKER, SETUP, CONFIGURE, CHECK]
GUIDE = REPO_ROOT / "docs" / "self-hosting-pc.md"
BASH = shutil.which("bash") or "/bin/bash"
TASK_NAME = "LG-SOTF WSL keepalive"

APP_SECRETS = [
    "POSTGRES_SUPERUSER_PASSWORD", "LGSOTF_OWNER_PASSWORD", "LGSOTF_APP_PASSWORD",
    "LG_SOTF_AUTH__JWT_SECRET", "LG_SOTF_SECURITY__ENCRYPTION_KEYS", "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY",
    "LG_SOTF_API__METRICS_TOKEN", "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD",
]
TS_SECRETS = ["TS_OAUTH_CLIENT_ID", "TS_OAUTH_SECRET", "TS_AUTHKEY"]
VARIABLES = ["DEPLOY_HOST", "DEPLOY_USER", "DEPLOY_PORT", "APP_DOMAIN", "BOOTSTRAP_ADMIN_EMAIL",
             "LLM_PROVIDER", "INGRESS", "DEPLOY_VIA_TAILSCALE"]


def code_lines(path: Path) -> List[str]:
    """Lines that are not comments (shell)."""
    return [line for line in path.read_text().splitlines() if not line.lstrip().startswith("#")]


def run(argv: List[str], env: Optional[Dict[str, str]] = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)


# --------------------------------------------------------------------------- every shell script


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_shell_scripts_are_strict_executable_and_never_trace(path: Path) -> None:
    text = path.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "\nset -euo pipefail\n" in text
    assert "set -x" not in text and "xtrace" not in text
    assert os.access(path, os.X_OK), f"chmod +x {path}"


def _without_tests_and_strings(line: str) -> str:
    line = re.sub(r"\[\[.*?\]\]", "", line)
    line = re.sub(r"'[^']*'", "''", line)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', line)


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_no_a_and_b_or_c_constructs(path: Path) -> None:
    """`A && B || C` runs C when B fails too, and older shellcheck (CI) rejects it (SC2015)."""
    offenders = [line.strip() for line in code_lines(path) if re.search(r"&&.*\|\|", _without_tests_and_strings(line))]
    assert offenders == []


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_nothing_is_piped_into_a_shell(path: Path) -> None:
    for line in code_lines(path):
        assert not re.search(r"\|\s*(sudo\s+)?(ba)?sh\b", line), line


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_shell_scripts_pass_shellcheck() -> None:
    proc = run(["shellcheck", "-x", *map(str, SHELL_SCRIPTS)])  # noqa: S607
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- install-docker.sh


def test_install_docker_keeps_docker_off_the_wsl_and_lan_ranges() -> None:
    text = INSTALL_DOCKER.read_text()
    assert '[ "$(id -u)" -eq 0 ] || die' in text
    assert '"bip": "10.200.0.1/24"' in text
    assert '"base": "10.201.0.0/16"' in text
    assert "https://download.docker.com/linux/ubuntu" in text and "Signed-By: /etc/apt/keyrings/docker.asc" in text
    assert "docs/self-hosting-pc.md, step 1" in text
    assert "newgrp docker" not in text, "Ubuntu 26.04 has no newgrp by default"


# --------------------------------------------------------------------------- setup-host.sh


def test_setup_host_help_needs_no_root() -> None:
    proc = run([BASH, str(SETUP), "--help"])
    assert proc.returncode == 0, proc.stderr
    for word in ("--auth-key-file", "--backup-time", "tag:lgsotf-host", "restrict"):
        assert word in proc.stdout


def test_setup_host_rejects_bad_arguments() -> None:
    assert run([BASH, str(SETUP), "--no-such-option"]).returncode == 64
    proc = run([BASH, str(SETUP), "--auth-key-file"])
    assert proc.returncode == 64 and "needs a value" in proc.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="runs as root")
def test_setup_host_refuses_to_run_without_root() -> None:
    proc = run([BASH, str(SETUP)])
    assert proc.returncode == 2
    assert "sudo" in proc.stderr


def test_setup_host_joins_the_tailnet_as_the_tagged_host_without_exposing_the_key() -> None:
    text = SETUP.read_text()
    assert 'TS_TAG="tag:lgsotf-host"' in text and 'TS_HOSTNAME="lgsotf-pc"' in text
    assert '"--advertise-tags=$TS_TAG" "--hostname=$TS_HOSTNAME" --accept-dns=false' in text
    assert '"--auth-key=file:$AUTH_KEY_FILE"' in text, "the auth key is read by tailscale from the file"
    assert "--authkey=$" not in text and "--auth-key=$" not in text.replace("--auth-key=file:$", "")
    # The apt repository and a pinned signing key, not a curl | sh installer.
    assert "https://pkgs.tailscale.com/stable/ubuntu/$CODENAME.noarmor.gpg" in text
    assert "https://pkgs.tailscale.com/stable/ubuntu $CODENAME main" in text
    assert 'TS_KEY_FINGERPRINT="2596A99EAAB33821893C0A79458CA832957F5868"' in text
    assert "install.sh" not in text


def test_setup_host_limits_ssh_to_the_tailnet_the_deploy_user_and_its_key() -> None:
    text = SETUP.read_text()
    dropin = text[text.index('write_file "$SSHD_DROPIN"'):]
    dropin = dropin[:dropin.index("EOF\n", dropin.index("<<EOF") + 6)]
    for line in ("ListenAddress $TS_IP", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
                 "PermitRootLogin no", "AllowUsers $DEPLOY_USER@$TAILNET_CIDR"):
        assert line in dropin
    assert 'SSHD_DROPIN="/etc/ssh/sshd_config.d/60-lgsotf.conf"' in text
    assert 'TAILNET_CIDR="100.64.0.0/10"' in text
    assert "FreeBind=yes" in text, "ssh.socket must bind the tailnet address before tailscaled is up"
    assert "sshd -t" in text and "sshd -T -C" in text, "the effective configuration is verified"
    assert "ss -Hltn 'sport = :22'" in text, "only <tailnet ip>:22 may listen"
    assert "use_service_mode" in text and "systemctl disable --now ssh.socket" in text, "ssh.service fallback"
    assert "restrict,from=" in text, "the deploy key gets no shell features and only tailnet sources"
    assert "ssh-keyscan -t ed25519" in text
    assert "StrictHostKeyChecking=yes" in text, "the end-to-end login pins the host key too"
    assert not re.search(r"StrictHostKeyChecking\s*=?\s*(no|accept-new)", text)


def test_setup_host_keeps_the_deploy_key_private_and_is_idempotent() -> None:
    text = SETUP.read_text()
    assert 'OWNER="${SUDO_USER:-}"' in text, "the key belongs to the invoking user"
    assert 'if [ ! -f "$KEY" ]; then' in text, "an existing key is kept"
    assert 'chmod 0600 "$KEY"' in text and 'chown "$OWNER:$OWNER_GROUP" "$KEY"' in text
    assert "ssh-keygen -q -t ed25519 -N ''" in text
    assert not re.search(r"(cat|echo|printf)[^\n]*\"\$KEY\"(?!\.pub)", text), "the private key is never printed"
    assert "if ! id \"$DEPLOY_USER\"" in text
    assert "cmp -s" in text, "files are rewritten only when they change"
    assert "install ok installed" in text, "packages are installed only when missing"
    assert 'if [ "$TS_BACKEND" = "Running" ]' in text, "an already connected node is not logged in again"
    assert '-m 0750 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$ROOT"' in text
    assert "passwd -l" in text


def test_setup_host_describes_restrict_accurately() -> None:
    """`restrict` removes the terminal and forwarding, not command execution."""
    guide = " ".join(GUIDE.read_text().split())
    script = SETUP.read_text()
    for text in (script, guide):
        assert "no shell" not in text
        assert "no terminal" in text and "root-equivalent" in text


SAMPLE_TS_IP = "100.101.102.103"


def render_service_dropin(ts_ip: str = SAMPLE_TS_IP) -> str:
    """The ssh.service drop-in exactly as bash writes it for a given tailnet address."""
    match = re.search(r'write_file "\$SERVICE_DROPIN" 0644 <<EOF\n(.*?\n)EOF\n', SETUP.read_text(), re.S)
    assert match, "the ssh.service drop-in heredoc"
    proc = subprocess.run(
        [BASH, "-c", f'TS_IP="$1"; cat <<EOF\n{match.group(1)}EOF\n', "render", ts_ip],
        capture_output=True, text=True, check=True, timeout=30,
    )
    return proc.stdout


def test_ssh_service_fallback_keeps_retrying_until_the_tailnet_address_exists() -> None:
    """Ubuntu's ssh.service has RestartPreventExitStatus=255, and sshd exits 255 when it cannot bind."""
    lines = render_service_dropin().splitlines()
    for line in ("[Unit]", "After=tailscaled.service", "Wants=tailscaled.service", "StartLimitIntervalSec=0",
                 "[Service]", "Restart=on-failure", "RestartPreventExitStatus=", "RestartSec=5s"):
        assert line in lines, line
    pre = [line for line in lines if line.startswith("ExecStartPre=")]
    assert len(pre) == 1
    assert pre[0].startswith("ExecStartPre=/usr/bin/timeout 60 /bin/sh -c ")
    assert f'grep -qF " inet {SAMPLE_TS_IP}/"' in pre[0]
    assert "$" not in pre[0] and "%" not in pre[0], "systemd would expand $ and % in Exec lines"
    assert "EOF" not in "".join(lines)


def _exec_start_pre(ts_ip: str, seconds: int) -> subprocess.CompletedProcess[str]:
    line = next(li for li in render_service_dropin(ts_ip).splitlines() if li.startswith("ExecStartPre="))
    argv = shlex.split(line.split("=", 1)[1])
    assert argv[:2] == ["/usr/bin/timeout", "60"]
    argv[1] = str(seconds)
    return subprocess.run(argv, capture_output=True, text=True, timeout=seconds + 30)


@pytest.mark.skipif(not (os.access("/usr/bin/ip", os.X_OK) and os.access("/usr/bin/timeout", os.X_OK)),
                    reason="needs /usr/bin/ip and /usr/bin/timeout")
def test_ssh_service_wait_ends_when_the_address_is_up_and_fails_when_it_never_is() -> None:
    addresses = subprocess.run(["/usr/bin/ip", "-4", "-o", "addr", "show"], capture_output=True, text=True).stdout
    if " inet 127.0.0.1/" not in addresses:
        pytest.skip("no 127.0.0.1 on this machine")
    assert _exec_start_pre("127.0.0.1", 10).returncode == 0
    assert _exec_start_pre("192.0.2.77", 2).returncode == 124, "fails, so Restart=on-failure tries again"


UBUNTU_SSH_SERVICE = """[Unit]
Description=OpenBSD Secure Shell server (test stand-in for Ubuntu's unit)
After=network.target

[Service]
ExecStartPre=/bin/true
ExecStart=/bin/true
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=sshd

[Install]
WantedBy=multi-user.target
"""


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed")
def test_ssh_service_dropin_is_valid_systemd_syntax(tmp_path: Path) -> None:
    (tmp_path / "ssh.service").write_text(UBUNTU_SSH_SERVICE)
    (tmp_path / "ssh.service.d").mkdir()
    (tmp_path / "ssh.service.d" / "60-lgsotf.conf").write_text(render_service_dropin())
    proc = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", str(tmp_path / "ssh.service")],  # noqa: S607 - resolved from PATH like the host does
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "SYSTEMD_UNIT_PATH": f"{tmp_path}:", "SYSTEMD_LOG_LEVEL": "warning"},
    )
    assert "60-lgsotf.conf" not in proc.stdout + proc.stderr, proc.stdout + proc.stderr


def _sshd_validation_snippet() -> str:
    """setup-host.sh's own code from the drop-in backup to the `sshd -t` verdict."""
    text = SETUP.read_text()
    start = text.index('SSHD_BACKUP=""\n')
    end_marker = '[ -z "$SSHD_BACKUP" ] || rm -f "$SSHD_BACKUP"\n'
    end = text.index(end_marker) + len(end_marker)
    write_file = re.search(r"^write_file\(\) \{\n.*?^\}\n", text, re.S | re.M)
    die = re.search(r"^die\(\) .*\n", text, re.M)
    assert write_file and die
    return "\n".join([
        "set -euo pipefail", die.group(0), "WROTE=0", write_file.group(0),
        "apt_install() { :; }", text[start:end], "echo SNIPPET-DONE",
    ])


def run_sshd_validation(tmp_path: Path, previous: Optional[str], sshd_rc: int) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    log = tmp_path / "calls.log"
    for name, body in {
        "install": f'#!/bin/sh\necho "install $*" >> "{log}"\n',
        "chown": "#!/bin/sh\nexit 0\n",
        "sshd": f'#!/bin/sh\necho "sshd $*" >> "{log}"\n'
                '[ "$STUB_SSHD_RC" -eq 0 ] || echo "/etc/ssh/sshd_config line 9: Bad configuration option: Nope" >&2\n'
                'exit "$STUB_SSHD_RC"\n',
    }.items():
        (stubs / name).write_text(body)
        (stubs / name).chmod(0o755)
    (tmp_path / "sshd_config.d").mkdir()
    (tmp_path / "ssh.socket.d").mkdir()
    dropin = tmp_path / "sshd_config.d" / "60-lgsotf.conf"
    if previous is not None:
        dropin.write_text(previous)
    script = tmp_path / "snippet.sh"
    script.write_text(_sshd_validation_snippet())
    env = {
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}", "LANG": "C.UTF-8", "STUB_SSHD_RC": str(sshd_rc),
    }
    prelude = (
        f'SSHD_DROPIN="{dropin}"; SOCKET_DROPIN="{tmp_path}/ssh.socket.d/60-lgsotf.conf"; '
        f'TS_IP={SAMPLE_TS_IP}; DEPLOY_USER=deploy; TAILNET_CIDR=100.64.0.0/10; . "{script}"'
    )
    return run([BASH, "-c", prelude], env=env)


OLD_DROPIN = "ListenAddress 100.64.9.9\nPasswordAuthentication no\nAllowUsers deploy@100.64.0.0/10\n"


def test_rejected_sshd_config_restores_the_previous_hardening(tmp_path: Path) -> None:
    proc = run_sshd_validation(tmp_path, OLD_DROPIN, sshd_rc=255)
    assert proc.returncode == 2
    assert "Bad configuration option: Nope" in proc.stderr, "the owner sees why"
    assert "restored the previous" in proc.stderr
    dropin = tmp_path / "sshd_config.d" / "60-lgsotf.conf"
    assert dropin.read_text() == OLD_DROPIN
    assert sorted(p.name for p in dropin.parent.iterdir()) == ["60-lgsotf.conf"]


def test_rejected_sshd_config_on_the_first_run_keeps_the_new_drop_in(tmp_path: Path) -> None:
    proc = run_sshd_validation(tmp_path, None, sshd_rc=255)
    assert proc.returncode == 2
    assert "is kept" in proc.stderr
    text = (tmp_path / "sshd_config.d" / "60-lgsotf.conf").read_text()
    assert f"ListenAddress {SAMPLE_TS_IP}\n" in text and "PasswordAuthentication no\n" in text


def test_accepted_sshd_config_replaces_the_drop_in_after_creating_run_sshd(tmp_path: Path) -> None:
    proc = run_sshd_validation(tmp_path, OLD_DROPIN, sshd_rc=0)
    assert proc.returncode == 0, proc.stderr
    assert "SNIPPET-DONE" in proc.stdout
    dropin = tmp_path / "sshd_config.d" / "60-lgsotf.conf"
    assert f"ListenAddress {SAMPLE_TS_IP}\n" in dropin.read_text()
    assert sorted(p.name for p in dropin.parent.iterdir()) == ["60-lgsotf.conf"], "no backup left behind"
    calls = (tmp_path / "calls.log").read_text().splitlines()
    assert calls == ["install -d -m 0755 -o root -g root /run/sshd", "sshd -t"], "sshd -t needs /run/sshd"


def test_setup_host_never_deletes_the_sshd_hardening() -> None:
    text = SETUP.read_text()
    assert 'rm -f "$SSHD_DROPIN"' not in text and "rm -f $SSHD_DROPIN" not in text
    assert text.index("install -d -m 0755 -o root -g root /run/sshd") < text.index('SSHD_CHECK="$(sshd -t 2>&1)"')
    assert text.index("/run/sshd") < text.index("sshd -T -C")


# --------------------------------------------------------------------------- configure-github.sh (fake gh)

GH_STUB = r'''
import json, os, sys

state_path = os.environ["GH_STUB_STATE"]
with open(state_path) as fh:
    state = json.load(fh)
argv = sys.argv[1:]
stdin = None


def save():
    with open(state_path, "w") as fh:
        json.dump(state, fh)


def out(obj):
    save()
    print(json.dumps(obj))
    sys.exit(0)


def fail(message, code=1):
    save()
    sys.stderr.write(message + "\n")
    sys.exit(code)


def opt(name):
    return argv[argv.index(name) + 1] if name in argv else None


if argv[:1] not in (["auth"], ["repo"]) and ("--input" in argv or argv[:2] in (["secret", "set"],)):
    stdin = sys.stdin.read()
state["calls"].append({"argv": argv, "stdin": stdin})

if argv[:2] == ["auth", "status"]:
    save()
    sys.exit(0 if state.get("authenticated", True) else 1)
if argv[:2] == ["repo", "view"]:
    out({"nameWithOwner": state["repo"]})
if argv[:2] in (["secret", "set"], ["variable", "set"]):
    kind = "secrets" if argv[0] == "secret" else "variables"
    name, env = argv[2], opt("--env")
    value = stdin if kind == "secrets" else opt("--body")
    if env:
        state["envs"].setdefault(env, {"secrets": {}, "variables": {}, "policies": []})[kind][name] = value
    else:
        state["repo_" + kind][name] = value
    save()
    sys.exit(0)
if argv[0] == "api":
    method = opt("--method") or "GET"
    path = [a for a in argv[1:] if not a.startswith("-") and a not in (opt("-H"), opt("--method"), opt("--input"))][0]
    path = path.split("?", 1)[0]
    parts = path.split("/")
    if path == "user":
        out({"id": 4242, "login": "owner"})
    if parts[:1] != ["repos"] or "/".join(parts[1:3]) != state["repo"]:
        fail("gh: Not Found (HTTP 404)")
    rest = parts[3:]
    if not rest:
        out({"full_name": state["repo"], "permissions": {"admin": state.get("admin", True)}})
    if rest[:3] == ["actions", "permissions", "workflow"]:
        out({"default_workflow_permissions": state.get("workflow_permissions", "read")})
    if rest[:3] == ["actions", "permissions", "fork-pr-contributor-approval"]:
        out({"approval_policy": "all_external_contributors"})
    if rest[:1] == ["environments"]:
        env_name = rest[1]
        env = state["envs"].get(env_name)
        if len(rest) == 2 and method == "PUT":
            env = state["envs"].setdefault(env_name, {"secrets": {}, "variables": {}, "policies": []})
            env["config"] = json.loads(stdin)
            out({"name": env_name})
        if env is None:
            fail("gh: Not Found (HTTP 404)")
        if len(rest) == 2:
            out({"name": env_name})
        if rest[2] == "secrets":
            out({"total_count": len(env["secrets"]), "secrets": [{"name": n} for n in env["secrets"]]})
        if rest[2] == "variables":
            out({"variables": [{"name": n, "value": v} for n, v in env["variables"].items()]})
        if rest[2] == "deployment-branch-policies":
            if method == "GET":
                out({"total_count": len(env["policies"]), "branch_policies": env["policies"]})
            if method == "POST":
                policy = json.loads(stdin)
                policy["id"] = 100 + len(state["calls"])
                env["policies"].append(policy)
                out(policy)
            if method == "DELETE":
                env["policies"] = [p for p in env["policies"] if str(p["id"]) != rest[3]]
                save()
                sys.exit(0)
fail("stub gh: unhandled call " + " ".join(argv), 3)
'''

SSH_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-suite-only-stub-not-a-key\n-----END OPENSSH PRIVATE KEY-----\n"
TS_VALUES = {
    "TS_OAUTH_CLIENT_ID": "kStubClient7CNTRL",
    "TS_OAUTH_SECRET": "tskey-" + "client-" + "kStubClient7CNTRL-stubOAuthSecretValue",
    "TS_AUTHKEY": "tskey-" + "auth-" + "kStubAuth7CNTRL-stubAuthKeyValue",
}
TS_FLAGS = {"TS_OAUTH_CLIENT_ID": "--ts-oauth-client-id-file", "TS_OAUTH_SECRET": "--ts-oauth-secret-file",
            "TS_AUTHKEY": "--ts-authkey-file"}


class FakeGitHub:
    def __init__(self, tmp: Path) -> None:
        self.home = tmp / "home"
        self.config = self.home / ".config" / "lg-sotf"
        self.config.mkdir(parents=True, mode=0o700)
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.state_path = tmp / "gh-state.json"
        self.secret_files = tmp / "secrets"
        self.secret_files.mkdir(mode=0o700)
        gh = self.bin / "gh"
        gh.write_text(f"#!{sys.executable}\n{GH_STUB}")
        gh.chmod(0o755)
        (self.config / "deploy_ed25519").write_text(SSH_KEY)
        (self.config / "deploy_ed25519").chmod(0o600)
        (self.config / "known_hosts").write_text("100.101.102.103 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIstubhostkey\n")
        (self.config / "deploy_host").write_text("100.101.102.103\n")
        (self.config / "tailnet").write_text("tail1234.ts.net\n")
        for name, value in TS_VALUES.items():
            path = self.secret_files / name
            path.write_text(value + "\n")
            path.chmod(0o600)
        self.write_state({"repo": "owner/soc", "envs": {}, "repo_secrets": {}, "repo_variables": {}, "calls": []})

    def write_state(self, state: Dict[str, Any]) -> None:
        self.state_path.write_text(json.dumps(state))

    @property
    def state(self) -> Dict[str, Any]:
        data = json.loads(self.state_path.read_text())
        assert isinstance(data, dict)
        return data

    def ts_file_args(self) -> List[str]:
        args: List[str] = []
        for name, flag in TS_FLAGS.items():
            args += [flag, str(self.secret_files / name)]
        return args

    def run(self, *args: str, ts_files: bool = True) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.home),
            "GH_STUB_STATE": str(self.state_path),
            "LANG": "C.UTF-8",
        }
        argv = [BASH, str(CONFIGURE), "--repo", "owner/soc", *args, *(self.ts_file_args() if ts_files else [])]
        return run(argv, env=env)

    def writes(self, since: int = 0) -> List[List[str]]:
        calls = self.state["calls"][since:]
        return [c["argv"] for c in calls if c["argv"][:2] in (["secret", "set"], ["variable", "set"])
                or (c["argv"][0] == "api" and "--method" in c["argv"])]


@pytest.fixture
def fake_gh(tmp_path: Path) -> FakeGitHub:
    return FakeGitHub(tmp_path)


def secret_values(state: Dict[str, Any]) -> List[str]:
    values = [SSH_KEY.strip(), "stubprivatekeymaterial", *TS_VALUES.values()]
    for env in state["envs"].values():
        values += [v for k, v in env["secrets"].items() if k != "DEPLOY_SSH_KNOWN_HOSTS" and v]
    return values


def assert_no_secret_leaks(state: Dict[str, Any], *outputs: str) -> None:
    values = secret_values(state)
    for call in state["calls"]:
        for arg in call["argv"]:
            for value in values:
                assert value not in arg, f"a secret value reached argv: gh {call['argv'][:3]}"
    for text in outputs:
        for value in values:
            assert value not in text, "a secret value was printed"


def test_configure_github_help() -> None:
    proc = run([BASH, str(CONFIGURE), "--help"])
    assert proc.returncode == 0
    for word in ("--env dev|uat", "--dry-run", "--rotate-app-secrets", "stdin", "~/.config/lg-sotf"):
        assert word in proc.stdout.replace("standard input", "stdin")


def test_dry_run_prints_names_only_and_changes_nothing(fake_gh: FakeGitHub) -> None:
    proc = fake_gh.run("--env", "dev", "--admin-email", "admin@example.org", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "nothing is changed" in out
    for name in (*VARIABLES, *APP_SECRETS, *TS_SECRETS, "DEPLOY_SSH_KEY", "DEPLOY_SSH_KNOWN_HOSTS"):
        assert name in out, name
    assert "https://soc-dev.tail1234.ts.net" in out
    assert "environment           dev (create)" in out
    assert "branch main" in out
    assert fake_gh.writes() == [], "a dry run must not change GitHub"
    assert not (fake_gh.config / "dev-admin-password").exists()
    assert_no_secret_leaks(fake_gh.state, proc.stdout, proc.stderr)
    assert "100.101.102.103" not in out and "admin@example.org" not in out, "names only in a dry run"


def test_dry_run_without_a_github_login_still_lists_the_names(fake_gh: FakeGitHub) -> None:
    state = fake_gh.state
    state["authenticated"] = False
    fake_gh.write_state(state)
    proc = fake_gh.run("--env", "uat", "--dry-run", ts_files=False)
    assert proc.returncode == 0, proc.stderr
    assert "gh auth login" in proc.stdout
    assert "TS_AUTHKEY(prompt)" in proc.stdout and "tag v*.*.*" in proc.stdout
    assert fake_gh.writes() == []


def test_first_run_sets_everything_through_stdin(fake_gh: FakeGitHub) -> None:
    proc = fake_gh.run("--env", "dev", "--admin-email", "admin@example.org")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    state = fake_gh.state
    env = state["envs"]["dev"]
    assert env["config"]["deployment_branch_policy"] == {"protected_branches": False, "custom_branch_policies": True}
    assert env["config"]["reviewers"] == []
    assert [(p["type"], p["name"]) for p in env["policies"]] == [("branch", "main")]
    assert env["variables"] == {
        "DEPLOY_HOST": "100.101.102.103", "DEPLOY_USER": "deploy", "DEPLOY_PORT": "22",
        "APP_DOMAIN": "soc-dev.tail1234.ts.net", "BOOTSTRAP_ADMIN_EMAIL": "admin@example.org",
        "LLM_PROVIDER": "fake", "INGRESS": "funnel", "DEPLOY_VIA_TAILSCALE": "true",
    }
    secrets = env["secrets"]
    assert set(secrets) == {*APP_SECRETS, *TS_SECRETS, "DEPLOY_SSH_KEY", "DEPLOY_SSH_KNOWN_HOSTS"}
    assert secrets["DEPLOY_SSH_KEY"] == SSH_KEY
    assert secrets["DEPLOY_SSH_KNOWN_HOSTS"].startswith("100.101.102.103 ssh-ed25519 ")
    for name, value in TS_VALUES.items():
        assert secrets[name] == value, "trimmed file content, sent as is"
    for name in ("POSTGRES_SUPERUSER_PASSWORD", "LGSOTF_OWNER_PASSWORD", "LGSOTF_APP_PASSWORD"):
        assert re.fullmatch(r"[A-Za-z0-9_-]{32}", secrets[name]), name
    assert len(secrets["LG_SOTF_SECURITY__ENCRYPTION_KEYS"]) == 44
    # Every secret went through stdin; argv carries names and options only.
    for call in state["calls"]:
        if call["argv"][:2] == ["secret", "set"]:
            assert call["argv"][3:] == ["--env", "dev", "--repo", "owner/soc"]
            assert "--body" not in call["argv"]
    admin_secret_path = fake_gh.config / "dev-admin-password"
    assert admin_secret_path.read_text().strip() == secrets["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD"]
    assert stat.S_IMODE(admin_secret_path.stat().st_mode) == 0o600
    assert str(admin_secret_path) in proc.stdout
    assert_no_secret_leaks(state, proc.stdout, proc.stderr)
    assert state["repo_variables"] == {}, "AUTO_DEPLOY_* only with --auto-deploy"


def test_rerun_keeps_existing_secrets_and_asks_nothing(fake_gh: FakeGitHub) -> None:
    assert fake_gh.run("--env", "dev", "--admin-email", "admin@example.org").returncode == 0
    before = fake_gh.state
    password_file = fake_gh.config / "dev-admin-password"
    saved_password = password_file.read_text()
    since = len(before["calls"])
    # No Tailscale files and no terminal: already-set secrets must not be asked for.
    proc = fake_gh.run("--env", "dev", "--auto-deploy", ts_files=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    after = fake_gh.state
    assert after["envs"]["dev"]["secrets"] == before["envs"]["dev"]["secrets"]
    set_now = sorted(c[2] for c in fake_gh.writes(since) if c[:2] == ["secret", "set"])
    assert set_now == ["DEPLOY_SSH_KEY", "DEPLOY_SSH_KNOWN_HOSTS"]
    assert not any(c[:2] == ["api", "--method"] and c[2] == "POST" for c in fake_gh.writes(since)), "policy kept"
    assert after["envs"]["dev"]["variables"]["BOOTSTRAP_ADMIN_EMAIL"] == "admin@example.org", "kept from GitHub"
    assert after["repo_variables"] == {"AUTO_DEPLOY_DEV": "true"}
    assert password_file.read_text() == saved_password
    assert "secrets kept" in proc.stdout
    assert_no_secret_leaks(after, proc.stdout, proc.stderr)


def test_uat_deploys_only_from_release_tags_after_review(fake_gh: FakeGitHub) -> None:
    state = fake_gh.state
    state["envs"]["uat"] = {"secrets": {}, "variables": {}, "policies": [{"id": 7, "name": "main", "type": "branch"}]}
    fake_gh.write_state(state)
    proc = fake_gh.run("--env", "uat", "--admin-email", "admin@example.org")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = fake_gh.state["envs"]["uat"]
    assert [(p["type"], p["name"]) for p in env["policies"]] == [("tag", "v*.*.*")], "the stale branch policy is removed"
    assert env["config"]["reviewers"] == [{"type": "User", "id": 4242}]
    assert env["config"]["prevent_self_review"] is False, "a solo owner approves their own deploys"
    assert env["variables"]["APP_DOMAIN"] == "soc-uat.tail1234.ts.net"
    assert (fake_gh.config / "uat-admin-password").exists()
    proc = fake_gh.run("--env", "uat", "--no-reviewer", ts_files=False)
    assert proc.returncode == 0, proc.stderr
    assert fake_gh.state["envs"]["uat"]["config"]["reviewers"] == []


def test_rotation_needs_confirmation_and_then_replaces_all_app_secrets(fake_gh: FakeGitHub) -> None:
    assert fake_gh.run("--env", "dev", "--admin-email", "admin@example.org").returncode == 0
    before = fake_gh.state["envs"]["dev"]["secrets"]
    since = len(fake_gh.state["calls"])
    proc = fake_gh.run("--env", "dev", "--rotate-app-secrets", ts_files=False)
    assert proc.returncode == 2
    assert "database" in proc.stderr and "--yes" in proc.stderr
    assert fake_gh.writes(since) == [], "nothing changes before the confirmation"
    proc = fake_gh.run("--env", "dev", "--rotate-app-secrets", "--yes", ts_files=False)
    assert proc.returncode == 0, proc.stderr
    after = fake_gh.state["envs"]["dev"]["secrets"]
    for name in APP_SECRETS:
        assert after[name] != before[name], name
    for name in TS_SECRETS:
        assert after[name] == before[name], name
    password = (fake_gh.config / "dev-admin-password").read_text().strip()
    assert password == after["LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD"]


def test_missing_tailscale_secret_without_a_terminal_fails_before_any_change(fake_gh: FakeGitHub) -> None:
    proc = fake_gh.run("--env", "dev", "--admin-email", "admin@example.org", ts_files=False)
    assert proc.returncode == 2
    assert "TS_OAUTH_CLIENT_ID" in proc.stderr and "terminal" in proc.stderr
    assert fake_gh.writes() == []


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--env", "prod"], "--env must be dev or uat"),
        (["--env", "dev", "--tailnet", "not a tailnet"], "tailnet"),
        (["--env", "dev", "--admin-email", "nobody"], "--admin-email"),
        (["--env", "dev", "--llm-provider", "gpt"], "--llm-provider"),
        (["--env", "dev", "--repo", "no-slash"], "--repo"),
    ],
)
def test_bad_arguments_are_refused_before_github_is_touched(fake_gh: FakeGitHub, args: List[str], message: str) -> None:
    proc = fake_gh.run(*args)
    assert proc.returncode == 2
    assert message in proc.stderr
    assert fake_gh.state["calls"] == []


def test_malformed_tailscale_values_are_refused_without_echoing_them(fake_gh: FakeGitHub) -> None:
    (fake_gh.secret_files / "TS_AUTHKEY").write_text("tskey-client-pasted-the-wrong-one\n")
    proc = fake_gh.run("--env", "dev", "--admin-email", "admin@example.org")
    assert proc.returncode == 2
    assert "TS_AUTHKEY must be an auth key" in proc.stderr
    assert "pasted-the-wrong-one" not in proc.stdout + proc.stderr
    assert fake_gh.writes() == []
    assert run([BASH, str(CONFIGURE), "--env", "dev", "--bogus"]).returncode == 64


def test_setup_host_files_are_required(fake_gh: FakeGitHub) -> None:
    (fake_gh.config / "deploy_host").unlink()
    proc = fake_gh.run("--env", "dev", "--admin-email", "admin@example.org")
    assert proc.returncode == 2
    assert "setup-host.sh" in proc.stderr
    assert fake_gh.state["calls"] == []


def test_configure_github_never_puts_secrets_in_argv_or_output() -> None:
    lines = code_lines(CONFIGURE)
    text = "\n".join(lines)
    for line in lines:
        if "gh secret set" in line:
            assert "--body" not in line and " -b " not in line, line
    assert re.search(r'set_secret "\$name" < <\(printf \'%s\' "\$\{NEW_SECRET\[\$name\]\}"\)', text)
    assert re.search(r'set_secret "\$name" < <\(printf \'%s\' "\$\{GEN\[\$name\]\}"\)', text)
    assert 'set_secret DEPLOY_SSH_KEY < "$KEY_FILE"' in text
    assert "read -rs" in text, "prompts hide the input"
    for line in lines:
        assert not re.search(r"\b(echo|log|warn|die)\b[^\n]*\$\{?(NEW_SECRET\[|GEN\[|REPLY_SECRET)", line), line
    assert "\numask 077\n" in CONFIGURE.read_text()
    assert "python3 \"$GENERATOR\"" in text, "values come from scripts/generate_secrets.py"


# --------------------------------------------------------------------------- check-host.sh

CHECK_STUBS = {
    "powershell.exe": """#!/bin/sh
cat <<'EOF'
USERPROFILE=C:\\Users\\tester
TASK_STATE=Ready
TASK_LOGON=S4U
TASK_LAST_RESULT=0
TASK_LAST_RUN=2026-09-29 10:00
TASK_NEXT_RUN=2026-09-29 10:05
WIN_TAILSCALE=absent
VHD_PATH=C:\\Users\\tester\\AppData\\Local\\wsl\\{x}\\ext4.vhdx
VHD_BYTES=30000000000
EOF
""",
    "wslpath": '#!/bin/sh\necho "$STUB_WINHOME"\n',
    "wslinfo": '#!/bin/sh\ncase "$1" in --version) echo 2.5.9.0 ;; *) echo nat ;; esac\n',
    "ps": '#!/bin/sh\necho systemd\n',
    "systemctl": '#!/bin/sh\ncase "$1" in is-enabled) echo enabled ;; esac\nexit 0\n',
    "ss": '#!/bin/sh\necho "${STUB_SS:-LISTEN 0 4096 100.101.102.103:22 0.0.0.0:*}"\n',
    "curl": '#!/bin/sh\nprintf 200\n',
    "df": """#!/bin/sh
for last; do :; done
echo Avail
if [ "$last" = "$STUB_C_MOUNT" ]; then echo "${STUB_C_FREE:-60000000000}"; else echo 900000000000; fi
""",
    "tailscale": """#!/bin/sh
cat <<'EOF'
{"BackendState": "Running", "Self": {"DNSName": "lgsotf-pc.tail1234.ts.net.", "Tags": ["tag:lgsotf-host"],
 "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1"]}}
EOF
""",
    "docker": r"""#!/bin/bash
args="$*"
case "$args" in
  info*) exit 0 ;;
  "version --format"*) echo 29.0.0 ;;
  "ps -q") printf 'a1\na2\n' ;;
  "network ls -q") echo n1 ;;
  "network inspect"*) echo "bridge 10.200.0.0/24 " ;;
  *"project=lgsotf-dev --filter label=com.docker.compose.service=ts"*) echo cid1 ;;
  *"project=lgsotf-dev --format"*) printf 'api=running\nts=running\n' ;;
  *"project=lgsotf-uat"*) ;;
  *"TS_SOCKET"*) echo /tmp/tailscaled.sock ;;
  *".Config.Env"*) echo "TS_AUTHKEY=tskey-auth-must-never-be-printed" ;;
  *".State.Status"*) echo running ;;
  *"status --json"*) echo '{"BackendState": "Running", "Self": {"DNSName": "soc-dev.tail1234.ts.net."}}' ;;
  *"funnel status"*) printf 'https://soc-dev.tail1234.ts.net (Funnel on)\n|-- / proxy http://127.0.0.1:8080\n' ;;
  *) echo "stub docker: unexpected: $args" >&2; exit 3 ;;
esac
""",
}


def run_check_host(tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "bin"
    stubs.mkdir(exist_ok=True)
    for name, body in CHECK_STUBS.items():
        path = stubs / name
        path.write_text(body)
        path.chmod(0o755)
    winhome = tmp_path / "winhome"
    winhome.mkdir(exist_ok=True)
    (winhome / ".wslconfig").write_text("[general]\r\ninstanceIdleTimeout=-1\r\n\r\n[wsl2]\r\nmemory=12GB\r\n")
    c_mount = tmp_path / "c"
    c_mount.mkdir(exist_ok=True)
    env = {
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "LGSOTF_C_MOUNT": str(c_mount),
        "STUB_C_MOUNT": str(c_mount),
        "STUB_WINHOME": str(winhome),
        **overrides,
    }
    return run([BASH, str(CHECK)], env=env)


def test_check_host_reports_a_healthy_host(tmp_path: Path) -> None:
    proc = run_check_host(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "FAIL" not in out
    for expected in (
        "instanceIdleTimeout=-1", f"Windows task '{TASK_NAME}'", "C: has 55.9 GB free",
        "connected as lgsotf-pc.tail1234.ts.net, tailnet address 100.101.102.103", "tagged tag:lgsotf-host",
        "sshd listens only on 100.101.102.103:22", "ts sidecar logged in as soc-dev.tail1234.ts.net",
        "Funnel is on", "https://soc-dev.tail1234.ts.net/healthz answers 200", "Environment uat",
        "not deployed", "No problems",
    ):
        assert expected in out, expected
    assert "tskey-auth" not in out, "the sidecar's environment is never printed"


def test_check_host_warns_loudly_when_c_is_nearly_full(tmp_path: Path) -> None:
    proc = run_check_host(tmp_path, STUB_C_FREE=str(6 * 1024**3))
    assert proc.returncode == 1
    assert "C: has only 6.0 GB free" in proc.stdout
    assert "C: IS NEARLY FULL" in proc.stdout


def test_check_host_fails_when_ssh_listens_beyond_the_tailnet(tmp_path: Path) -> None:
    proc = run_check_host(tmp_path, STUB_SS="LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*")
    assert proc.returncode == 1
    assert "port 22 is open on 0.0.0.0:22" in proc.stdout


def test_check_host_is_read_only() -> None:
    text = "\n".join(code_lines(CHECK))
    executed = [_without_tests_and_strings(line) for line in code_lines(CHECK)]
    assert not [line for line in executed if re.search(r"\bsudo\b", line)]
    for pattern in (
        r"^\s*systemctl (start|stop|restart|enable|disable|daemon-reload)",
        r"\bapt(-get)?\s+install", r"\bdocker (run|rm|stop|restart|kill|pull|volume rm|system prune|compose)\b",
        r"\btailscale (up|down|set|logout|serve|funnel)\b(?! status)", r">\s*/etc/",
        r"\bwsl(\.exe)? --(shutdown|terminate|update)", r"\b(powercfg|schtasks|reg)(\.exe)?\b",
        r"Register-ScheduledTask|Set-ItemProperty|New-ItemProperty",
    ):
        for line in executed:
            assert not re.search(pattern, line), f"{pattern}: {line.strip()}"
    assert '{{if eq (index (split . "=") 0) "TS_SOCKET"}}' in text, "only TS_SOCKET is read from the container env"


# --------------------------------------------------------------------------- windows-setup.ps1


def ps1() -> str:
    return WINDOWS.read_text()


def test_windows_script_is_ascii_for_windows_powershell_5_1() -> None:
    data = WINDOWS.read_bytes()
    assert data.isascii(), "Windows PowerShell 5.1 reads BOM-less scripts as ANSI"
    assert not data.startswith(b"\xef\xbb\xbf")
    text = ps1()
    for ps7_only in ("??", "?.", " && ", " || ", "-Parallel", "ternary"):
        assert ps7_only not in re.sub(r"(?m)^\s*#.*$", "", text.split("#>", 1)[1]), ps7_only


def test_windows_script_registers_the_keepalive_task_exactly() -> None:
    text = ps1()
    assert f"$TaskName = '{TASK_NAME}'" in text
    assert "New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited" in text
    assert "New-ScheduledTaskTrigger -AtStartup" in text and "$atStartup.Delay = 'PT1M'" in text
    assert "-RepetitionInterval (New-TimeSpan -Minutes 5)" in text
    assert "-RepetitionDuration" not in text, "no duration means: repeat indefinitely"
    settings = re.search(r"New-ScheduledTaskSettingsSet ([^\n]*\n[^\n]*)", text)
    assert settings is not None
    for flag in ("-AllowStartIfOnBatteries", "-DontStopIfGoingOnBatteries", "-StartWhenAvailable",
                 "-MultipleInstances IgnoreNew", "-ExecutionTimeLimit (New-TimeSpan -Minutes 5)"):
        assert flag in settings.group(1), flag
    assert "-Trigger @($atStartup, $watchdog)" in text
    assert "-Force" in text.split("Register-ScheduledTask -TaskName", 1)[1].split("\n", 2)[1], "updates in place"
    assert "'-d {0} --exec /bin/true' -f $Distro" in text
    assert "[string]$Distro = 'Ubuntu'" in text
    assert "Join-Path $programFiles 'WSL\\wsl.exe'" in text and "'System32\\wsl.exe'" in text
    assert "-Password" not in text, "S4U: no password is stored"
    assert "Unregister-ScheduledTask -TaskName $TaskName" in text and "[switch]$Uninstall" in text


def test_windows_script_requires_elevation_except_for_reports() -> None:
    text = ps1()
    assert "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" in text
    main = text.split("# ------------------------------------------------------------------ main", 1)[1]
    status = main.index("if ($Status)")
    elevation = main.index("if (-not (Test-Elevated))")
    assert status < elevation < main.index("Register-KeepaliveTask $wslExe")
    assert "exit 1" in main[elevation:main.index("Get-DistroRegistration $Distro")]
    assert "[CmdletBinding(SupportsShouldProcess = $true)]" in text


def test_windows_uninstall_works_without_wsl_or_the_distribution() -> None:
    """-Uninstall must remove the task even after the distribution was unregistered or renamed."""
    main = ps1().split("# ------------------------------------------------------------------ main", 1)[1]
    elevation = main.index("if (-not (Test-Elevated))")
    uninstall = main.index("if ($Uninstall)")
    lookup = main.index("$wslExe = Get-WslExe")
    assert elevation < uninstall < lookup < main.index("Get-DistroRegistration $Distro")
    assert main.count("Get-WslExe") == 2 and main.index("Show-Status (Get-WslExe)") < elevation, "-Status finds wsl.exe itself"
    remove = ps1()[ps1().index("function Remove-Setup"):ps1().index("function Show-NextSteps")]
    assert "$wslExe" not in remove and "Get-DistroRegistration" not in remove and "Get-WslExe" not in remove


def test_windows_script_changes_windows_only_behind_should_process() -> None:
    lines = ps1().splitlines()
    mutating = re.compile(
        r"^\s*(Register-ScheduledTask|Unregister-ScheduledTask|Start-ScheduledTask|New-ItemProperty|New-Item\b"
        r"|Remove-ItemProperty|Set-ItemProperty|Invoke-Checked 'powercfg\.exe')"
    )
    checked = 0
    for i, line in enumerate(lines):
        if not mutating.search(line):
            continue
        checked += 1
        for back in range(i - 1, -1, -1):
            if "$PSCmdlet.ShouldProcess(" in lines[back]:
                break
            assert not lines[back].startswith("function "), f"line {i + 1} runs outside ShouldProcess: {line.strip()}"
    assert checked >= 8


def test_windows_script_power_and_update_settings() -> None:
    text = ps1()
    for setting in ("@('SUB_BUTTONS', 'LIDACTION'", "@('SUB_SLEEP', 'STANDBYIDLE'", "@('SUB_SLEEP', 'HIBERNATEIDLE'"):
        assert setting in text
    assert "@('/setacvalueindex', 'SCHEME_CURRENT', $change[0], $change[1], '0')" in text, "AC values only, set to 0"
    assert "setdcvalueindex" not in text.lower(), "battery settings are left alone"
    power = text[text.index("function Set-PowerSettings"):text.index("function Set-ActiveHours")]
    assert power.index("if ($KeepHibernation)") < power.index("@('/hibernate', 'off')")
    assert "[switch]$KeepHibernation" in text
    assert "$PolicyKey = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate'" in text
    for value in ("'SetActiveHours'", "'ActiveHoursStart'", "'ActiveHoursEnd'"):
        assert value in text
    assert "$ActiveHoursLength = 18" in text


def test_windows_script_never_restarts_wsl_itself() -> None:
    for line in ps1().splitlines():
        if re.search(r"wsl(\.exe)?\s+--(shutdown|terminate|update|unregister)", line) or "Restart-Computer" in line:
            assert line.lstrip().startswith(("Write-Host", "#", ".", "*")) or "Write-Host" in line, line
    assert "claude --continue" in ps1(), "the owner is told how to resume"


def _powershell() -> Optional[List[str]]:
    for exe in ("pwsh", "powershell.exe"):
        path = shutil.which(exe)
        if path:
            return [path, "-NoProfile", "-NonInteractive", "-Command"]
    return None


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_windows_script_parses() -> None:
    shell = _powershell()
    assert shell is not None
    script = (
        "$t = [Console]::In.ReadToEnd(); $e = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseInput($t, [ref]$null, [ref]$e); "
        "if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 } else { 'PARSE-OK' }"
    )
    proc = subprocess.run([*shell, script], input=ps1(), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0 and "PARSE-OK" in proc.stdout, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- the guide


def test_guide_is_linked() -> None:
    assert "docs/self-hosting-pc.md" in (REPO_ROOT / "README.md").read_text()
    assert "self-hosting-pc.md" in (REPO_ROOT / "docs" / "deployment.md").read_text()


def _guide_policy() -> Dict[str, Any]:
    blocks = re.findall(r"```json\n(.*?)```", GUIDE.read_text(), re.S)
    return next(json.loads(re.sub(r"(?m)^\s{3}", "", b)) for b in blocks if "tagOwners" in b)


def test_guide_policy_is_valid_json_with_the_decided_rules() -> None:
    policy = _guide_policy()
    assert policy["tagOwners"] == {t: ["autogroup:admin"] for t in ("tag:soc", "tag:ci", "tag:lgsotf-host")}
    assert policy["grants"] == [
        {"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
        {"src": ["autogroup:member"], "dst": ["tag:lgsotf-host"], "ip": ["*"]},
        {"src": ["autogroup:member"], "dst": ["tag:soc"], "ip": ["tcp:443"]},
        {"src": ["tag:ci"], "dst": ["tag:lgsotf-host"], "ip": ["tcp:22"]},
    ]
    assert policy["nodeAttrs"] == [{"target": ["tag:soc"], "attr": ["funnel"]}]
    assert policy["ssh"] == []


def test_guide_policy_never_opens_the_sidecars_beyond_https() -> None:
    # In userspace mode a sidecar forwards any other port to 127.0.0.1 in the
    # namespace it shares with nginx, which trusts X-Forwarded-For from there.
    for grant in _guide_policy()["grants"]:
        assert "*" not in grant["dst"], grant
        if "tag:soc" in grant["dst"]:
            assert grant["dst"] == ["tag:soc"] and grant["ip"] == ["tcp:443"], grant


def test_guide_and_cicd_show_the_same_grants() -> None:
    section = (REPO_ROOT / "docs" / "cicd.md").read_text().split("\n## 16.", 1)[1]
    block = re.search(r'```json\n\s*"grants": (\[.*?\])\n\s*```', section, re.S)
    assert block is not None
    assert json.loads(block.group(1)) == _guide_policy()["grants"]


def test_guide_uat_rollback_commands_target_uat() -> None:
    guide = GUIDE.read_text()
    section = guide[guide.index("To redeploy or roll back uat by hand"):]
    block = re.search(r"```sh\n(.*?)```", section, re.S)
    assert block is not None
    commands = block.group(1)
    assert "/opt/lg-sotf/env/uat/releases/" in commands
    assert "--env uat --status" in commands
    assert "--env uat --domain soc-uat.<tailnet>.ts.net --rollback" in commands
    assert "dev" not in commands


def _options(script: Path) -> set[str]:
    return set(re.findall(r"^\s+(--[a-z][a-z0-9-]*)(?:\)|\|)", script.read_text(), re.M))


@pytest.mark.parametrize("script", [SETUP, CONFIGURE, CHECK], ids=lambda p: p.name)
def test_guide_uses_only_real_options_and_documents_all_of_them(script: Path) -> None:
    options = _options(script)
    assert options, script
    guide = GUIDE.read_text()
    used = set()
    in_code = False
    for line in guide.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        for span in [line] if in_code else re.findall(r"`([^`]*)`", line):
            if script.name in span:
                used |= set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", span.split(script.name, 1)[1]))
    assert used <= options | {"--help"}, sorted(used - options)
    if script is CONFIGURE:
        undocumented = sorted(o for o in options if o not in guide and o not in ("--config-dir", "--yes", "--repo"))
        assert undocumented == []


def test_guide_names_every_variable_and_secret_configure_github_sets() -> None:
    guide = GUIDE.read_text()
    for name in (*VARIABLES, *APP_SECRETS, *TS_SECRETS, "DEPLOY_SSH_KEY", "DEPLOY_SSH_KNOWN_HOSTS",
                 "AUTO_DEPLOY_DEV", "AUTO_DEPLOY_UAT", "ANTHROPIC_API_KEY"):
        assert f"`{name}" in guide, name
    script = CONFIGURE.read_text()
    assert set(re.search(r"VARIABLES=\(([^)]*)\)", script).group(1).split()) == set(VARIABLES)  # type: ignore[union-attr]
    assert set(re.search(r"APP_SECRETS=\(([^)]*)\)", script).group(1).split()) == set(APP_SECRETS)  # type: ignore[union-attr]


def test_guide_covers_the_operating_rules() -> None:
    guide = " ".join(GUIDE.read_text().split())
    for needle in (
        "non-commercial", "zrok", "10 GB", "12.7 GB", "sparse", "wsl --update", "3.0.1", "2.7.14",
        "PICK", "HTTPS Certificates", "Reusable", "Ephemeral", "Pre-approved", "Auth Keys: Write",
        "Require approval for all external contributors", "Read repository contents and packages permissions",
        "mobile data", "?token=", "#18651", "10 minutes", "soc-dev-1", "lgsotf-dev-tailscale",
        "Disable-ScheduledTask", "claude --continue", "backup.sh", "Pause updates", TASK_NAME,
        "setup-host.sh", "windows-setup.ps1", "configure-github.sh", "check-host.sh", "install-docker.sh",
        "iptables-legacy", "```mermaid",
    ):
        assert needle.lower() in guide.lower(), needle
