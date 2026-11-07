"""scripts/ci/release_train.sh (ARCH-E1.5): which tag the train cuts, and the gates it refuses to pass.

``plan`` runs on a throwaway git repository; ``gates`` runs against a stub ``gh`` that serves canned
GitHub API answers through the real ``jq`` (as ``gh api --jq`` does).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest
import yaml

from tests.deploy._support import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "ci" / "release_train.sh"
TRAIN = REPO_ROOT / ".github" / "workflows" / "release-train.yml"
COMMIT = "c" * 40


def _env(home: Path, **extra: str) -> Dict[str, str]:
    return {
        "PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com", **extra,
    }


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", *args], cwd=self.root, env=_env(self.root.parent), capture_output=True, text=True, check=True,  # noqa: S607
        )
        return proc.stdout.strip()

    def commit(self, version: str, files: Optional[Dict[str, str]] = None) -> str:
        init = self.root / "src" / "lg_sotf" / "__init__.py"
        init.parent.mkdir(parents=True, exist_ok=True)
        init.write_text(f'"""LG-SOTF."""\n\n__version__ = "{version}"\n')
        for name, text in (files or {}).items():
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", f"version {version}")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        return self.git("rev-parse", "HEAD")

    def plan(self, promote: str = "", lts: str = "false") -> tuple[int, str, Dict[str, str]]:
        out = self.root.parent / "github_output"
        out.write_text("")
        proc = subprocess.run(
            ["bash", str(SCRIPT), "plan"], cwd=self.root, capture_output=True, text=True, timeout=30,  # noqa: S607
            env=_env(self.root.parent, GITHUB_OUTPUT=str(out), PROMOTE=promote, LTS=lts),
        )
        outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
        return proc.returncode, proc.stdout + proc.stderr, outputs


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    r = Repo(tmp_path / "repo")
    r.commit("1.2.0")
    r.git("tag", "v1.2.0")
    r.commit("1.3.0", {"changelog.d/feature.md": "### Added\n\n- A feature.\n"})
    return r


def test_the_weekly_train_cuts_the_next_rc_of_mains_version(repo: Repo) -> None:
    rc, log, out = repo.plan()
    assert rc == 0, log
    head = repo.git("rev-parse", "HEAD")
    assert out == {
        "skip": "false", "tag": "v1.3.0-rc.1", "commit": head, "prerelease": "true",
        "channels": "partner", "lts_ref": "", "security": "false",
    }
    repo.git("tag", "v1.3.0-rc.1")
    rc, log, out = repo.plan()
    assert rc == 0 and out == {"skip": "true"} and "nothing new to ship" in log, "main has not moved"
    # A security fix lands: the next RC is numbered on and marked security-relevant.
    head = repo.commit("1.3.0", {"changelog.d/fix.md": "### Security\n\n- A fix.\n"})
    rc, log, out = repo.plan()
    assert rc == 0, log
    assert out["tag"] == "v1.3.0-rc.2" and out["commit"] == head and out["security"] == "true"


def test_the_train_waits_for_a_version_bump_once_the_version_is_released(repo: Repo) -> None:
    repo.git("tag", "v1.3.0")
    repo.commit("1.3.0", {"changelog.d/more.md": "### Fixed\n\n- More.\n"})
    rc, log, out = repo.plan()
    assert rc == 0 and out == {"skip": "true"} and "bump __version__" in log


def test_promotion_makes_the_stable_tag_and_moves_lts_forward_only(repo: Repo) -> None:
    rc_commit = repo.git("rev-parse", "HEAD")
    repo.git("tag", "v1.3.0-rc.1")
    repo.commit("1.4.0")  # main moved on: promotion still takes the RC's own commit
    rc, log, out = repo.plan(promote="v1.3.0-rc.1", lts="true")
    assert rc == 0, log
    assert out == {
        "skip": "false", "tag": "v1.3.0", "commit": rc_commit, "prerelease": "false",
        "channels": "lts lts-1.3", "lts_ref": "lts-1.3", "security": "false",
    }
    rc, _, out = repo.plan(promote="v1.3.0-rc.1")
    assert rc == 0 and out["channels"] == "" and out["lts_ref"] == "", "stable without the LTS channel"
    # The LTS channel never moves back to an older commit.
    repo.git("tag", "lts-1.4", "HEAD")
    rc, log, _ = repo.plan(promote="v1.3.0-rc.1", lts="true")
    assert rc == 1 and "::error::lts-1.4 is newer than v1.3.0-rc.1" in log


@pytest.mark.parametrize(
    ("promote", "lts", "setup", "error"),
    [
        ("", "true", None, "the LTS channel takes a promoted release"),
        ("v1.3.0", "false", None, "promote takes an RC tag"),
        ("v1.3.0-rc.9", "false", None, "no tag v1.3.0-rc.9"),
        ("v1.3.0-rc.1", "false", "v1.3.0", "v1.3.0 already exists; a release tag never moves"),
        ("v1.4.0-rc.1", "false", None, "__version__ at v1.4.0-rc.1 is not 1.4.0"),
        ("v1.3.0-rc.1", "false", "off-main", "is not on main"),
    ],
)
def test_promotion_refuses(repo: Repo, promote: str, lts: str, setup: Optional[str], error: str) -> None:
    repo.git("tag", "v1.3.0-rc.1")
    repo.git("tag", "v1.4.0-rc.1", "HEAD")  # names 1.4.0 but the commit says 1.3.0
    if setup == "v1.3.0":
        repo.git("tag", "v1.3.0")
    if setup == "off-main":
        repo.git("update-ref", "refs/remotes/origin/main", "HEAD~1")
    rc, log, out = repo.plan(promote=promote, lts=lts)
    assert rc == 1 and "::error::" in log and error in log, log
    assert "tag" not in out


# --------------------------------------------------------------------------- gates

GATES = [g.strip() for g in yaml.safe_load(TRAIN.read_text())["env"]["RELEASE_GATES"].splitlines() if g.strip()]


def _run(head_branch: str = "main", status: str = "completed", conclusion: str = "success") -> Dict[str, object]:
    return {"id": 77, "run_number": 9, "head_branch": head_branch, "status": status, "conclusion": conclusion}


def _gates(tmp_path: Path, ci: List[Dict[str, object]], jobs: Dict[str, str],
           images: List[Dict[str, object]]) -> subprocess.CompletedProcess[str]:
    if not shutil.which("jq"):
        pytest.skip("jq is not installed")
    api = tmp_path / "api"
    api.mkdir()
    (api / "ci.json").write_text(json.dumps({"workflow_runs": [*ci, _run(head_branch="feature", conclusion="failure")]}))
    (api / "jobs.json").write_text(json.dumps({"jobs": [{"name": n, "conclusion": c} for n, c in jobs.items()]}))
    (api / "images.json").write_text(json.dumps({"workflow_runs": images}))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "gh $*" >> "{tmp_path}/calls"\n'
        '[ "$1" = api ] && [ "$3" = --jq ] || exit 9\n'
        'case "$2" in\n'
        f'  */workflows/ci.yml/runs\\?head_sha={COMMIT}\\&event=push\\&*) f=ci ;;\n'
        f'  */workflows/release-images.yml/runs\\?head_sha={COMMIT}\\&event=workflow_run\\&*) f=images ;;\n'
        "  */actions/runs/77/jobs*) f=jobs ;;\n"
        "  *) exit 8 ;;\n"
        "esac\n"
        f'exec jq -r "$4" "{api}/$f.json"\n'
    )
    gh.chmod(0o755)
    env = _env(tmp_path, GH_TOKEN="test-only-token", GITHUB_REPOSITORY="gapilongo/SOC",
               RELEASE_GATES="\n".join(GATES) + "\n", RELEASE_WAIT_SECONDS="0", RELEASE_POLL_SECONDS="0")
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    return subprocess.run(
        ["bash", str(SCRIPT), "gates", COMMIT], capture_output=True, text=True, timeout=30, env=env,  # noqa: S607
    )


def test_gates_pass_when_ci_the_rehearsals_and_the_signed_build_passed(tmp_path: Path) -> None:
    proc = _gates(tmp_path, [_run()], {**{g: "success" for g in GATES}, "Helm chart": "success"}, [_run()])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for gate in GATES:
        assert f"gate passed: {gate} (CI run 77)" in proc.stdout
    assert "gate passed: Release images built and signed" in proc.stdout
    assert "test-only-token" not in proc.stdout + proc.stderr


@pytest.mark.parametrize("failed", GATES)
def test_a_failed_rehearsal_job_stops_the_release(tmp_path: Path, failed: str) -> None:
    jobs = {g: ("failure" if g == failed else "success") for g in GATES}
    proc = _gates(tmp_path, [_run()], jobs, [_run()])
    assert proc.returncode == 1
    assert f"::error::CI job '{failed}' did not pass on {COMMIT}" in proc.stdout


@pytest.mark.parametrize(
    ("ci", "images", "error"),
    [
        ([_run(conclusion="failure")], [_run()], "CI on " + COMMIT + " ended 'failure'"),
        ([], [_run()], "CI on " + COMMIT + " has not finished (status: none)"),
        ([_run(status="in_progress", conclusion="")], [_run()], "has not finished (status: in_progress)"),
        ([_run()], [_run(conclusion="failure")], "Release images on " + COMMIT + " ended 'failure'"),
        ([_run()], [_run(head_branch="feature")], "Release images on " + COMMIT + " has not finished"),
    ],
)
def test_gates_fail_closed(tmp_path: Path, ci: List[Dict[str, object]], images: List[Dict[str, object]], error: str) -> None:
    proc = _gates(tmp_path, ci, {g: "success" for g in GATES}, images)
    assert proc.returncode == 1
    assert "::error::" in proc.stdout and error in proc.stdout, proc.stdout


# --------------------------------------------------------------------------- upgrade rehearsal from the LTS line


def _rehearse_from_lts(repo: Repo) -> subprocess.CompletedProcess[str]:
    script = repo.root / "scripts" / "ci" / "upgrade_rehearsal.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / "scripts" / "ci" / "upgrade_rehearsal.sh", script)
    return subprocess.run(
        ["bash", str(script), "--from", "lts"], cwd=repo.root, capture_output=True, text=True, timeout=30,  # noqa: S607
        env=_env(repo.root.parent, PATH="/nonexistent:/usr/bin:/bin"),
    )


def test_the_lts_rehearsal_is_skipped_without_an_lts_or_when_it_is_the_previous_release(repo: Repo) -> None:
    proc = _rehearse_from_lts(repo)
    assert proc.returncode == 0 and "no LTS release (lts-X.Y tag) yet" in proc.stdout, proc.stderr
    repo.git("tag", "lts-1.2", "v1.2.0")
    proc = _rehearse_from_lts(repo)
    assert proc.returncode == 0 and "lts-1.2 is the latest release (v1.2.0), rehearsed already" in proc.stdout, proc.stderr
