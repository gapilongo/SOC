"""What a pull request runs, from the paths it changes: scripts/ci/changed_areas.py and the conditions of ci.yml.

The classification is pinned here as "given these paths, these jobs run", by evaluating every job's
condition in ci.yml the way GitHub does. A new job, or a new condition, fails until it is placed below.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Set

import pytest
import yaml

from tests.deploy._support import REPO_ROOT

CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SCRIPT = REPO_ROOT / "scripts" / "ci" / "changed_areas.py"

BACKEND = "needs.changes.outputs.backend == 'true'"
STACK = "needs.changes.outputs.stack == 'true'"
NOT_A_PULL_REQUEST = "github.event_name != 'pull_request'"
BY_HAND_OR_WEEKLY = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"

# Every job of ci.yml, by when it runs.
ALWAYS = {"changes", "lint", "fast", "api-compat", "schemas", "eval-gate", "security", "helm"}
BACKEND_JOBS = {"test-parallel", "upgrade", "wazuh-contract"}
STACK_JOBS = {"docker", "frontend", "sbom", "e2e-ui"}
NEVER_ON_A_PULL_REQUEST = {"test", "parallel-parity"}
WEEKLY = {"gitleaks-history"}
EVERYTHING_ON_A_PULL_REQUEST = ALWAYS | BACKEND_JOBS | STACK_JOBS


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("changed_areas", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _jobs() -> Dict[str, Dict[str, Any]]:
    jobs: Dict[str, Dict[str, Any]] = yaml.safe_load(CI.read_text())["jobs"]
    return jobs


def _needs(job: Dict[str, Any]) -> List[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def jobs_that_run(event: str, paths: List[str]) -> Set[str]:
    """The jobs of ci.yml that run: a job runs when its ``if`` holds and none of its needs was skipped."""
    script = _script()
    areas = script.classify(paths) if event == "pull_request" else script.EVERYTHING
    holds = {
        BACKEND: areas["backend"],
        STACK: areas["stack"],
        NOT_A_PULL_REQUEST: event != "pull_request",
        BY_HAND_OR_WEEKLY: event in ("schedule", "workflow_dispatch"),
    }
    pending, running = dict(_jobs()), set()
    while pending:
        ready = [key for key, job in pending.items() if not any(n in pending for n in _needs(job))]
        assert ready, f"a cycle in needs: {sorted(pending)}"
        for key in ready:
            job = pending.pop(key)
            condition = job.get("if")
            assert condition is None or condition in holds, f"{key}: place the condition {condition!r} in this test"
            if all(n in running for n in _needs(job)) and (condition is None or holds[condition]):
                running.add(key)
    return running


def test_every_job_is_placed() -> None:
    assert set(_jobs()) == EVERYTHING_ON_A_PULL_REQUEST | NEVER_ON_A_PULL_REQUEST | WEEKLY


PROSE = ["README.md", "CHANGELOG.md", "docs/cicd.md", "docs/adr/0001-layering.md", "docs/screenshots/overview.png",
         "docs/media/tour.mp4", "changelog.d/faster-ci.md", ".github/pull_request_template.md"]
WEB_UI = ["src/lg_front/src/app/Layout.tsx", "src/lg_front/e2e/triage.spec.ts", "src/lg_front/README.md"]


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (PROSE, ALWAYS),
        (WEB_UI, ALWAYS | STACK_JOBS),
        ([*WEB_UI, *PROSE], ALWAYS | STACK_JOBS),
        (["src/lg_front/package-lock.json"], ALWAYS | STACK_JOBS),
        (["src/lg_sotf/api/app.py"], EVERYTHING_ON_A_PULL_REQUEST),
        (["tests/integration/api/test_alerts.py"], EVERYTHING_ON_A_PULL_REQUEST),
        ([*PROSE, "src/lg_sotf/api/app.py"], EVERYTHING_ON_A_PULL_REQUEST),
        ([*WEB_UI, "docs/openapi.json"], EVERYTHING_ON_A_PULL_REQUEST),
        # A workflow, a lock file, a Dockerfile, a script, the chart: everything.
        ([".github/workflows/ci.yml"], EVERYTHING_ON_A_PULL_REQUEST),
        (["requirements.txt"], EVERYTHING_ON_A_PULL_REQUEST),
        (["docker/Dockerfile"], EVERYTHING_ON_A_PULL_REQUEST),
        (["scripts/ci/changed_areas.py"], EVERYTHING_ON_A_PULL_REQUEST),
        (["deploy/helm/lg-sotf/values.yaml"], EVERYTHING_ON_A_PULL_REQUEST),
        # Not prose although it lives with the prose: data that tests and builds read.
        (["docs/openapi.json"], EVERYTHING_ON_A_PULL_REQUEST),
        (["docs/tools/export_feedback.sql"], EVERYTHING_ON_A_PULL_REQUEST),
        (["docs/roadmap/engineering-backlog.json"], EVERYTHING_ON_A_PULL_REQUEST),
        (["tests/fixtures/eval/README.md"], EVERYTHING_ON_A_PULL_REQUEST),
        (["src/lg_sotf/prompts/triage.md"], EVERYTHING_ON_A_PULL_REQUEST),
        # Anything this test has never heard of, and a diff with no path at all.
        (["some/new/thing.cfg"], EVERYTHING_ON_A_PULL_REQUEST),
        ([], EVERYTHING_ON_A_PULL_REQUEST),
    ],
)
def test_a_pull_request_runs_what_its_paths_can_affect(paths: List[str], expected: Set[str]) -> None:
    assert jobs_that_run("pull_request", paths) == expected


@pytest.mark.parametrize(
    ("event", "extra"),
    [("push", set()), ("schedule", WEEKLY), ("workflow_dispatch", WEEKLY)],
)
def test_main_the_schedule_and_a_manual_run_skip_nothing(event: str, extra: Set[str]) -> None:
    """The release train reads every gate on the commit it tags: a prose-only merge still runs them all."""
    assert jobs_that_run(event, PROSE) == EVERYTHING_ON_A_PULL_REQUEST | NEVER_ON_A_PULL_REQUEST | extra
    assert _script().decide(event, "") == {"backend": True, "stack": True, "cve_gate": True}


def test_the_serial_suite_and_the_release_gates_never_depend_on_the_changed_paths() -> None:
    jobs = _jobs()
    assert jobs["test"]["if"] == NOT_A_PULL_REQUEST and "needs" not in jobs["test"]
    assert jobs["test-parallel"]["if"] == BACKEND and jobs["upgrade"]["if"] == BACKEND
    assert jobs["docker"]["if"] == STACK
    for key in ALWAYS:
        assert "if" not in jobs[key] and "needs" not in jobs[key], key


@pytest.mark.parametrize(
    ("path", "blocks"),
    [
        ("docker/Dockerfile", True), ("src/lg_front/Dockerfile", True), (".dockerignore", True),
        ("requirements.txt", True), ("docker/requirements-build.txt", True),
        ("src/lg_front/package-lock.json", True), ("src/lg_front/package.json", True),
        (".trivyignore", True), (".github/workflows/ci.yml", True), ("scripts/ci/changed_areas.py", True),
        ("src/lg_sotf/api/app.py", False), ("src/lg_front/src/app/Layout.tsx", False), ("docs/security.md", False),
        ("security/vex.json", False),
    ],
)
def test_the_cve_gate_blocks_a_pull_request_that_changes_an_image_input(path: str, blocks: bool) -> None:
    assert _script().classify([path])["cve_gate"] is blocks
    assert _script().classify(["README.md", path])["cve_gate"] is blocks


def test_the_changes_job_reads_the_merge_commit_and_only_reads() -> None:
    job = _jobs()["changes"]
    assert set(job["outputs"]) == {"backend", "stack", "cve_gate"}
    for name, value in job["outputs"].items():
        assert value == f"${{{{ steps.areas.outputs.{name} }}}}"
    checkout, classify = job["steps"]
    assert checkout["with"] == {"persist-credentials": False, "fetch-depth": 2}
    assert classify["id"] == "areas" and classify["run"] == "python3 scripts/ci/changed_areas.py"
    assert classify["env"] == {"PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}"}
    assert "continue-on-error" not in job and "permissions" not in job
    assert os.access(SCRIPT, os.X_OK)


def test_what_the_backend_image_copies_from_the_prose_exists() -> None:
    """A prose-only pull request skips the image build, so the one prose file the image copies is checked here."""
    assert "COPY pyproject.toml setup.py README.md LICENSE ./" in (REPO_ROOT / "docker" / "Dockerfile").read_text()
    assert (REPO_ROOT / "README.md").is_file()
    assert _script().area("README.md") == "docs" and _script().area("LICENSE") == "other"


# --------------------------------------------------------------------------- the script against a real merge commit


def _git(repo: Path, *args: str) -> str:
    env = {
        "PATH": os.environ["PATH"], "HOME": str(repo), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    done = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env)  # noqa: S607
    return done.stdout.strip()


def _merge_commit(repo: Path, changes: Dict[str, str], move: bool = False) -> str:
    """A base branch, a pull request branch that writes ``changes``, and their merge checked out; returns the head."""
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n")
    (repo / "README.md").write_text("# readme\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "pr")
    if move:
        (repo / "docs").mkdir()
        _git(repo, "mv", "src/app.py", "docs/app.md")
    for name, text in changes.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "change")
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    (repo / "other.txt").write_text("the base moved on\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base moves")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "pr")
    return head


def _run_script(repo: Path, event: str, head: str) -> Dict[str, str]:
    out = repo / "github-output"
    out.write_text("")
    env = {"PATH": os.environ["PATH"], "GITHUB_EVENT_NAME": event, "PR_HEAD_SHA": head, "GITHUB_OUTPUT": str(out),
           "GIT_CEILING_DIRECTORIES": str(repo.parent),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    done = subprocess.run([sys.executable, str(SCRIPT)], cwd=repo, capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return dict(line.split("=", 1) for line in out.read_text().splitlines())


ALL_TRUE = {"backend": "true", "stack": "true", "cve_gate": "true"}


def test_the_script_classifies_the_merge_commit_of_a_pull_request(tmp_path: Path) -> None:
    prose = tmp_path / "prose"
    head = _merge_commit(prose, {"README.md": "# readme, edited\n", "docs/guide.md": "guide\n"})
    assert _run_script(prose, "pull_request", head) == {"backend": "false", "stack": "false", "cve_gate": "false"}
    # The base moving on (other.txt) is not part of the pull request's change.
    web = tmp_path / "web"
    head = _merge_commit(web, {"src/lg_front/src/App.tsx": "export {}\n", "src/lg_front/package-lock.json": "{}\n"})
    assert _run_script(web, "pull_request", head) == {"backend": "false", "stack": "true", "cve_gate": "true"}
    code = tmp_path / "code"
    head = _merge_commit(code, {"src/app.py": "x = 2\n", "README.md": "# readme, edited\n"})
    assert _run_script(code, "pull_request", head) == {"backend": "true", "stack": "true", "cve_gate": "false"}


def test_a_file_moved_out_of_the_code_into_the_prose_is_a_code_change(tmp_path: Path) -> None:
    repo = tmp_path / "moved"
    head = _merge_commit(repo, {}, move=True)
    assert _run_script(repo, "pull_request", head)["backend"] == "true"


def test_any_doubt_about_the_diff_runs_everything(tmp_path: Path) -> None:
    repo = tmp_path / "doubt"
    head = _merge_commit(repo, {"README.md": "# readme, edited\n"})
    # Another event: everything, whatever changed.
    assert _run_script(repo, "push", head) == ALL_TRUE
    # Not the merge commit of this pull request: no head given, another head, or a plain commit checked out.
    assert _run_script(repo, "pull_request", "") == ALL_TRUE
    assert _run_script(repo, "pull_request", "0" * 40) == ALL_TRUE
    _git(repo, "checkout", "-q", head)
    assert _run_script(repo, "pull_request", head) == ALL_TRUE
    # Not a git checkout at all.
    assert _run_script(tmp_path, "pull_request", head) == ALL_TRUE
