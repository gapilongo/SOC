"""Supply-chain and secret-scanning policy for .github/workflows/ci.yml and scripts/ci."""

from __future__ import annotations

import re
import tomllib
from typing import Any, Dict, List

import yaml

from tests.deploy._support import REPO_ROOT

CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GITLEAKS = REPO_ROOT / "scripts" / "ci" / "gitleaks.toml"
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def workflow() -> Dict[str, Any]:
    data = yaml.safe_load(CI.read_text())
    assert isinstance(data, dict)
    return data


def steps() -> List[Dict[str, Any]]:
    return [step for job in workflow()["jobs"].values() for step in job.get("steps", [])]


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    uses = [step["uses"] for step in steps() if "uses" in step]
    assert uses, "the workflow uses actions"
    unpinned = [u for u in uses if not SHA_PIN.match(u)]
    assert unpinned == [], "pin actions by full commit SHA (with a # vX.Y.Z comment)"
    # The human-readable version rides along as a trailing comment.
    for line in CI.read_text().splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$", line), line.strip()


def test_container_images_are_pinned_by_digest() -> None:
    wf = workflow()
    assert re.search(r"@sha256:[0-9a-f]{64}$", wf["env"]["GITLEAKS_IMAGE"])
    for job in wf["jobs"].values():
        for name, service in job.get("services", {}).items():
            assert re.search(r"@sha256:[0-9a-f]{64}$", service["image"]), name


def test_workflow_permissions_are_read_only() -> None:
    wf = workflow()
    assert wf["permissions"] == {"contents": "read"}
    for name, job in wf["jobs"].items():
        assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}, name
    for step in steps():
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_dependabot_keeps_pins_current() -> None:
    config = yaml.safe_load((REPO_ROOT / ".github" / "dependabot.yml").read_text())
    ecosystems = {u["package-ecosystem"] for u in config["updates"]}
    assert {"github-actions", "docker"} <= ecosystems


def test_gitleaks_scans_tests_and_allowlists_only_named_fixtures() -> None:
    config = tomllib.loads(GITLEAKS.read_text())
    allow = config["allowlist"]
    assert not allow.get("paths"), "no path allowlist: tests/ must be scanned too"
    assert allow["regexTarget"] == "secret"
    for rx in allow["regexes"]:
        re.compile(rx)
    # A realistic credential in a test fixture is not allowlisted. (Assembled at
    # runtime so this file does not itself trip the scanner.)
    for candidate in ("AKIA" + "Z7QX4JH2KD9WPL3M", "ghp_" + "R4nd0mT0kenV4lu3xQz8Kp2Lm9Nw7Bv5Cy1Ds3F",
                      "sk_live_" + "51HqLyjWDarjtT1zdp7dc"):
        assert not any(re.search(rx, candidate) for rx in allow["regexes"]), candidate
    # The known synthetic fixtures are.
    for fixture in ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "sk_live_abcdefghijklmnop1234", "abcdef123456"):
        assert any(re.search(rx, fixture) for rx in allow["regexes"]), fixture


def test_full_history_secret_scan_runs_weekly() -> None:
    wf = workflow()
    triggers = wf[True] if True in wf else wf["on"]  # PyYAML reads the bare `on` key as boolean true
    assert triggers["schedule"], "weekly schedule"
    job = wf["jobs"]["gitleaks-history"]
    checkout = job["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0
    run = job["steps"][1]["run"]
    assert "--log-opts=\"--all\"" in run
    assert "scripts/ci/gitleaks-history.ignore" in run
    ignore = (REPO_ROOT / "scripts" / "ci" / "gitleaks-history.ignore").read_text().splitlines()
    fingerprints = [line for line in ignore if line and not line.startswith("#")]
    assert fingerprints and all(re.fullmatch(r"[0-9a-f]{40}:[^:]+:[\w-]+:\d+", f) for f in fingerprints)


def test_image_job_runs_the_stack_smoke_test_on_the_built_image() -> None:
    job = workflow()["jobs"]["docker"]
    names = [s.get("name", "") for s in job["steps"]]
    smoke = next(s for s in job["steps"] if s.get("name", "").startswith("Stack smoke test"))
    assert smoke["run"].strip() == "scripts/smoke_stack.sh --no-build"
    assert smoke["env"]["APP_IMAGE"] == "lg-sotf:ci"
    # It must run after the build step that loads lg-sotf:ci into the local daemon.
    build = next(i for i, s in enumerate(job["steps"]) if s.get("name") == "Build (no push)")
    assert job["steps"][build]["with"]["load"] is True and names.index(smoke["name"]) > build
    assert job["timeout-minutes"] >= 20
    lint = next(s for s in steps() if s.get("name") == "Shellcheck")
    assert "scripts/smoke_stack.sh" in lint["run"]
