"""Supply-chain and secret-scanning policy for .github/workflows/ci.yml and scripts/ci."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, List

import pytest
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


WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml"))


def test_every_workflow_pins_actions_and_drops_checkout_credentials() -> None:
    """WSC-6: every workflow (not only ci.yml) holds secrets or tokens; tags are mutable."""
    assert len(WORKFLOWS) >= 3
    for path in WORKFLOWS:
        data = yaml.safe_load(path.read_text())
        for name, job in data["jobs"].items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if not uses:
                    continue
                assert SHA_PIN.match(uses), f"{path.name}:{name} uses a mutable ref: {uses}"
                if uses.startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False, f"{path.name}:{name}"


def test_frontend_dependencies_are_audited_and_updated() -> None:
    """WSC-7: npm advisories fail CI and Dependabot watches the frontend and its base images."""
    config = yaml.safe_load((REPO_ROOT / ".github" / "dependabot.yml").read_text())
    entries = {(u["package-ecosystem"], u["directory"]) for u in config["updates"]}
    assert {("npm", "/src/lg_front"), ("docker", "/src/lg_front"), ("docker", "/docker")} <= entries
    frontend = workflow()["jobs"]["frontend"]
    assert any("npm run audit:prod" in step.get("run", "") for step in frontend["steps"])


# High-signal shapes of the gitleaks default rules that fake fixtures tend to trip.
_SECRET_SHAPES = [
    re.compile(r"\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)"),
    re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b"),
    re.compile(r"\b(glpat-[\w-]{20})"),
    re.compile(r"\b(npm_[a-z0-9]{36})", re.IGNORECASE),
    re.compile(r"\b(SG\.[\w=-]{20,24}\.[\w=-]{39,50})"),
    re.compile(r"(hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56})"),
    re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36})\b"),
]


def test_tree_has_no_secret_shaped_value_outside_the_gitleaks_allowlist() -> None:
    """WSC-2: a new fake fixture must not turn the CI secret scan red unnoticed."""
    import subprocess

    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],  # noqa: S607
        cwd=REPO_ROOT, capture_output=True, check=True,
    ).stdout.decode().split("\0")
    allow = [re.compile(rx) for rx in tomllib.loads(GITLEAKS.read_text())["allowlist"]["regexes"]]
    allow.append(re.compile(r".+EXAMPLE$"))  # gitleaks' own aws-access-token allowlist (AWS documentation keys)
    leaks = []
    for name in filter(None, listed):
        path = REPO_ROOT / name
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for shape in _SECRET_SHAPES:
            for match in shape.finditer(text):
                secret = match.group(1)
                if not any(rx.search(secret) for rx in allow):
                    leaks.append(f"{name}: {secret[:12]}...")
    assert leaks == [], "allowlist the fake value in scripts/ci/gitleaks.toml or assemble it at run time"



def test_ci_and_make_type_check_the_same_files() -> None:
    # One list: pyproject.toml [tool.mypy] files; CI and `make typecheck` run bare `mypy`.
    makefile = (REPO_ROOT / "Makefile").read_text()
    assert re.search(r"^typecheck:.*\n\tmypy\n", makefile, re.MULTILINE)
    ci = CI.read_text()
    assert re.search(r"^        run: mypy$", ci, re.MULTILINE)
    assert not re.search(r"^\s+mypy\s+src/", ci + makefile, re.MULTILINE), "pass no paths to mypy; edit [tool.mypy] files"
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["tool"]["mypy"]
    assert "src/lg_sotf" in config["files"]


def test_pre_commit_ruff_matches_the_pinned_ruff() -> None:
    pinned = re.search(r"^ruff==(\S+)$", (REPO_ROOT / "requirements-dev.txt").read_text(), re.MULTILINE)
    hooks = yaml.safe_load((REPO_ROOT / ".pre-commit-config.yaml").read_text())
    [ruff] = [r for r in hooks["repos"] if r["repo"].endswith("/ruff-pre-commit")]
    assert pinned and ruff["rev"] == f"v{pinned.group(1)}"


def test_ci_enforces_the_import_contracts() -> None:
    # docs/adr/0001-layering.md: the dependency rule is checked on every push, and `make check` runs it too.
    assert re.search(r"^        run: lint-imports$", CI.read_text(), re.MULTILINE)
    assert re.search(r"^check:.*\bimport-lint\b", (REPO_ROOT / "Makefile").read_text(), re.MULTILINE)
    contracts = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["tool"]["importlinter"]["contracts"]
    assert {c["id"] for c in contracts} >= {"layers", "api-no-workflow", "mcp-thin-client", "infra-drivers"}


def test_a_fast_job_runs_the_unit_and_deploy_tiers_without_services() -> None:
    jobs = workflow()["jobs"]
    fast = jobs["fast"]
    assert "services" not in fast and not any(k.startswith("LG_SOTF_TEST_") for k in (fast.get("env") or {}))
    runs = [s.get("run", "") for s in fast["steps"]]
    assert "pytest tests/unit tests/deploy" in runs
    # The service-backed job still runs the whole suite, so coverage stays complete.
    assert any(r.startswith("pytest") and "tests/" not in r for r in (s.get("run", "") for s in jobs["test"]["steps"]))


def test_every_test_has_a_timeout() -> None:
    pytest_cfg = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"]
    assert pytest_cfg["timeout"] == 120 and pytest_cfg["timeout_method"] == "signal"


def test_coverage_floors_are_enforced_in_ci() -> None:
    runs = " ".join(s.get("run", "") for s in workflow()["jobs"]["test"]["steps"])
    assert re.search(r"--cov-fail-under=\d+", runs)
    assert "python scripts/ci/coverage_floors.py coverage.json" in runs
    omit = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["tool"]["coverage"]["run"]["omit"]
    assert "*/lg_sotf/db/migrations/*" in omit


def test_the_parallel_tier_runs_beside_the_serial_job_until_it_is_proven() -> None:
    """Roadmap Q4: xdist runs non-blocking, and a parity job compares its JUnit report with the serial one."""
    jobs = workflow()["jobs"]
    parallel = jobs["test-parallel"]
    runs = [s.get("run", "") for s in parallel["steps"]]
    assert "pytest -n 4 --dist loadfile --junitxml=junit-parallel.xml" in runs
    assert parallel["continue-on-error"] is True and parallel["env"] == jobs["test"]["env"]
    parity = jobs["parallel-parity"]
    assert parity["needs"] == ["test", "test-parallel"] and parity["continue-on-error"] is True
    assert "python3 scripts/ci/compare_junit.py junit.xml junit-parallel.xml" in [s.get("run", "") for s in parity["steps"]]
    # The blocking serial job keeps coverage and stays one process.
    assert not any("-n " in s.get("run", "") for s in jobs["test"]["steps"])
    make = (REPO_ROOT / "Makefile").read_text()
    assert "test-serial:" in make and "-n 4 --dist loadfile" in make


def test_a_nightly_job_runs_the_suite_in_random_order_with_a_pinned_plugin() -> None:
    nightly = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "nightly.yml").read_text())
    assert re.fullmatch(r"\d+\.\d+\.\d+", nightly["env"]["PYTEST_RANDOMLY_VERSION"])
    runs = " ".join(s.get("run", "") for s in nightly["jobs"]["random-order"]["steps"])
    assert '"pytest-randomly==${PYTEST_RANDOMLY_VERSION}"' in runs and "pytest -p randomly" in runs
    # Installed, pytest-randomly shuffles every run: it stays out of the dev requirements.
    assert "pytest-randomly" not in (REPO_ROOT / "requirements-dev.txt").read_text()


JUNIT = """<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">
<testcase classname="tests.a" name="test_ok"/>
<testcase classname="tests.a" name="test_skip"><skipped message="x"/></testcase>
{extra}</testsuite></testsuites>"""


def test_compare_junit_requires_the_same_tests_and_outcomes(tmp_path: Path) -> None:
    script = REPO_ROOT / "scripts" / "ci" / "compare_junit.py"
    serial, same, other = tmp_path / "s.xml", tmp_path / "p.xml", tmp_path / "o.xml"
    serial.write_text(JUNIT.format(extra=""))
    same.write_text(JUNIT.format(extra=""))
    other.write_text(JUNIT.format(extra='<testcase classname="tests.b" name="test_new"><failure message="x"/></testcase>'))
    ok = subprocess.run([sys.executable, str(script), str(serial), str(same)], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout
    assert "serial: 2 tests, passed 1, failure 0, error 0, skipped 1" in ok.stdout
    bad = subprocess.run([sys.executable, str(script), str(serial), str(other)], capture_output=True, text=True)
    assert bad.returncode == 1 and "only in the parallel run: tests.b::test_new" in bad.stdout


# --------------------------------------------------------------------------- SEC1.1: signed images

RELEASE = REPO_ROOT / ".github" / "workflows" / "release-images.yml"
DEPLOY = REPO_ROOT / ".github" / "workflows" / "deploy.yml"
COSIGN_INSTALLER = re.compile(r"^sigstore/cosign-installer@[0-9a-f]{40}$")
SIGNER = "https://github.com/gapilongo/SOC/.github/workflows/release-images.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
VERIFY_STEP = "Verify image signatures and provenance"


def _load(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)
    return data


def test_release_and_deploy_pin_every_action_with_its_version() -> None:
    for path in (RELEASE, DEPLOY):
        for line in path.read_text().splitlines():
            if re.match(r"^\s*(- )?uses: [^.]", line):
                assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$", line), f"{path.name}: {line.strip()}"


def test_release_images_sign_the_digests_and_attest_provenance() -> None:
    jobs = _load(RELEASE)["jobs"]
    sign = jobs["sign"]
    assert sign["needs"] == "build"
    uses = [s["uses"] for s in sign["steps"] if "uses" in s]
    assert any(COSIGN_INSTALLER.match(u) for u in uses)
    # The signing job runs no repository code: no checkout, no build.
    assert not any(u.startswith(("actions/checkout@", "docker/build-push-action@")) for u in uses)
    run = "\n".join(s.get("run", "") for s in sign["steps"])
    assert 'cosign sign --yes "$APP_REPO@$APP_DIGEST"' in run
    assert 'cosign sign --yes "$FRONTEND_REPO@$FRONTEND_DIGEST"' in run
    assert len(re.findall(r"cosign sign ", run)) == 2, "sign digests, never tags"
    attests = [s for s in sign["steps"] if s.get("uses", "").startswith("actions/attest@")]
    assert {a["with"]["subject-digest"] for a in attests} == {
        "${{ needs.build.outputs.app_digest }}", "${{ needs.build.outputs.frontend_digest }}",
    }
    assert {a["with"]["subject-name"] for a in attests} == {"${{ env.APP_REPO }}", "${{ env.FRONTEND_REPO }}"}
    assert all(a["with"]["push-to-registry"] is True for a in attests)
    assert jobs["deploy-dev"]["needs"] == ["build", "sign"], "nothing deploys before it is signed"


def test_id_token_write_is_scoped_to_the_signing_job_only() -> None:
    """The OIDC token mints signing certificates: only the job that runs no build step may hold it."""
    holders = []
    for path in WORKFLOWS:
        if path.name.startswith("claude"):  # the Claude review bot's own OIDC login; it signs nothing
            continue
        wf = _load(path)
        assert "id-token" not in (wf.get("permissions") or {}), path.name
        holders += [f"{path.name}:{n}" for n, j in wf["jobs"].items() if (j.get("permissions") or {}).get("id-token")]
    assert holders == ["release-images.yml:sign"]
    assert _load(RELEASE)["jobs"]["sign"]["permissions"] == {
        "contents": "read", "packages": "write", "id-token": "write", "attestations": "write",
    }


def test_deploy_verifies_signature_and_provenance_before_touching_the_host() -> None:
    wf = _load(DEPLOY)
    assert wf["env"]["SIGNER_IDENTITY"] == SIGNER
    assert wf["env"]["SIGNER_OIDC_ISSUER"] == ISSUER
    assert wf["env"]["SIGNER_REPO"] == "gapilongo/SOC"
    steps_ = wf["jobs"]["deploy"]["steps"]
    names = [s.get("name", s.get("uses", "")) for s in steps_]
    verify = steps_[names.index(VERIFY_STEP)]
    assert not any("continue-on-error" in s for s in steps_) and "if" not in verify, "fail closed, always"
    run = verify["run"]
    assert '--certificate-identity "$SIGNER_IDENTITY"' in run and '--certificate-oidc-issuer "$SIGNER_OIDC_ISSUER"' in run
    assert '--cert-identity "$SIGNER_IDENTITY"' in run and "--predicate-type https://slsa.dev/provenance/v1" in run
    assert "regex" not in run, "an exact identity, not a pattern"
    assert verify["env"]["APP_REF"] == "${{ steps.images.outputs.app_ref }}"  # repo@sha256:digest
    i = names.index(VERIFY_STEP)
    assert names.index("Resolve image digests and source commit") < i < names.index("Build the deploy bundle")
    assert i < names.index("Configure SSH (pinned host key)")
    assert COSIGN_INSTALLER.match(steps_[i - 1]["uses"])


def test_signing_and_verifying_use_the_same_cosign() -> None:
    def installer(steps_: List[Dict[str, Any]]) -> Dict[str, Any]:
        return next(s for s in steps_ if COSIGN_INSTALLER.match(s.get("uses", "")))

    signer = installer(_load(RELEASE)["jobs"]["sign"]["steps"])
    verifier = installer(_load(DEPLOY)["jobs"]["deploy"]["steps"])
    assert signer["uses"] == verifier["uses"] and signer["with"] == verifier["with"]
    assert re.fullmatch(r"v3\.\d+\.\d+", signer["with"]["cosign-release"])


def _run_verify(tmp_path: Path, cosign_rc: int = 0, gh_rc: int = 0) -> subprocess.CompletedProcess[str]:
    """Run the verify step the way GitHub does, with stub cosign, gh and docker that log their arguments."""
    wf = _load(DEPLOY)
    step = next(s for s in wf["jobs"]["deploy"]["steps"] if s.get("name") == VERIFY_STEP)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool, body in (("cosign", f"exit {cosign_rc}"), ("gh", f"exit {gh_rc}"), ("docker", "cat >/dev/null")):
        stub = bin_dir / tool
        stub.write_text(f'#!/usr/bin/env bash\necho "{tool} $*" >> "{tmp_path}/calls"\n{body}\n')
        stub.chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_text(step["run"])
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), "GH_TOKEN": "test-only-token", "ACTOR": "ci",
        "APP_REF": "ghcr.io/gapilongo/lg-sotf@sha256:" + "a" * 64,
        "FRONTEND_REF": "ghcr.io/gapilongo/lg-sotf-frontend@sha256:" + "b" * 64,
        **{k: v for k, v in wf["env"].items() if k.startswith("SIGNER_")},
    }
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],  # noqa: S607 - GitHub's bash invocation
        capture_output=True, text=True, timeout=30, env=env, stdin=subprocess.DEVNULL,
    )


def test_verify_step_checks_both_digests_with_the_exact_identity(tmp_path: Path) -> None:
    proc = _run_verify(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = (tmp_path / "calls").read_text().splitlines()
    for digest in ("a" * 64, "b" * 64):
        [cosign] = [c for c in calls if c.startswith("cosign verify ") and digest in c]
        assert f"--certificate-identity {SIGNER} --certificate-oidc-issuer {ISSUER}" in cosign
        [gh] = [c for c in calls if c.startswith("gh attestation verify oci://") and digest in c]
        assert f"--repo gapilongo/SOC --cert-identity {SIGNER} --cert-oidc-issuer {ISSUER}" in gh
        assert "--deny-self-hosted-runners" in gh
    assert "test-only-token" not in proc.stdout + proc.stderr + "\n".join(calls)


def test_docs_show_customers_the_same_exact_identity() -> None:
    security = (REPO_ROOT / "docs" / "security.md").read_text()
    airgap = (REPO_ROOT / "docs" / "air-gapped.md").read_text()
    for text in (security, airgap):
        assert f"SIGNER={SIGNER}" in text and f"ISSUER={ISSUER}" in text
        assert 'cosign verify --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER"' in text
        assert "gh attestation verify" in text
    assert "cosign save --dir" in airgap and "--trusted-root" in airgap and "--local-image" in airgap


@pytest.mark.parametrize(("cosign_rc", "gh_rc", "error"), [(1, 0, "no valid signature"), (0, 1, "no valid build provenance")])
def test_verify_step_fails_closed(tmp_path: Path, cosign_rc: int, gh_rc: int, error: str) -> None:
    proc = _run_verify(tmp_path, cosign_rc=cosign_rc, gh_rc=gh_rc)
    assert proc.returncode == 1
    assert "::error::" in proc.stdout and error in proc.stdout
    assert "verified:" not in proc.stdout, "the first failure stops the step"
