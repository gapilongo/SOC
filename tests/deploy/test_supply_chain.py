"""Supply-chain policy: pinned images, hash-locked installs, the CVE gate (SEC1.3); dependency policy (SEC2.3)."""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest
import yaml

from tests.deploy._support import REPO_ROOT

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
TRIVY_ACTION = re.compile(r"^aquasecurity/trivy-action@[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# Tag kept next to the digest so a reader (and Dependabot) knows what it is.
PINNED_IMAGE = re.compile(r"^[a-z0-9][\w./-]*:[\w.-]+@sha256:[0-9a-f]{64}$")

LOCKS = [
    REPO_ROOT / "requirements.txt",
    REPO_ROOT / "requirements-dev.txt",
    REPO_ROOT / "docker" / "requirements-build.txt",
    REPO_ROOT / "scripts" / "ci" / "requirements-tools.txt",
    REPO_ROOT / "scripts" / "ci" / "requirements-nightly.txt",
]


def _load(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)
    return data


def _dockerfiles() -> List[Path]:
    found = [p for p in REPO_ROOT.rglob("Dockerfile*")
             if not {"node_modules", ".git", ".venv"} & set(p.parts) and p.is_file()]
    return sorted(found)


def _from_lines(path: Path) -> List[Tuple[str, str]]:
    """(image, stage name) of every FROM, flags dropped."""
    out = []
    for line in path.read_text().splitlines():
        m = re.match(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", line, re.IGNORECASE)
        if m:
            out.append((m.group(1), m.group(2) or ""))
    return out


# --------------------------------------------------------------------------- base images


def test_every_dockerfile_from_line_resolves_to_a_digest() -> None:
    """Acceptance (SEC1.3): every FROM is digest-pinned, or an override ARG defaulting to a pinned stage."""
    files = _dockerfiles()
    assert {p.relative_to(REPO_ROOT).as_posix() for p in files} >= {"docker/Dockerfile", "src/lg_front/Dockerfile"}
    for path in files:
        text = path.read_text()
        stages: Dict[str, str] = {}
        for image, name in _from_lines(path):
            override = re.fullmatch(r"\$\{(\w+):-([\w.-]+)\}", image)
            if override:
                # ${BASE_IMAGE:-python-base}: an empty ARG (the default) selects the pinned stage.
                arg, stage = override.groups()
                assert stage in stages, f"{path.name}: {image} must fall back to an earlier pinned stage"
                assert re.search(rf"^ARG {arg}=$", text, re.MULTILINE), f"{path.name}: ARG {arg} must default to empty"
            elif image in stages:
                pass  # FROM an earlier stage
            else:
                assert PINNED_IMAGE.match(image), f"{path.name}: FROM {image} is not pinned as name:tag@sha256:digest"
            if name:
                stages[name] = image
        # The BuildKit frontend image is pulled too: pin it the same way.
        syntax = re.match(r"^# syntax=(\S+)", text)
        assert syntax and PINNED_IMAGE.match(syntax.group(1)), f"{path.name}: pin the # syntax= image by digest"


def test_overrides_default_to_the_pinned_bases_everywhere() -> None:
    """Make, compose and the quickstart pass an empty override unless the operator sets a mirror."""
    makefile = (REPO_ROOT / "Makefile").read_text()
    assert re.search(r"^PYTHON_BASE_IMAGE \?=$", makefile, re.MULTILINE)
    compose = _load(REPO_ROOT / "docker" / "docker-compose.yml")
    assert compose["x-app-build"]["args"]["BASE_IMAGE"] == "${PYTHON_BASE_IMAGE:-}"
    assert compose["services"]["frontend"]["build"]["args"] == {"NODE_IMAGE": "${NODE_IMAGE:-}", "NGINX_IMAGE": "${NGINX_IMAGE:-}"}
    assert '--build-arg BASE_IMAGE="${PYTHON_BASE_IMAGE:-}"' in (REPO_ROOT / "scripts" / "quickstart.sh").read_text()


def test_third_party_runtime_images_are_digest_pinned() -> None:
    compose = _load(REPO_ROOT / "docker" / "docker-compose.yml")["services"]
    edge = _load(REPO_ROOT / "deploy" / "vm" / "docker-compose.edge.yml")["services"]
    for ref in (compose["postgres"]["image"], compose["redis"]["image"], edge["caddy"]["image"]):
        default = re.fullmatch(r"\$\{\w+:-(.+)\}", ref)
        assert default and PINNED_IMAGE.match(default.group(1)), ref
    # deploy.sh leaves the Caddy pin to the edge compose file (one place for Dependabot to bump).
    assert 'CADDY_IMAGE "${VALUES[CADDY_IMAGE]:-}"' in (REPO_ROOT / "deploy" / "vm" / "deploy.sh").read_text()


def test_dependabot_bumps_the_pinned_digests() -> None:
    config = _load(REPO_ROOT / ".github" / "dependabot.yml")
    docker = {u["directory"] for u in config["updates"] if u["package-ecosystem"] == "docker"}
    assert {path.parent.relative_to(REPO_ROOT).as_posix() for path in _dockerfiles()} <= {d.strip("/") for d in docker}


# --------------------------------------------------------------------------- hash-locked installs


def _requirements(path: Path) -> Iterator[Tuple[str, str, List[str]]]:
    """(name, version, hashes) per requirement of a uv/pip-compile lock file."""
    for block in re.split(r"\n(?=\S)", path.read_text()):
        if block.startswith("#") or not block.strip():
            continue
        m = re.match(r"^([A-Za-z0-9][\w.-]*)==([^\s;\\]+)", block)
        assert m, f"{path.name}: unpinned requirement {block.splitlines()[0]!r}"
        yield m.group(1).lower(), m.group(2), re.findall(r"--hash=sha256:([0-9a-f]{64})", block)


@pytest.mark.parametrize("lock", LOCKS, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_lock_files_pin_every_package_with_hashes(lock: Path) -> None:
    text = lock.read_text()
    # Generated, never hand-edited: the header names the one command that rewrites it.
    assert text.startswith("# This file was autogenerated by uv via the following command:\n#    scripts/lock_requirements.sh\n")
    reqs = list(_requirements(lock))
    assert reqs
    for name, _, hashes in reqs:
        assert hashes, f"{lock.name}: {name} has no --hash"


def test_locks_carry_hashes_for_every_platform() -> None:
    """amd64 and arm64 images (and macOS dev installs) verify from one file: every wheel's hash is in it."""
    script = (REPO_ROOT / "scripts" / "lock_requirements.sh").read_text()
    assert "--universal" in script and "--generate-hashes" in script and "--python-version 3.11" in script
    hashes = {name: h for name, _, h in _requirements(REPO_ROOT / "requirements.txt")}
    # Compiled packages ship one wheel per platform and Python; a single-platform lock would hold a few.
    for name in ("asyncpg", "cryptography", "pydantic-core", "psycopg-binary", "uvloop"):
        assert len(hashes[name]) >= 20, f"{name}: {len(hashes[name])} hashes; re-lock with scripts/lock_requirements.sh"


def test_dev_lock_uses_the_runtime_versions() -> None:
    runtime = {n: v for n, v, _ in _requirements(REPO_ROOT / "requirements.txt")}
    dev = {n: v for n, v, _ in _requirements(REPO_ROOT / "requirements-dev.txt")}
    assert {n: dev.get(n) for n in runtime} == runtime, "CI tests exactly what the image ships"


def _pip_installs() -> Iterator[Tuple[str, str]]:
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        for job in _load(path)["jobs"].values():
            for step in job.get("steps", []):
                for cmd in re.findall(r"pip install [^\n&;]*", step.get("run", "")):
                    yield path.name, cmd.strip()
    for path in (REPO_ROOT / "Makefile", *_dockerfiles()):
        for line in path.read_text().splitlines():
            if not line.lstrip().startswith("#"):
                for cmd in re.findall(r"pip install [^\n&;\\]*", line):
                    yield path.relative_to(REPO_ROOT).as_posix(), cmd.strip()


def test_every_dependency_install_requires_hashes() -> None:
    """Acceptance (SEC1.3): CI, make and the image builds only install from hash-locked files."""
    installs = list(_pip_installs())
    assert len(installs) >= 10
    # The only installs without a lock file are the project itself and its freshly built wheel.
    local = {"pip install --no-deps -e .", "pip install --no-deps /dist/lg_sotf-*.whl"}
    bad = [(where, cmd) for where, cmd in installs
           if cmd not in local and not re.fullmatch(r"pip install --require-hashes (--no-deps )?-r \S+\.txt", cmd)]
    assert bad == []
    for _, cmd in installs:
        if "-r " in cmd:
            target = cmd.rsplit(" ", 1)[1]
            assert any(lock.name == Path(target).name for lock in LOCKS), cmd


def test_pip_audit_checks_every_lock() -> None:
    security = _load(CI)["jobs"]["security"]
    run = next(s["run"] for s in security["steps"] if s.get("name", "").startswith("pip-audit"))
    assert 'pip-audit --strict --progress-spinner off --disable-pip --require-hashes -r "$lock"' in run
    for lock in LOCKS:
        assert lock.relative_to(REPO_ROOT).as_posix() in run, lock.name


# --------------------------------------------------------------------------- image CVE gate


def _gate_steps() -> Dict[str, Dict[str, Any]]:
    jobs = _load(CI)["jobs"]
    out = {}
    for job_name in ("docker", "frontend"):
        steps = jobs[job_name]["steps"]
        [i] = [n for n, s in enumerate(steps) if s.get("name", "").startswith("Image CVE gate")]
        assert TRIVY_ACTION.match(steps[i]["uses"])
        build = next(n for n, s in enumerate(steps) if s.get("name", "").startswith("Build"))
        assert build < i, f"{job_name}: scan after the image is built"
        out[job_name] = steps[i]
    return out


def test_ci_fails_on_fixable_critical_or_high_image_findings() -> None:
    """Acceptance (SEC1.3): a fixable critical or high CVE in either image fails CI."""
    wf = _load(CI)
    assert re.fullmatch(r"v\d+\.\d+\.\d+", wf["env"]["TRIVY_VERSION"])
    images = {}
    for job_name, step in _gate_steps().items():
        w = step["with"]
        assert "continue-on-error" not in step and "continue-on-error" not in wf["jobs"][job_name], job_name
        assert w["exit-code"] == "1" and w["severity"] == "CRITICAL,HIGH" and w["ignore-unfixed"] is True
        assert w["scanners"] == "vuln" and w["vuln-type"] == "os,library"
        assert w["trivyignores"] == ".trivyignore" and w["version"] == "${{ env.TRIVY_VERSION }}"
        images[job_name] = w["image-ref"]
    assert images == {"docker": "lg-sotf:ci", "frontend": "lg-sotf-frontend:ci"}


def _trivyignore() -> List[Tuple[str, str, str]]:
    """(comment above, id, expiry) per entry."""
    entries, comment = [], ""
    for line in (REPO_ROOT / ".trivyignore").read_text().splitlines():
        if line.startswith("#"):
            comment += line[1:].strip() + " "
        elif line.strip():
            m = re.fullmatch(r"(CVE-\d{4}-\d+|GHSA-[\w-]+) exp:(\d{4}-\d{2}-\d{2})", line.strip())
            assert m, f".trivyignore: {line!r} needs an exp:YYYY-MM-DD"
            entries.append((comment, m.group(1), m.group(2)))
            comment = ""
        else:
            comment = ""
    return entries


def test_trivyignore_entries_are_reviewed_and_expire() -> None:
    vex = json.loads((REPO_ROOT / "security" / "vex.json").read_text())
    not_affected = {s["vulnerability"]["name"] for s in vex["statements"] if s["status"] == "not_affected"}
    for comment, vuln, expiry in _trivyignore():
        reviewed = re.search(r"Reviewed (\d{4}-\d{2}-\d{2})", comment)
        assert reviewed, f"{vuln}: say when and by whom it was reviewed"
        age = dt.date.fromisoformat(expiry) - dt.date.fromisoformat(reviewed.group(1))
        assert dt.timedelta(0) < age <= dt.timedelta(days=90), f"{vuln}: expire within 90 days of the review"
        if comment.startswith("not affected"):
            assert vuln in not_affected, f"{vuln}: publish the not_affected statement in security/vex.json"


# --------------------------------------------------------------------------- SEC1.2: SBOMs and VEX

RELEASE = WORKFLOWS / "release-images.yml"
VEX = REPO_ROOT / "security" / "vex.json"
ASSETS_SCRIPT = REPO_ROOT / "scripts" / "ci" / "release_assets.sh"
JUSTIFICATIONS = {
    "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist",
}


def _step(steps: List[Dict[str, Any]], prefix: str) -> Dict[str, Any]:
    return next(s for s in steps if s.get("name", "").startswith(prefix))


def test_ci_validates_the_sboms_and_vex_against_their_schemas() -> None:
    """Acceptance (SEC1.2): every change builds the release SBOMs and VEX and validates them."""
    jobs = _load(CI)["jobs"]
    for job_name, image in (("docker", "lg-sotf"), ("frontend", "lg-sotf-frontend")):
        sbom = _step(jobs[job_name]["steps"], "Image SBOM (CycloneDX)")
        assert TRIVY_ACTION.match(sbom["uses"]) and sbom["with"]["format"] == "cyclonedx"
        assert sbom["with"]["image-ref"] == f"{image}:ci" and sbom["with"]["output"] == f"{image}-ci-image.cdx.json"
        upload = _step(jobs[job_name]["steps"], "Upload the image SBOM")
        assert upload["with"]["path"] == f"{image}-ci-image.cdx.json"
    job = jobs["sbom"]
    assert job["needs"] == ["docker", "frontend"] and "continue-on-error" not in job
    runs = [s.get("run", "") for s in job["steps"]]
    assert "pip install --require-hashes -r scripts/ci/requirements-tools.txt" in runs
    assert "scripts/ci/release_assets.sh release-assets ci" in runs
    assert ("python scripts/ci/validate_sbom.py image-sbom/lg-sotf-ci-image.cdx.json "
            "image-sbom/lg-sotf-frontend-ci-image.cdx.json") in runs
    # The script validates every file it writes before it hashes them.
    script = ASSETS_SCRIPT.read_text()
    assert 'python3 scripts/ci/validate_sbom.py "$out"/*.json' in script
    assert script.index("validate_sbom.py \"$out\"") < script.index("sha256sum")
    for produced in ("cyclonedx-py requirements", "npm sbom --sbom-format cyclonedx --omit dev",
                     "trivy image --quiet --format cyclonedx", 'cp security/vex.json "$out/lg-sotf-$version.openvex.json"'):
        assert produced in script, produced


def test_release_tags_get_attested_sboms_and_vex_as_assets() -> None:
    """Acceptance (SEC1.2): a vX.Y.Z release carries the SBOMs and the VEX document."""
    wf = _load(RELEASE)
    jobs = wf["jobs"]
    assert wf["env"]["TRIVY_VERSION"] == _load(CI)["env"]["TRIVY_VERSION"], "one Trivy release for gate and SBOMs"
    build = jobs["release-assets"]
    assert build["needs"] == "promote" and build["permissions"] == {"contents": "read", "packages": "read"}
    checkout = next(s for s in build["steps"] if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ needs.promote.outputs.commit }}", "the tagged commit's lock files"
    setup = next(s for s in build["steps"] if s.get("uses", "").startswith("aquasecurity/setup-trivy@"))
    assert setup["with"]["version"] == "${{ env.TRIVY_VERSION }}"
    run = _step(build["steps"], "SBOMs")
    assert run["env"]["APP_DIGEST"] == "${{ needs.promote.outputs.app_digest }}"
    assert run["env"]["FRONTEND_DIGEST"] == "${{ needs.promote.outputs.frontend_digest }}"
    assert 'scripts/ci/release_assets.sh release-assets "$TAG"' in run["run"]
    assert '"lg-sotf=$APP_REPO@$APP_DIGEST" "lg-sotf-frontend=$FRONTEND_REPO@$FRONTEND_DIGEST"' in run["run"]
    assert 'PLATFORMS="${PLATFORMS//,/ }"' in run["run"], "an SBOM per platform of the multi-arch images"
    attest = jobs["attest-release-assets"]
    assert attest["needs"] == "release-assets"
    assert _step(attest["steps"], "Build provenance")["with"] == {"subject-path": "release-assets/*.json"}
    publish = jobs["publish-release-assets"]
    assert publish["needs"] == ["promote", "attest-release-assets"], "nothing is published before it is attested"
    assert publish["permissions"] == {"contents": "write"}
    assert not any(s.get("uses", "").startswith("actions/checkout@") for s in publish["steps"])
    upload = _step(publish["steps"], "Upload to the release")["run"]
    assert 'gh release upload "$TAG" release-assets/* --repo "$GITHUB_REPOSITORY" --clobber' in upload
    assert "--verify-tag" in upload


def test_vex_statements_are_justified() -> None:
    doc = json.loads(VEX.read_text())
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["statements"]
    for st in doc["statements"]:
        name = st["vulnerability"]["name"]
        assert re.fullmatch(r"CVE-\d{4}-\d+|GHSA-[\w-]+", name), name
        for product in st["products"]:
            assert product["@id"] in {"pkg:oci/lg-sotf", "pkg:oci/lg-sotf-frontend"}, name
            assert product.get("subcomponents"), f"{name}: scope the statement to the affected package"
        if st["status"] == "not_affected":
            assert st["justification"] in JUSTIFICATIONS, name
            assert len(st.get("impact_statement", "")) > 80, f"{name}: say why, for the customer's analyst"
    assert (REPO_ROOT / "security" / "schemas" / "openvex-0.2.0.schema.json").is_file()


def _validator() -> Any:
    pytest.importorskip("jsonschema")
    pytest.importorskip("cyclonedx.validation.json")
    import importlib.util

    spec = importlib.util.spec_from_file_location("validate_sbom", REPO_ROOT / "scripts" / "ci" / "validate_sbom.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validator_accepts_the_published_documents_and_rejects_broken_ones(tmp_path: Path) -> None:
    validate = _validator().validate
    assert validate(VEX) == []
    broken = json.loads(VEX.read_text())
    broken["statements"][0]["status"] = "probably_fine"
    del broken["timestamp"]
    (tmp_path / "vex.json").write_text(json.dumps(broken))
    errors = validate(tmp_path / "vex.json")
    assert any("probably_fine" in e for e in errors) and any("timestamp" in e for e in errors)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "components": [{"type": "library", "name": "fastapi", "version": "0.162.0", "purl": "pkg:pypi/fastapi@0.162.0"}]}
    (tmp_path / "ok.cdx.json").write_text(json.dumps(bom))
    assert validate(tmp_path / "ok.cdx.json") == []
    bom["components"][0]["type"] = "not-a-type"
    (tmp_path / "bad.cdx.json").write_text(json.dumps(bom))
    assert validate(tmp_path / "bad.cdx.json")
    (tmp_path / "empty.cdx.json").write_text(json.dumps({**bom, "components": []}))
    assert any("no components" in e for e in validate(tmp_path / "empty.cdx.json"))
    (tmp_path / "other.json").write_text("{}")
    assert validate(tmp_path / "other.json") == ["neither a CycloneDX SBOM nor an OpenVEX 0.2.0 document"]


# --------------------------------------------------------------------------- SEC2.3: dependency policy

POLICY = REPO_ROOT / "docs" / "dependency-policy.md"
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"
PATCH_SLAS = {"Critical": "7 days", "High": "14 days", "Medium": "30 days", "Low": "The next minor release"}


def _section(text: str, heading: str) -> str:
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, heading
    return match.group(1)


def test_policy_states_the_patch_slas_and_a_triage_time_inside_the_shortest() -> None:
    """Acceptance (SEC2.3): one patch-SLA table, and triage and Dependabot fit inside it."""
    text = POLICY.read_text()
    rows = dict(re.findall(r"^\| (Critical|High|Medium|Low) \| ([^|]+?) \|$", _section(text, "Patch SLAs"), re.MULTILINE))
    assert rows == PATCH_SLAS
    shortest = min(int(v.split()[0]) for v in rows.values() if v.endswith("days"))
    triage = re.search(r"within \*\*(\d+) business days\*\*", _section(text, "Updates and triage"))
    assert triage and int(triage.group(1)) <= 2 < shortest
    # The same numbers wherever they are repeated.
    for path in (DEPENDABOT, REPO_ROOT / "docs" / "security.md"):
        flat = " ".join(path.read_text().replace("#", " ").split())
        assert "critical 7 days, high 14, medium 30, low the next minor release" in flat, path.name
    assert "(dependency-policy.md#patch-slas)" in (REPO_ROOT / "docs" / "releases.md").read_text()


def test_policy_has_the_admission_checklist() -> None:
    checklist = _section(POLICY.read_text(), "Adding a dependency")
    items = re.findall(r"^\d+\. \*\*([^*]+)\.\*\*", checklist, re.MULTILINE)
    assert items == ["Need", "Licence", "Maintenance", "Size and transitive dependencies", "Security history", "Hash-locked"]
    assert "`make lock`" in checklist and "MIT" in checklist and "OSV" in checklist


def test_dependabot_matches_the_policy_and_the_release_trains() -> None:
    """Weekly on Monday (before Thursday's train) for every ecosystem, labelled, minor and patch grouped."""
    updates = _load(DEPENDABOT)["updates"]
    assert {u["package-ecosystem"] for u in updates} == {"github-actions", "docker", "npm", "pip"}
    for u in updates:
        where = f"{u['package-ecosystem']} {u['directory']}"
        assert u["schedule"] == {"interval": "weekly", "day": "monday", "time": "05:00", "timezone": "Etc/UTC"}, where
        assert u["labels"][0] == "dependencies" and len(u["labels"]) == 2, where
        for group in (u.get("groups") or {}).values():
            assert group.get("applies-to", "version-updates") == "version-updates", f"{where}: never group security updates"
    by_ecosystem = {u["package-ecosystem"]: u for u in updates}
    assert by_ecosystem["pip"]["groups"]["python"]["update-types"] == ["minor", "patch"]
    assert by_ecosystem["npm"]["groups"]["frontend-prod"] == {"dependency-type": "production", "update-types": ["minor", "patch"]}
    # The weekly CI run that re-audits the locks against fresh advisories runs on the same day.
    ci = _load(CI)
    [cron] = [entry["cron"] for entry in (ci[True] if True in ci else ci["on"])["schedule"]]
    assert cron.split()[4] == "1"


def test_new_dependencies_are_flagged_in_pull_requests_and_reviewed_by_the_owner() -> None:
    template = (REPO_ROOT / ".github" / "pull_request_template.md").read_text()
    line = next(line for line in template.splitlines() if "New dependency" in line)
    assert line.startswith("- [ ] ") and "docs/dependency-policy.md#adding-a-dependency" in line
    owned = {line.split()[0] for line in (REPO_ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
             if line.strip() and not line.startswith("#")}
    for path in ("/requirements.txt", "/requirements-dev.txt", "/docker/requirements-build.txt",
                 "/src/lg_front/package.json", "/src/lg_front/package-lock.json", "/.github/dependabot.yml"):
        assert path in owned, path
    assert "(dependency-policy.md)" in (REPO_ROOT / "docs" / "index.md").read_text()
