"""Supply-chain policy (SEC1.3): digest-pinned base images, hash-locked installs, the image CVE gate."""

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
        [i] = [n for n, s in enumerate(steps) if TRIVY_ACTION.match(s.get("uses", ""))]
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
