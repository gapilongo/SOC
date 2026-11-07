"""Policy checks for docker/Dockerfile, .dockerignore and the pinned requirements."""

from __future__ import annotations

import re
from typing import List, Tuple

import pytest

from tests.deploy._support import DOCKER_DIR, REPO_ROOT

DOCKERFILE = DOCKER_DIR / "Dockerfile"


def instructions() -> List[Tuple[str, str]]:
    """(INSTRUCTION, arguments) pairs with line continuations joined and comments dropped."""
    lines: List[str] = []
    buf = ""
    for raw in DOCKERFILE.read_text().splitlines():
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        lines.append(buf + stripped)
        buf = ""
    assert not buf, "dangling line continuation"
    out = []
    for line in lines:
        word, _, rest = line.partition(" ")
        out.append((word.upper(), rest.strip()))
    return out


def stages() -> List[List[Tuple[str, str]]]:
    result: List[List[Tuple[str, str]]] = []
    for ins in instructions():
        if ins[0] == "FROM":
            result.append([])
        if result:
            result[-1].append(ins)
    return result


def final_stage() -> List[Tuple[str, str]]:
    return stages()[-1]


def builder_stage() -> List[Tuple[str, str]]:
    [builder] = [s for s in stages() if s[0][1].endswith(" AS builder")]
    return builder


def test_base_image_is_digest_pinned_and_overridable() -> None:
    ins = instructions()
    first_from = next(i for i, (word, _) in enumerate(ins) if word == "FROM")
    global_args = [rest for word, rest in ins[:first_from] if word == "ARG"]
    assert global_args.count("BASE_IMAGE=") == 1, "BASE_IMAGE is declared once, empty, before the first FROM"
    froms = [rest for word, rest in ins if word == "FROM"]
    # The pinned base is a literal FROM (so Dependabot can bump it): a specific minor version on the
    # slim variant, tag kept for readability, pinned by digest.
    assert re.fullmatch(r"python:3\.\d+-slim@sha256:[a-f0-9]{64} AS python-base", froms[0]), froms[0]
    # Every real stage builds from it unless BASE_IMAGE (a registry mirror) is set.
    assert froms[1:] == ["${BASE_IMAGE:-python-base} AS builder", "${BASE_IMAGE:-python-base} AS runtime"]


def test_multi_stage_with_named_builder_and_runtime() -> None:
    names = [rest.split()[-1] for word, rest in instructions() if word == "FROM"]
    assert names == ["python-base", "builder", "runtime"]
    copies_from_builder = [rest for word, rest in final_stage() if word == "COPY" and "--from=builder" in rest]
    assert copies_from_builder == ["--from=builder /opt/venv /opt/venv"], "only the virtualenv leaves the builder"


def test_no_add_and_no_remote_fetches() -> None:
    for word, rest in instructions():
        assert word != "ADD", "use COPY; ADD can fetch remote URLs and unpack archives implicitly"
        if word == "RUN":
            assert not re.search(r"\b(curl|wget)\b", rest), f"no ad-hoc downloads in RUN: {rest}"
            assert "| sh" not in rest and "|sh" not in rest


def test_runtime_runs_as_fixed_non_root_uid() -> None:
    users = [rest for word, rest in final_stage() if word == "USER"]
    assert users, "final stage must set USER"
    user = users[-1]
    uid = user.split(":")[0]
    assert uid.isdigit(), "numeric uid so Kubernetes runAsNonRoot can verify it"
    assert int(uid) == 10001
    assert int(user.split(":")[1]) == 10001


def test_runtime_has_no_build_tools_or_package_manager_use() -> None:
    runtime_runs = " ".join(rest for word, rest in final_stage() if word == "RUN")
    for forbidden in ("apt-get", "apk ", "gcc", "build-essential", "pip install", "curl", "wget"):
        assert forbidden not in runtime_runs, forbidden


def test_dependencies_install_from_the_hash_locked_files_with_binary_wheels_only() -> None:
    builder = builder_stage()
    env = " ".join(rest for word, rest in builder if word == "ENV")
    assert "PIP_ONLY_BINARY=:all:" in env
    runs = " ".join(rest for word, rest in builder if word == "RUN")
    assert "pip install --require-hashes -r requirements-build.txt" in runs
    assert "pip install --require-hashes -r requirements.txt" in runs
    # Every other pip install is the local application wheel, which must not pull extra deps.
    others = [m.strip() for m in re.findall(r"pip install (?!--require-hashes -r )[^&;]*", runs)]
    assert others == ["pip install --no-deps /dist/lg_sotf-*.whl"], others
    assert "pip check" in runs
    # The build tools are gone before /opt/venv ships.
    assert "pip uninstall -y -q pip setuptools" in runs
    # The lock files themselves: tests/deploy/test_supply_chain.py.


def test_build_ca_is_a_secret_mount_never_copied() -> None:
    for word, rest in instructions():
        if word == "COPY":
            assert "ca" not in rest.lower().split("/")[-1] or "configs" in rest, rest
        if word == "RUN" and "build_ca" in rest:
            assert "--mount=type=secret,id=build_ca,required=false" in rest
    assert (DOCKER_DIR / "empty-ca.crt").read_bytes() == b"", "the default build CA placeholder must stay empty"


def test_signal_handling_entrypoint_and_default_command() -> None:
    entry = [rest for word, rest in final_stage() if word == "ENTRYPOINT"]
    cmd = [rest for word, rest in final_stage() if word == "CMD"]
    assert entry == ['["dumb-init", "--", "lg-sotf"]']
    assert cmd == ['["api"]']
    assert ("STOPSIGNAL", "SIGTERM") in final_stage()


def test_healthcheck_targets_the_role_probe() -> None:
    checks = [rest for word, rest in final_stage() if word == "HEALTHCHECK"]
    assert len(checks) == 1
    assert 'CMD ["python", "/usr/local/lib/lg-sotf/healthcheck.py"]' in checks[0]


def test_read_only_root_friendly_environment() -> None:
    env = " ".join(rest for word, rest in final_stage() if word == "ENV")
    assert "PYTHONDONTWRITEBYTECODE=1" in env
    assert "HOME=/tmp" in env and "TMPDIR=/tmp" in env


def test_oci_labels() -> None:
    labels = " ".join(rest for word, rest in final_stage() if word == "LABEL")
    for key in ("title", "version", "revision", "created", "source", "licenses"):
        assert f"org.opencontainers.image.{key}=" in labels, key


def test_no_secrets_baked_into_env_or_args() -> None:
    for word, rest in instructions():
        if word in ("ENV", "ARG"):
            assert not re.search(r"(?i)(secret|password|token|api_key|jwt)", rest), rest


@pytest.mark.parametrize("pattern", [".env", ".git", "tests", "node_modules", "Backup"])
def test_dockerignore_denies_by_default(pattern: str) -> None:
    lines = [ln.strip() for ln in (REPO_ROOT / ".dockerignore").read_text().splitlines()]
    active = [ln for ln in lines if ln and not ln.startswith("#")]
    assert active[0] == "*", "allowlist style: exclude everything, then re-include"
    reincluded = [ln[1:] for ln in active if ln.startswith("!")]
    assert not any(r.rstrip("/").startswith(pattern) for r in reincluded), pattern
    assert "**/.env" in active


def test_dockerignore_reincludes_everything_the_build_copies() -> None:
    active = [ln.strip() for ln in (REPO_ROOT / ".dockerignore").read_text().splitlines()]
    reincluded = {ln[1:].rstrip("/") for ln in active if ln.startswith("!")}
    for word, rest in instructions():
        if word == "COPY" and "--from=" not in rest:
            sources = rest.split()[:-1]
            for src in sources:
                assert src.rstrip("/") in reincluded, f"{src} is copied but excluded from the build context"


def test_runtime_image_drops_the_base_images_pip_and_setuid_bits() -> None:
    """WSC-3: the runtime stage starts from a fresh base image with its own pip/setuptools."""
    text = (DOCKER_DIR / "Dockerfile").read_text()
    runtime = text[text.index("AS runtime") :]
    assert "pip uninstall -y -q pip setuptools wheel" in runtime
    assert "-perm /6000 -exec chmod a-s" in runtime
    assert runtime.index("pip uninstall") < runtime.index("USER 10001")


def test_the_image_ships_every_llm_provider() -> None:
    """llm.provider is a runtime setting: the image must not need a rebuild to switch it."""
    pinned = {
        line.split("==", 1)[0].lower().replace("_", "-")
        for line in (REPO_ROOT / "requirements.txt").read_text().splitlines()
        if "==" in line and not line.lstrip().startswith("#")
    }
    for package in ("langchain-anthropic", "langchain-openai", "langchain-google-genai"):
        assert package in pinned, f"{package} is missing from requirements.txt"
