"""Helpers shared by the deployment packaging tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKER_DIR = REPO_ROOT / "docker"
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "lg-sotf"
FULL_VALUES = CHART_DIR / "ci" / "full-values.yaml"
COMPOSE = DOCKER_DIR / "docker-compose.yml"
PROD = DOCKER_DIR / "docker-compose.prod.yml"

Manifest = Dict[str, Any]


def helm_binary() -> Optional[str]:
    return shutil.which("helm")


requires_helm = pytest.mark.skipif(helm_binary() is None, reason="helm is not installed")


def run_helm_template(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    helm = helm_binary()
    assert helm is not None
    return subprocess.run(
        [helm, "template", "t", str(CHART_DIR), *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=60,
    )


def render(*args: str) -> List[Manifest]:
    out = run_helm_template(*args).stdout
    return [doc for doc in yaml.safe_load_all(out) if doc]


def find(manifests: List[Manifest], kind: str, name_suffix: Optional[str] = None) -> List[Manifest]:
    return [
        m
        for m in manifests
        if m["kind"] == kind and (name_suffix is None or m["metadata"]["name"].endswith(name_suffix))
    ]


def one(manifests: List[Manifest], kind: str, name_suffix: str) -> Manifest:
    found = find(manifests, kind, name_suffix)
    assert len(found) == 1, f"expected one {kind} *{name_suffix}, found {[m['metadata']['name'] for m in found]}"
    return found[0]


# ------------------------------------------------------------- docker compose

PROD_SECRETS = {
    "POSTGRES_SUPERUSER_PASSWORD": "compose-test-superuser",
    "LGSOTF_OWNER_PASSWORD": "compose-test-owner",
    "LGSOTF_APP_PASSWORD": "compose-test-app",
    "LG_SOTF_AUTH__JWT_SECRET": "compose-test-jwt",
    "LG_SOTF_SECURITY__ENCRYPTION_KEYS": "compose-test-fernet",
    "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY": "compose-test-hmac",
}


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader that understands Compose's merge tags (!reset, !override)."""


def _compose_tag(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


ComposeLoader.add_constructor("!reset", _compose_tag)
ComposeLoader.add_constructor("!override", _compose_tag)


def load(path: Any) -> Dict[str, Any]:
    data = yaml.load(path.read_text(), Loader=ComposeLoader)  # noqa: S506 - SafeLoader subclass
    assert isinstance(data, dict)
    return data


requires_compose = pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI is not installed")


def compose_config(*files: str, env: Dict[str, str], env_file: Optional[Path] = None) -> Dict[str, Any]:
    argv = ["docker", "compose"]
    for f in files:
        argv += ["-f", f]
    if env_file is not None:
        argv += ["--env-file", str(env_file)]
    proc = subprocess.run(
        [*argv, "config", "--format", "json"],
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "/tmp"), **env},
        timeout=60,
    )
    if proc.returncode != 0 and "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin is not installed")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)
