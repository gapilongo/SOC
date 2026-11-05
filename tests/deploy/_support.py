"""Helpers shared by the deployment packaging tests."""

from __future__ import annotations

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
