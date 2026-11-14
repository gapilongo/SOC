#!/usr/bin/env python3
"""API breaking-change gate: oasdiff on the OpenAPI document, split by stability tier.

    python scripts/ci/check_api_compat.py BASE.json REVISION.json
    python scripts/ci/check_api_compat.py --self-test docs/openapi.json

Every operation carries ``x-stability`` (``stable``, ``beta`` or ``internal``;
see lg_sotf.api.stability and docs/api.md). Both documents are split in two
and each half goes through ``oasdiff breaking``:

* stable operations: any ERR-level breaking change exits 1. Removing a stable
  operation needs ``deprecated: true`` and an ``x-sunset`` date that has passed;
  a new deprecation needs a sunset at least ``STABLE_DEPRECATION_DAYS`` away.
  Moving an operation from stable to beta or internal reads as a removal.
* beta and internal operations: the breaking changes are printed, not enforced.

An operation without a tier counts as stable in the revision. In the base it
takes the revision's tier, so the change that introduces a tier is not read
as removing the operation from the stable set.

``--self-test`` proves the gate on a real document: a breaking change to a
stable operation must fail, the same change to a beta operation must pass.
The oasdiff binary is ``$OASDIFF`` or ``oasdiff`` on the PATH (CI sets
``OASDIFF=scripts/ci/oasdiff.sh``: the image pinned by digest). Standard library only.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

STABILITY_KEY = "x-stability"
STABLE = "stable"
STABLE_DEPRECATION_DAYS = 180  # lg_sotf.api.stability.STABLE_DEPRECATION_DAYS
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

Spec = Dict[str, Any]


def operations(spec: Spec) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
    for path, item in sorted((spec.get("paths") or {}).items()):
        for method in METHODS:
            if method in item:
                yield path, method, item[method]


def tier(op: Dict[str, Any]) -> str:
    return str(op.get(STABILITY_KEY, STABLE))


def adopt_tiers(base: Spec, revision: Spec) -> Spec:
    """``base`` with each untiered operation given the revision's tier for it (stable if it is gone)."""
    out = copy.deepcopy(base)
    revised = {(path, method): tier(op) for path, method, op in operations(revision)}
    for path, method, op in operations(out):
        op.setdefault(STABILITY_KEY, revised.get((path, method), STABLE))
    return out


def select(spec: Spec, *, stable: bool) -> Spec:
    """A copy of ``spec`` with only the stable operations, or only the others."""
    out = copy.deepcopy(spec)
    paths: Dict[str, Any] = {}
    for path, item in (out.get("paths") or {}).items():
        kept = {k: v for k, v in item.items() if k not in METHODS or (tier(v) == STABLE) == stable}
        if any(k in METHODS for k in kept):
            paths[path] = kept
    out["paths"] = paths
    return out


def oasdiff(base: Spec, revision: Spec, *, enforce: bool, binary: str) -> Tuple[int, str]:
    """Run ``oasdiff breaking``; ``enforce`` exits 1 on an ERR-level change."""
    with tempfile.TemporaryDirectory(prefix="api-compat-") as tmp:
        files = []
        for name, doc in (("base.json", base), ("revision.json", revision)):
            target = Path(tmp) / name
            target.write_text(json.dumps(doc), encoding="utf-8")
            files.append(str(target))
        cmd = [binary, "breaking", *files, "--format", "text", "--color", "never"]
        cmd += ["--deprecation-days-stable", str(STABLE_DEPRECATION_DAYS)]
        if enforce:
            cmd += ["--fail-on", "ERR"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603 - pinned oasdiff, our files
        return proc.returncode, (proc.stdout + proc.stderr).replace(tmp + os.sep, "")


def check(base: Spec, revision: Spec, *, binary: str, out: Callable[[str], None] = print) -> int:
    """0: no breaking change to a stable operation; 1: there is one; 2: oasdiff failed."""
    base = adopt_tiers(base, revision)
    code, text = oasdiff(select(base, stable=True), select(revision, stable=True), enforce=True, binary=binary)
    out("== Stable operations: a breaking change fails the build")
    out(text.rstrip())
    if code not in (0, 1):
        return 2
    report, text = oasdiff(select(base, stable=False), select(revision, stable=False), enforce=False, binary=binary)
    out("== Beta and internal operations: reported only")
    out(text.rstrip())
    return 2 if report != 0 else code


def _first(spec: Spec, *, stable: bool) -> Tuple[str, str]:
    for path, method, op in operations(spec):
        if (tier(op) == STABLE) == stable:
            return path, method
    raise SystemExit(f"self-test: the document has no {'stable' if stable else 'non-stable'} operation")


def _changed(spec: Spec, where: Tuple[str, str], change: Callable[[Dict[str, Any]], None]) -> Spec:
    out = copy.deepcopy(spec)
    change(out["paths"][where[0]][where[1]])
    return out


def _require_param(op: Dict[str, Any]) -> None:
    param = {"in": "query", "name": "self_test_required", "required": True, "schema": {"type": "string"}}
    op["parameters"] = [*op.get("parameters", []), param]


def _without(spec: Spec, where: Tuple[str, str]) -> Spec:
    out = copy.deepcopy(spec)
    del out["paths"][where[0]][where[1]]
    return out


def _untiered(spec: Spec) -> Spec:
    out = copy.deepcopy(spec)
    for _, _, op in operations(out):
        op.pop(STABILITY_KEY, None)
    return out


def self_test(spec: Spec, *, binary: str) -> int:
    stable_op, other_op = _first(spec, stable=True), _first(spec, stable=False)
    soon = {"deprecated": True, "x-sunset": (date.today() + timedelta(days=30)).isoformat()}
    cases: List[Tuple[str, Spec, Spec, int]] = [
        ("unchanged document passes", spec, spec, 0),
        (f"new required parameter on stable {stable_op} fails", spec, _changed(spec, stable_op, _require_param), 1),
        (f"new required parameter on non-stable {other_op} passes", spec, _changed(spec, other_op, _require_param), 0),
        (f"stable {stable_op} removed without deprecation fails", spec, _without(spec, stable_op), 1),
        (
            f"stable {stable_op} deprecated with a 30-day sunset fails",
            spec,
            _changed(spec, stable_op, lambda op: op.update(soon)),
            1,
        ),
        (
            f"stable {stable_op} moved to beta fails",
            spec,
            _changed(spec, stable_op, lambda op: op.update({STABILITY_KEY: "beta"})),
            1,
        ),
        ("an untiered base takes the revision's tiers", _untiered(spec), spec, 0),
    ]
    failed = 0
    for name, base, revision, expected in cases:
        lines: List[str] = []
        got = check(base, revision, binary=binary, out=lines.append)
        ok = got == expected
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} (exit {got}, expected {expected})")
        if not ok:
            print("\n".join(lines))
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("specs", nargs="+", type=Path, help="BASE REVISION, or the document to self-test on")
    parser.add_argument("--self-test", action="store_true", help="prove the gate on the given document")
    parser.add_argument("--oasdiff", default=os.environ.get("OASDIFF", "oasdiff"), help="oasdiff binary")
    args = parser.parse_args(argv)
    docs = [json.loads(p.read_text(encoding="utf-8")) for p in args.specs]
    if args.self_test:
        if len(docs) != 1:
            parser.error("--self-test takes one document")
        return self_test(docs[0], binary=args.oasdiff)
    if len(docs) != 2:
        parser.error("expected BASE and REVISION")
    return check(docs[0], docs[1], binary=args.oasdiff)


if __name__ == "__main__":
    sys.exit(main())
