#!/usr/bin/env python3
"""Breaking-change check for the published JSON Schemas (``schemas/<name>/v<major>.json``).

Compares every schema with its version at a base revision and fails when the
version in its ``$id`` was not bumped enough for the change (SemVer):

* major (breaking): a removed field, a newly required field, a narrowed type,
  a removed enum value or alternative, a tighter bound, a changed pattern or
  format, closed additional properties. A major bump is a new file, ``v<N+1>.json``;
  a published file never takes a breaking change.
* minor: a new optional field, a new enum value or alternative, a widened type
  or a looser bound.
* patch: titles, descriptions, examples and defaults.

    python scripts/ci/schema_compat.py --base origin/main

Standard library only. An empty or all-zero ``--base`` (a new branch, a scheduled run) skips the check.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILE = re.compile(r"^schemas/[a-z0-9-]+/v(\d+)\.json$")
ID_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:\.json)?$")
LEVELS = ("none", "patch", "minor", "major")
ANNOTATIONS = frozenset({"title", "description", "examples", "default", "$comment", "deprecated"})
STRUCTURAL = frozenset({"$ref", "type", "enum", "const", "properties", "required", "additionalProperties", "items",
                        "anyOf", "oneOf", "discriminator", "$defs", "$id", "$schema"})
# keyword -> True when a larger value is tighter (a lower bound), False when smaller is tighter
BOUNDS = {"minimum": True, "exclusiveMinimum": True, "minLength": True, "minItems": True,
          "maximum": False, "exclusiveMaximum": False, "maxLength": False, "maxItems": False}
Json = Dict[str, Any]


@dataclass(frozen=True)
class Change:
    level: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.level}: {self.path or '/'}: {self.message}"


class _Diff:
    def __init__(self, old_doc: Json, new_doc: Json) -> None:
        self.docs = (old_doc, new_doc)
        self.changes: List[Change] = []
        self.seen: Set[Tuple[str, str]] = set()

    def add(self, level: str, path: str, message: str) -> None:
        self.changes.append(Change(level, path, message))

    def deref(self, node: Json, side: int) -> Tuple[Json, str]:
        ref = node.get("$ref")
        if not isinstance(ref, str):
            return node, ""
        target: Any = self.docs[side]
        for part in ref.removeprefix("#/").split("/"):
            target = target[part]
        return target, ref

    def node(self, old: Json, new: Json, path: str) -> None:
        old, old_ref = self.deref(old, 0)
        new, new_ref = self.deref(new, 1)
        if old_ref or new_ref:
            if (old_ref, new_ref) in self.seen:
                return
            self.seen.add((old_ref, new_ref))
        if ("anyOf" in old or "oneOf" in old or "anyOf" in new or "oneOf" in new):
            self.alternatives(old, new, path)
            return
        self.annotations(old, new, path)
        self.types(old, new, path)
        self.values(old, new, path)
        self.bounds(old, new, path)
        self.objects(old, new, path)
        if "items" in old or "items" in new:
            self.node(old.get("items", {}), new.get("items", {}), f"{path}/items")
        for key in sorted((set(old) | set(new)) - ANNOTATIONS - STRUCTURAL - set(BOUNDS) - {"pattern", "format"}):
            if old.get(key) != new.get(key):
                self.add("major", path, f"changed keyword {key!r}")

    def annotations(self, old: Json, new: Json, path: str) -> None:
        for key in sorted(ANNOTATIONS):
            if old.get(key) != new.get(key):
                self.add("patch", path, f"changed {key}")

    def types(self, old: Json, new: Json, path: str) -> None:
        def types(node: Json) -> Optional[Set[str]]:
            t = node.get("type")
            return None if t is None else ({t} if isinstance(t, str) else set(t))

        before, after = types(old), types(new)
        if before == after:
            return
        if after is None or (before is not None and before <= after):
            self.add("minor", path, f"widened type {sorted(before or [])} -> {sorted(after or ['any'])}")
        else:
            self.add("major", path, f"narrowed type {sorted(before or ['any'])} -> {sorted(after)}")

    def values(self, old: Json, new: Json, path: str) -> None:
        if old.get("enum") != new.get("enum"):
            if "enum" not in new:
                self.add("minor", path, "removed the enum restriction")
            elif "enum" not in old:
                self.add("major", path, "added an enum restriction")
            else:
                removed = [v for v in old["enum"] if v not in new["enum"]]
                added = [v for v in new["enum"] if v not in old["enum"]]
                if removed:
                    self.add("major", path, f"removed enum value(s) {removed}")
                if added:
                    self.add("minor", path, f"added enum value(s) {added}")
        if old.get("const") != new.get("const"):
            level = "minor" if "const" not in new else "major"
            self.add(level, path, f"changed const {old.get('const')!r} -> {new.get('const')!r}")
        for key in ("pattern", "format"):
            if old.get(key) != new.get(key):
                level = "minor" if key not in new else "major"
                self.add(level, path, f"changed {key} {old.get(key)!r} -> {new.get(key)!r}")

    def bounds(self, old: Json, new: Json, path: str) -> None:
        for key, lower in BOUNDS.items():
            before, after = old.get(key), new.get(key)
            if before == after:
                continue
            if after is None:
                self.add("minor", path, f"removed {key}")
            elif before is None or (after > before if lower else after < before):
                self.add("major", path, f"tightened {key} {before} -> {after}")
            else:
                self.add("minor", path, f"loosened {key} {before} -> {after}")

    def objects(self, old: Json, new: Json, path: str) -> None:
        old_props, new_props = old.get("properties", {}), new.get("properties", {})
        old_req, new_req = set(old.get("required", [])), set(new.get("required", []))
        for name in sorted(set(old_props) - set(new_props)):
            self.add("major", f"{path}/{name}", "removed field")
        for name in sorted(set(new_props) - set(old_props)):
            if name in new_req:
                self.add("major", f"{path}/{name}", "added a required field")
            else:
                self.add("minor", f"{path}/{name}", "added an optional field")
        for name in sorted(set(old_props) & set(new_props)):
            if name in new_req and name not in old_req:
                self.add("major", f"{path}/{name}", "field is now required")
            elif name in old_req and name not in new_req:
                self.add("minor", f"{path}/{name}", "field is now optional")
            self.node(old_props[name], new_props[name], f"{path}/{name}")
        closed_before, closed_after = old.get("additionalProperties") is False, new.get("additionalProperties") is False
        if closed_after and not closed_before:
            self.add("major", path, "closed additional properties")
        elif closed_before and not closed_after:
            self.add("minor", path, "opened additional properties")

    def alternatives(self, old: Json, new: Json, path: str) -> None:
        """anyOf/oneOf branches matched by $ref, const or type; a bare schema counts as one branch."""
        def branches(node: Json) -> Dict[str, Json]:
            items = node.get("anyOf") or node.get("oneOf") or [node]
            return {_branch_key(b): b for b in items}

        old_b, new_b = branches(old), branches(new)
        self.annotations(old, new, path)
        for key in sorted(set(old_b) - set(new_b)):
            self.add("major", path, f"removed alternative {key}")
        for key in sorted(set(new_b) - set(old_b)):
            self.add("minor", path, f"added alternative {key}")
        for key in sorted(set(old_b) & set(new_b)):
            self.node(old_b[key], new_b[key], path)
        if ("oneOf" in old) != ("oneOf" in new) and len(old_b) > 1 and len(new_b) > 1:
            self.add("major", path, "switched between anyOf and oneOf")


def _branch_key(branch: Json) -> str:
    if "$ref" in branch:
        return str(branch["$ref"])
    if "const" in branch:
        return f"const:{json.dumps(branch['const'])}"
    t = branch.get("type", "any")
    return f"type:{t if isinstance(t, str) else ','.join(sorted(t))}"


def compare(old: Json, new: Json) -> List[Change]:
    """Every difference between two schema documents, each with the SemVer level it needs."""
    diff = _Diff(old, new)
    diff.node(old, new, "")
    return diff.changes


def version(schema: Json) -> Tuple[int, int, int]:
    match = ID_VERSION.search(str(schema.get("$id", "")))
    if not match:
        raise ValueError(f"$id {schema.get('$id')!r} carries no SemVer version")
    major, minor, patch = (int(g) for g in match.groups())
    return major, minor, patch


def bump(old: Tuple[int, int, int], new: Tuple[int, int, int]) -> str:
    if new < old:
        return "downgrade"
    for level, i in (("major", 0), ("minor", 1), ("patch", 2)):
        if new[i] != old[i]:
            return level
    return "none"


def check_file(rel: str, old: Optional[Json], new: Optional[Json]) -> List[str]:
    """Problems with one schema file: its name and $id agree, and its version covers its changes."""
    match = SCHEMA_FILE.match(rel)
    if new is None:
        return [f"{rel}: a published schema was removed; keep it (publish a new major beside it)"]
    try:
        new_v = version(new)
    except ValueError as exc:
        return [f"{rel}: {exc}"]
    if match is None or int(match.group(1)) != new_v[0]:
        return [f"{rel}: the file name must be v{new_v[0]}.json for $id version {'.'.join(map(str, new_v))}"]
    if old is None:
        return []
    old_v = version(old)
    changes = compare(old, new)
    needed = max((c.level for c in changes), key=LEVELS.index, default="none")
    made = bump(old_v, new_v)
    shown = "\n".join(f"  {c}" for c in changes)
    if made == "downgrade" or made == "major":
        return [f"{rel}: version went {old_v} -> {new_v}; a published file keeps its major and never goes back"]
    if needed == "major":
        return [f"{rel}: breaking change; publish it as schemas/.../v{old_v[0] + 1}.json instead:\n{shown}"]
    if LEVELS.index(made) < LEVELS.index(needed):
        return [f"{rel}: needs a {needed} version bump in $id (now {'.'.join(map(str, new_v))}):\n{shown}"]
    return []


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True).stdout  # noqa: S603, S607


def _base_schemas(base: str) -> Dict[str, Json]:
    names = _git("ls-tree", "-r", "--name-only", base, "--", "schemas").splitlines()
    return {n: json.loads(_git("show", f"{base}:{n}")) for n in names if SCHEMA_FILE.match(n)}


def _tree_schemas() -> Dict[str, Json]:
    found = (p.relative_to(REPO_ROOT).as_posix() for p in (REPO_ROOT / "schemas").glob("*/v*.json"))
    return {n: json.loads((REPO_ROOT / n).read_text(encoding="utf-8")) for n in found if SCHEMA_FILE.match(n)}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="origin/main", help="git revision holding the published schemas")
    args = parser.parse_args(argv)
    if not args.base.strip("0"):
        print("schema_compat: no base revision; nothing to compare")
        return 0
    old, new = _base_schemas(args.base), _tree_schemas()
    problems = [p for rel in sorted(set(old) | set(new)) for p in check_file(rel, old.get(rel), new.get(rel))]
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"schema_compat: {len(set(old) | set(new))} schema(s) checked against {args.base}, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
