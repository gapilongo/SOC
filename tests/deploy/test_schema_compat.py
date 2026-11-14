"""scripts/ci/schema_compat.py: the SemVer breaking-change check on the published schemas (INT9.2).

Each case mutates the real ``schemas/evidence-fact/v1.json`` and asserts the
version bump the checker demands; the CI job runs it against the base revision.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from types import ModuleType
from typing import Any, Callable, Dict

import pytest
import yaml

from tests.deploy._support import REPO_ROOT

REL = "schemas/evidence-fact/v1.json"
Json = Dict[str, Any]


def _checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("schema_compat", REPO_ROOT / "scripts" / "ci" / "schema_compat.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


CHECKER = _checker()


def _v1() -> Json:
    data = json.loads((REPO_ROOT / REL).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _defs(s: Json, name: str) -> Json:
    node = s["$defs"][name]
    assert isinstance(node, dict)
    return node


def _set_version(s: Json, version: str) -> Json:
    s["$id"] = s["$id"].rsplit(":", 1)[0] + ":" + version
    return s


def _remove_field(s: Json) -> None:
    del _defs(s, "Source")["properties"]["version"]


def _new_required_field(s: Json) -> None:
    _defs(s, "Subject")["properties"]["display"] = {"type": "string"}
    _defs(s, "Subject")["required"].append("display")


def _now_required(s: Json) -> None:
    _defs(s, "ReputationValue")["required"].append("score")


def _narrow_type(s: Json) -> None:
    _defs(s, "SignInHistoryValue")["properties"]["total"]["type"] = "boolean"


def _remove_enum_value(s: Json) -> None:
    _defs(s, "Subject")["properties"]["type"]["enum"].remove("url")


def _remove_kind(s: Json) -> None:
    s["oneOf"] = [b for b in s["oneOf"] if not b["$ref"].endswith("/RelatedAlertFact")]


def _tighten_bound(s: Json) -> None:
    _defs(s, "ProcessLineageValue")["properties"]["chain"]["maxItems"] = 8


def _drop_null(s: Json) -> None:
    field = _defs(s, "ReputationFact")["properties"]["ttl_seconds"]
    field.update(field.pop("anyOf")[0])


def _change_pattern(s: Json) -> None:
    _defs(s, "Source")["properties"]["name"]["pattern"] = "^[a-z]+$"


def _add_optional_field(s: Json) -> None:
    _defs(s, "Subject")["properties"]["display"] = {"type": "string"}


def _add_enum_value(s: Json) -> None:
    _defs(s, "Subject")["properties"]["type"]["enum"].append("email")


def _add_kind(s: Json) -> None:
    s["$defs"]["DnsFact"] = copy.deepcopy(_defs(s, "RelatedAlertFact"))
    s["oneOf"].append({"$ref": "#/$defs/DnsFact"})


def _loosen_bound(s: Json) -> None:
    _defs(s, "ProcessLineageValue")["properties"]["chain"]["maxItems"] = 64


def _allow_null(s: Json) -> None:
    field = _defs(s, "SignInHistoryValue")["properties"]["total"]
    _defs(s, "SignInHistoryValue")["properties"]["total"] = {"anyOf": [field, {"type": "null"}]}


def _reword(s: Json) -> None:
    _defs(s, "Subject")["description"] = "Reworded."


CASES: Dict[str, tuple[Callable[[Json], None], str]] = {
    "removed field": (_remove_field, "major"),
    "new required field": (_new_required_field, "major"),
    "optional field made required": (_now_required, "major"),
    "narrowed type": (_narrow_type, "major"),
    "removed enum value": (_remove_enum_value, "major"),
    "removed fact kind": (_remove_kind, "major"),
    "tighter bound": (_tighten_bound, "major"),
    "no longer nullable": (_drop_null, "major"),
    "changed pattern": (_change_pattern, "major"),
    "new optional field": (_add_optional_field, "minor"),
    "new enum value": (_add_enum_value, "minor"),
    "new fact kind": (_add_kind, "minor"),
    "looser bound": (_loosen_bound, "minor"),
    "now nullable": (_allow_null, "minor"),
    "reworded description": (_reword, "patch"),
}


@pytest.mark.parametrize("case", list(CASES))
def test_each_change_needs_its_semver_level(case: str) -> None:
    mutate, level = CASES[case]
    old, new = _v1(), _v1()
    mutate(new)
    changes = CHECKER.compare(old, new)
    assert changes, case
    assert max((c.level for c in changes), key=CHECKER.LEVELS.index) == level, [str(c) for c in changes]


def test_an_unchanged_schema_has_no_changes() -> None:
    assert CHECKER.compare(_v1(), _v1()) == []
    assert CHECKER.check_file(REL, _v1(), _v1()) == []


def _at_1_0_0() -> Json:
    """The published schema as if at 1.0.0, so the bump cases do not depend on the version it is at now."""
    return _set_version(_v1(), "1.0.0")


def test_an_additive_change_needs_a_minor_bump() -> None:
    old, new = _at_1_0_0(), _at_1_0_0()
    _add_optional_field(new)
    [problem] = CHECKER.check_file(REL, old, new)
    assert "needs a minor version bump" in problem and "added an optional field" in problem
    assert CHECKER.check_file(REL, old, _set_version(new, "1.1.0")) == []
    assert CHECKER.check_file(REL, old, _set_version(new, "1.0.1")) != []


def test_a_breaking_change_is_refused_in_a_published_file_even_with_a_bump() -> None:
    old, new = _at_1_0_0(), _at_1_0_0()
    _remove_enum_value(new)
    for version in ("1.0.0", "1.1.0"):
        [problem] = CHECKER.check_file(REL, old, _set_version(copy.deepcopy(new), version))
        assert "breaking change" in problem and "v2.json" in problem and "removed enum value" in problem
    # The new major goes in its own file, beside v1.
    assert CHECKER.check_file("schemas/evidence-fact/v2.json", None, _set_version(new, "2.0.0")) == []


def test_file_name_version_and_removal_rules() -> None:
    assert "must be v2.json" in CHECKER.check_file(REL, None, _set_version(_v1(), "2.0.0"))[0]
    assert "removed" in CHECKER.check_file(REL, _v1(), None)[0]
    assert "never goes back" in CHECKER.check_file(REL, _set_version(_v1(), "1.2.0"), _set_version(_v1(), "1.1.0"))[0]
    no_version = _v1()
    no_version["$id"] = "urn:lg-sotf:schema:evidence-fact"
    assert "no SemVer" in CHECKER.check_file(REL, None, no_version)[0]


def test_the_command_compares_the_tree_with_a_git_revision(capsys: pytest.CaptureFixture[str]) -> None:
    assert CHECKER.main(["--base", "HEAD"]) == 0
    assert "problem(s)" in capsys.readouterr().out
    # A new branch or a scheduled run has no base to compare with.
    assert CHECKER.main(["--base", ""]) == 0
    assert CHECKER.main(["--base", "0" * 40]) == 0


def test_ci_runs_the_check_against_the_base_revision_with_full_history() -> None:
    job = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]["schemas"]
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0
    step = next(s for s in job["steps"] if "schema_compat.py" in s.get("run", ""))
    assert step["run"] == 'python scripts/ci/schema_compat.py --base "${BASE_REF}"'
    assert step["env"]["BASE_REF"] == "${{ github.event.pull_request.base.sha || github.event.before }}"
