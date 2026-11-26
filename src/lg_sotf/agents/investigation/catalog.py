"""The skill catalogue: the reviewed skill files that ship in the image, loaded and checked (ADR 0014 section 1.1).

:func:`load_catalog` reads ``skills/<skill id>.yaml`` and validates each file with the strict
:class:`lg_sotf.models.skill.SkillSpec`. :func:`check_catalog` then holds every skill against the tool
registry and the view it names, and refuses the catalogue when

* a query names a tool or a version the registry does not have, an argument the tool does not take, or
  leaves out one it requires;
* a binding names a field the skill's view does not have;
* a Wazuh skill does not run ``wazuh.host_activity`` on the alert's own host (``host: view.host``);
* an indicator reads evidence whose tool does not produce the fact kind it is about;
* two active skills apply to the same source.

An invalid catalogue is an error at process start (and in CI), never a skill that quietly does not run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, List, Sequence, Tuple

import yaml
from pydantic import TypeAdapter, ValidationError
from pydantic.fields import FieldInfo

from lg_sotf.domain.skill_views import VIEWS, WAZUH, view_fields
from lg_sotf.errors import LG_SOTFError
from lg_sotf.models.skill import AllOf, AnyOf, Const, Maybe, Not, Predicate, SkillSpec
from lg_sotf.tools.registry import ToolNotFound, ToolRegistry

__all__ = ["SKILLS_DIR", "SkillError", "check_catalog", "load_catalog", "load_skill"]

SKILLS_DIR = Path(__file__).parent / "skills"
MAX_SKILL_BYTES = 65_536
HOST_ACTIVITY_TOOL = "wazuh.host_activity"
HOST_ACTIVITY_KIND = "host_activity"


class SkillError(LG_SOTFError):
    """A skill file, or the catalogue, does not load: the process does not start."""


def load_skill(path: Path) -> SkillSpec:
    raw = path.read_bytes()
    if len(raw) > MAX_SKILL_BYTES:
        raise SkillError(f"{path.name}: a skill file is at most {MAX_SKILL_BYTES} bytes")
    try:
        skill = SkillSpec.model_validate(yaml.safe_load(raw.decode("utf-8")))
    except (yaml.YAMLError, UnicodeDecodeError, ValidationError) as exc:
        problems = str(exc).splitlines()
        raise SkillError(f"{path.name}: not a valid skill ({'; '.join(problems[:6])[:600]})") from None
    if path.stem != skill.id:
        raise SkillError(f"{path.name}: the file is named after the skill id ({skill.id}.yaml)")
    return skill


def load_catalog(directory: Path = SKILLS_DIR) -> Tuple[SkillSpec, ...]:
    """Every skill file of ``directory``, in file-name order."""
    return tuple(load_skill(path) for path in sorted(directory.glob("*.yaml")))


OWN_EVENT_ARG, OWN_EVENT_BINDING = "exclude_rule_id", "view.rule_id"


def _leaves(predicate: Predicate) -> List[str]:
    if isinstance(predicate, (AllOf, AnyOf)):
        inner = predicate.all if isinstance(predicate, AllOf) else predicate.any
        return [fact for one in inner for fact in _leaves(one)]
    return _leaves(predicate.negated) if isinstance(predicate, Not) else [predicate.fact]


def _fits(field: FieldInfo, arg: Any) -> bool:
    """Whether a number or a constant of the file is a value the tool's parameter takes (its type and bounds),
    so a query that could never run refuses the file instead of being skipped on every alert."""
    value = arg.const if isinstance(arg, Const) else arg
    expected: Any = Annotated[field.annotation, *field.metadata] if field.metadata else field.annotation
    try:
        TypeAdapter(expected).validate_python(value, strict=True)
    except ValidationError:
        return False
    return True


def _problems(skill: SkillSpec, registry: ToolRegistry) -> List[str]:
    problems: List[str] = []
    bindable = view_fields(skill.view)
    if skill.view not in VIEWS:
        problems.append(f"view {skill.view} is not registered")
    produces = {}
    for ref in skill.evidence:
        try:
            spec = registry.get(ref.tool_name)
        except ToolNotFound:
            problems.append(f"{ref.id}: no tool {ref.tool_name}")
            continue
        produces[ref.id] = spec.produces
        if spec.version != ref.tool_version:
            problems.append(f"{ref.id}: {ref.tool_name} is version {spec.version}, not {ref.tool_version}")
        fields = spec.params.model_fields
        unknown = sorted(set(ref.args) - set(fields))
        missing = sorted(name for name, field in fields.items() if field.is_required() and name not in ref.args)
        if unknown or missing:
            problems.append(f"{ref.id}: arguments not taken: {unknown or 'none'}; required and not given: {missing or 'none'}")
        for name, given in ref.args.items():
            arg = given.optional if isinstance(given, Maybe) else given
            if isinstance(given, Maybe) and name in fields and fields[name].is_required():
                problems.append(f"{ref.id}: {name} is required by {ref.tool_name}, so its binding cannot be optional")
            if isinstance(arg, str) and arg.startswith("view.") and arg.removeprefix("view.") not in bindable:
                problems.append(f"{ref.id}: the view has no field {arg}")
            elif not isinstance(arg, str) and name in fields and not _fits(fields[name], arg):
                problems.append(f"{ref.id}: {name} is not a value {ref.tool_name} takes")
    if WAZUH in skill.applies_to.source_types and not any(
        ref.tool_name == HOST_ACTIVITY_TOOL and ref.args.get("host") == "view.host" for ref in skill.evidence
    ):
        problems.append(f"a Wazuh skill runs {HOST_ACTIVITY_TOOL} on the alert's host (host: view.host)")
    args = {ref.id: ref.args for ref in skill.evidence}
    for hypothesis in skill.hypotheses.malicious:
        for fact in _leaves(hypothesis.indicator):
            if HOST_ACTIVITY_KIND not in produces.get(fact, frozenset({HOST_ACTIVITY_KIND})):
                problems.append(f"{hypothesis.id}: evidence {fact} holds no {HOST_ACTIVITY_KIND} fact")
            # A true indicator holds a close, so what it reads never counts the alert under investigation.
            elif fact in args and args[fact].get(OWN_EVENT_ARG) != Maybe(optional=OWN_EVENT_BINDING):
                problems.append(
                    f"{hypothesis.id}: evidence {fact} must leave the alert's own event out "
                    f"({OWN_EVENT_ARG}: {{optional: {OWN_EVENT_BINDING}}})"
                )
    return problems


def check_catalog(skills: Sequence[SkillSpec], registry: ToolRegistry) -> None:
    """Raise :class:`SkillError` unless every skill fits the registry and no two active skills overlap."""
    problems = [f"{skill.id}: {problem}" for skill in skills for problem in _problems(skill, registry)]
    seen: dict[str, str] = {}
    for skill in skills:
        if skill.status != "active":
            continue
        for source in skill.applies_to.source_types:
            if source in seen:
                problems.append(f"{skill.id} and {seen[source]} both apply to {source}")
            seen[source] = skill.id
    if len({skill.id for skill in skills}) != len(skills):
        problems.append("a skill id appears twice")
    if not skills:
        problems.append("it holds no skill (the skill files ship with the package)")
    if problems:
        raise SkillError("the skill catalogue does not load: " + "; ".join(problems)[:2_000])
