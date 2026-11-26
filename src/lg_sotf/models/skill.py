"""The investigation skill format (ADR 0014 section 1): a reviewed YAML file, validated by this strict model.

A skill says which alerts it applies to, which read-only queries to run and which typed facts would show
the activity is malicious. This is the part of the format the first slice needs (ADR 0014 Amendment 1,
step 3); a file that uses anything else does not load, so nothing is ever silently ignored:

* ``evidence``: query references into the tool registry. Every argument is a **binding** (``view.<field>``
  of the alert's typed view, or ``alert.occurred_at``), a whole number, or a constant of the file
  (``{const: target_user}``). No argument is free text, and none is chosen at run time by a model.
  Every query is ``when: always``: the plan is fixed. Optional queries come with the planner.
* ``hypotheses.malicious``: indicators over the facts, in the small predicate set of Amendment 1 point 4
  as far as a skill needs it: ``any_technique_in``, ``any_group_in``, ``max_level_ge`` and ``all`` /
  ``any`` / ``not``. They are evaluated three-valued (:mod:`lg_sotf.domain.skills`).

Not in this slice, and refused in a file: benign hypotheses and their proofs, ``close``,
``never_close``, ``lists``, ``settle_min``, a per-skill ``budget`` and optional evidence.
"""

from __future__ import annotations

from typing import Annotated, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

__all__ = [
    "SKILL_SCHEMA",
    "AllOf",
    "AnyGroupIn",
    "AnyOf",
    "AnyTechniqueIn",
    "AppliesTo",
    "ArgValue",
    "Const",
    "EvidenceRef",
    "Hypotheses",
    "MaliciousHypothesis",
    "MaxLevelGe",
    "Not",
    "Predicate",
    "SkillSpec",
]

SKILL_SCHEMA = "lg-sotf/investigation-skill/v1"
MAX_EVIDENCE = 16
MAX_ARGS = 12
MAX_LIST = 64
MAX_DEPTH_ITEMS = 8

SkillId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){1,2}$")]
EvidenceId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
ToolRef = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}:[1-9][0-9]{0,3}$")]
Binding = Annotated[str, Field(pattern=r"^(view\.[a-z][a-z0-9_]{0,31}|alert\.occurred_at)$")]
Token = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
Technique = Annotated[str, Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Const(_Strict):
    """A constant the reviewed file fixes (a pivot, a kind): never a value from the alert or a model."""

    const: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]


class Maybe(_Strict):
    """A binding the query can do without: when the alert has no value for it, the argument is left out and
    the query still runs (``exclude_rule_id: {optional: view.rule_id}``)."""

    optional: Binding


ArgValue = Union[Binding, StrictInt, Const, Maybe]


class EvidenceRef(_Strict):
    id: EvidenceId
    tool: ToolRef
    """``<tool name>:<version>`` as the registry declares it."""
    when: Literal["always"] = "always"
    required: bool = False
    args: Dict[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")], ArgValue] = Field(min_length=1, max_length=MAX_ARGS)

    @property
    def tool_name(self) -> str:
        return self.tool.rsplit(":", 1)[0]

    @property
    def tool_version(self) -> int:
        return int(self.tool.rsplit(":", 1)[1])


class AnyTechniqueIn(_Strict):
    """True when a ``host_activity`` fact of ``fact`` lists one of the ATT&CK techniques (sub-techniques included)."""

    fact: EvidenceId
    any_technique_in: List[Technique] = Field(min_length=1, max_length=MAX_LIST)


class AnyGroupIn(_Strict):
    """True when a ``host_activity`` fact of ``fact`` counts events in one of the rule groups."""

    fact: EvidenceId
    any_group_in: List[Token] = Field(min_length=1, max_length=MAX_LIST)


class MaxLevelGe(_Strict):
    """True when the highest rule level a ``host_activity`` fact of ``fact`` saw is at least this."""

    fact: EvidenceId
    max_level_ge: Annotated[StrictInt, Field(ge=0, le=16)]


class AllOf(_Strict):
    all: List[Predicate] = Field(min_length=1, max_length=MAX_DEPTH_ITEMS)


class AnyOf(_Strict):
    any: List[Predicate] = Field(min_length=1, max_length=MAX_DEPTH_ITEMS)


class Not(_Strict):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True)

    negated: Predicate = Field(alias="not")


Predicate = Union[AnyTechniqueIn, AnyGroupIn, MaxLevelGe, AllOf, AnyOf, Not]
AllOf.model_rebuild()
AnyOf.model_rebuild()
Not.model_rebuild()


class MaliciousHypothesis(_Strict):
    id: EvidenceId
    says: Annotated[str, Field(min_length=1, max_length=300)]
    """One sentence for the analyst: trusted prose of the reviewed file. It proves nothing."""
    technique: Optional[Technique] = None
    indicator: Predicate


class Hypotheses(_Strict):
    malicious: List[MaliciousHypothesis] = Field(default_factory=list, max_length=MAX_EVIDENCE)


class AppliesTo(_Strict):
    source_types: List[Token] = Field(min_length=1, max_length=8)


class SkillSpec(_Strict):
    """One skill file. ``extra="forbid"``: a field this release does not implement refuses the file."""

    schema_id: Literal["lg-sotf/investigation-skill/v1"] = Field(alias="schema")
    id: SkillId
    title: Annotated[str, Field(min_length=1, max_length=120)]
    version: Annotated[str, Field(pattern=r"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$")]
    status: Literal["draft", "active", "retired"]
    owner: Token
    """The owning team (CODEOWNERS), never a person."""
    summary: Annotated[str, Field(min_length=1, max_length=1_000)]
    applies_to: AppliesTo
    view: Token
    """The registered typed extractor that reads the alert's detector fields (``lg_sotf.domain.skill_views``)."""
    evidence: List[EvidenceRef] = Field(min_length=1, max_length=MAX_EVIDENCE)
    hypotheses: Hypotheses = Hypotheses()

    @model_validator(mode="after")
    def _coherent(self) -> SkillSpec:
        ids = [ref.id for ref in self.evidence]
        if len(set(ids)) != len(ids):
            raise ValueError("evidence ids must be unique in a skill")
        named = [h.id for h in self.hypotheses.malicious]
        if len(set(named)) != len(named):
            raise ValueError("hypothesis ids must be unique in a skill")
        unknown = sorted({fact for h in self.hypotheses.malicious for fact in _facts(h.indicator)} - set(ids))
        if unknown:
            raise ValueError(f"an indicator reads evidence the skill does not collect: {', '.join(unknown)}")
        return self


def _facts(predicate: Predicate) -> List[str]:
    """The evidence ids a predicate reads."""
    if isinstance(predicate, (AllOf, AnyOf)):
        inner = predicate.all if isinstance(predicate, AllOf) else predicate.any
        return [fact for one in inner for fact in _facts(one)]
    if isinstance(predicate, Not):
        return _facts(predicate.negated)
    return [predicate.fact]
