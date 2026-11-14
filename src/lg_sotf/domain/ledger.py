"""The fact ledger's rules (AI-E3.2): what an investigation observed, and what a verdict may cite.

A run's ledger is a list of :class:`LedgerEntry`, in the order the tool calls returned. One tool call
(:class:`ToolStep`) adds one entry per typed evidence fact it returned, or a single entry without a fact
when it returned none: the query matched nothing (``empty``), it did not run to an answer (``failed``),
or its answer holds no typed fact. Every entry carries the call it came from: the tool and its version,
the trace step's input and output hashes, the outcome and whether the answer was complete.

**Ids are minted here, by code.** :func:`build_entries` names each entry ``<evidence id>:<n>``, numbered
after the ids the run already has. Nothing else gives a fact an id: a tool's own id is overwritten, and a
model never supplies one. :func:`check_citations` tells a verdict's citations from ids the run's ledger
does not hold.

**An empty or failed query is never benign evidence** (ADR-0014 Amendment 2).
:attr:`LedgerEntry.citable_as_benign_evidence` is computed from the entry, never stored and never set by
a caller: true only for a ``success`` entry that holds a typed fact a tool observed. A fact a reader
model extracted from free text (``source.name`` ``reader.<tool>``) is a lead, not evidence.

Standard library and the fact schema only: no I/O. The store is
:class:`lg_sotf.db.repos.evidence_facts.EvidenceFactsRepo`; the executor's interface is
:class:`lg_sotf.agents.investigation.ledger.FactLedger`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Collection, Dict, List, Literal, Mapping, NamedTuple, Optional, Sequence, Tuple, get_args

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from lg_sotf.models.evidence_fact import EvidenceFact, parse_fact

__all__ = [
    "EVIDENCE_ID_PATTERN",
    "FACT_ID_PATTERN",
    "MAX_RUN_ENTRIES",
    "OUTCOMES",
    "READER_SOURCE_PREFIX",
    "CitationProblem",
    "LedgerEntry",
    "LedgerError",
    "Outcome",
    "ToolStep",
    "build_entries",
    "check_citations",
    "content_hash",
    "mint_fact_id",
    "planner_view",
]

Outcome = Literal["success", "empty", "failed"]
OUTCOMES: Tuple[str, ...] = get_args(Outcome)
CitationCode = Literal["unknown_fact", "altered_fact", "not_benign_evidence"]

EVIDENCE_ID_PATTERN = r"^[a-z][a-z0-9_.-]{0,63}$"
FACT_ID_PATTERN = r"^[a-z][a-z0-9_.-]{0,63}:(0|[1-9][0-9]{0,5})$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_RUN_ENTRIES = 200
"""Entries one run's ledger holds: far above an investigation's query budget, so a loop cannot grow it."""
MAX_REASON_CHARS = 64
READER_SOURCE_PREFIX = "reader."
_EVIDENCE_ID = re.compile(EVIDENCE_ID_PATTERN)
# The content hash covers the call and the fact's body, not what the ledger stamps on the fact: the same
# tool result hashes the same in every run, whatever id it gets there. ``reason`` is a diagnostic the
# registry does not replay from a cassette, so it is left out; the output hash covers the answer itself.
_HASHED = ("tool", "tool_version", "input_hash", "output_hash", "outcome", "complete")
_STAMPED = ("id", "provenance")


class LedgerError(Exception):
    """A step the ledger refuses to record. The message never carries a value from the tool's answer."""


def content_hash(observed: Mapping[str, Any]) -> str:
    """Lowercase hex SHA-256 of ``observed`` as canonical JSON (sorted keys, compact, UTF-8): the trace's recipe."""
    text = json.dumps(observed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolStep:
    """One tool call as the ledger records it: what the registry returned, and the typed facts in it."""

    evidence_id: str
    """What the call was made for: the skill's evidence id, written by code or picked from a closed list."""
    tool: str
    tool_version: int
    input_hash: str
    output_hash: Optional[str]
    outcome: Outcome
    complete: bool
    reason: Optional[str] = None
    facts: Tuple[EvidenceFact, ...] = ()


class LedgerEntry(BaseModel):
    """One observation of a run: a typed fact with the call it came from, or a call that returned none."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    fact_id: str = Field(pattern=FACT_ID_PATTERN)
    evidence_id: str = Field(pattern=EVIDENCE_ID_PATTERN)
    tool: str = Field(min_length=1, max_length=64)
    tool_version: int = Field(ge=1)
    input_hash: str = Field(pattern=SHA256_PATTERN)
    output_hash: Optional[str] = Field(default=None, pattern=SHA256_PATTERN)
    outcome: Outcome
    complete: bool
    reason: Optional[str] = Field(default=None, max_length=MAX_REASON_CHARS)
    as_of: AwareDatetime
    """When the ledger recorded the call, right after it returned."""
    fact: Optional[Dict[str, Any]] = None
    """The evidence fact (schema v1, JSON form) with the ledger's id and the call's hashes; ``None`` without one."""
    content_hash: str = Field(pattern=SHA256_PATTERN)

    @property
    def kind(self) -> Optional[str]:
        kind = (self.fact or {}).get("kind")
        return kind if isinstance(kind, str) else None

    @property
    def intact(self) -> bool:
        """The entry still says what was recorded: its content hash is the hash of its own fields."""
        return self.content_hash == content_hash(_observed(self.model_dump()))

    @property
    def citable_as_benign_evidence(self) -> bool:
        """Whether a benign claim may cite the entry: a tool observed a typed fact. Decided here, by code."""
        if self.outcome != "success" or self.fact is None:
            return False
        source = self.fact.get("source")
        name = source.get("name") if isinstance(source, Mapping) else None
        return isinstance(name, str) and not name.startswith(READER_SOURCE_PREFIX)

    def evidence_fact(self) -> Optional[EvidenceFact]:
        """The typed fact (validated against schema v1); ``None`` for an entry without one."""
        return None if self.fact is None else parse_fact(self.fact)


def _observed(fields: Mapping[str, Any]) -> Dict[str, Any]:
    """What the content hash covers: the call and the fact as the tool returned it, not its name or its time."""
    fact = fields.get("fact")
    body = None if fact is None else {k: v for k, v in fact.items() if k not in _STAMPED}
    return {**{name: fields.get(name) for name in _HASHED}, "fact": body}


def mint_fact_id(evidence_id: str, taken: Collection[str]) -> str:
    """The next id of ``evidence_id`` in a run: ``<evidence_id>:<n>``, numbered after the ids already ``taken``."""
    if not _EVIDENCE_ID.fullmatch(evidence_id):
        raise LedgerError("an evidence id is lower-case letters, digits and _ . - (at most 64, a letter first)")
    prefix = f"{evidence_id}:"
    numbers = [int(i[len(prefix):]) for i in taken if i.startswith(prefix) and i[len(prefix):].isdecimal()]
    return f"{prefix}{max(numbers, default=-1) + 1}"


def _stamped(fact: EvidenceFact, fact_id: str, step: ToolStep) -> Dict[str, Any]:
    """The fact under the ledger's id, bound to the call's hashes; validated again, so only schema facts enter."""
    provenance = {"input_hash": step.input_hash, "output_hash": step.output_hash or None}
    bound = parse_fact({**fact.model_dump(mode="json", exclude_none=True), "id": fact_id, "provenance": provenance})
    return bound.model_dump(mode="json", exclude_none=True)


def build_entries(step: ToolStep, taken: Collection[str], as_of: datetime) -> Tuple[LedgerEntry, ...]:
    """The ledger entries of one tool call, with ids minted after ``taken`` (the ids the run already has).

    One entry per fact, or one entry without a fact. A call that did not succeed never carries a fact.
    """
    if step.outcome != "success" and step.facts:
        raise LedgerError(f"a call whose outcome is {step.outcome} carries no fact")
    if step.outcome == "failed" and step.complete:
        raise LedgerError("a failed call is never complete")
    ids = list(taken)
    entries: List[LedgerEntry] = []
    for fact in step.facts or (None,):
        fact_id = mint_fact_id(step.evidence_id, ids)
        ids.append(fact_id)
        fields: Dict[str, Any] = {
            "fact_id": fact_id, "evidence_id": step.evidence_id, "tool": step.tool,
            "tool_version": step.tool_version, "input_hash": step.input_hash,
            "output_hash": step.output_hash or None, "outcome": step.outcome, "complete": step.complete,
            "reason": step.reason[:MAX_REASON_CHARS] if step.reason else None, "as_of": as_of,
            "fact": None if fact is None else _stamped(fact, fact_id, step),
        }
        entries.append(LedgerEntry(**fields, content_hash=content_hash(_observed(fields))))
    if len(ids) > MAX_RUN_ENTRIES:
        raise LedgerError(f"a run's ledger holds at most {MAX_RUN_ENTRIES} entries")
    return tuple(entries)


class CitationProblem(NamedTuple):
    """A cited id a claim may not rest on."""

    fact_id: str
    code: CitationCode


def check_citations(
    cited: Sequence[str], ledger: Sequence[LedgerEntry], *, benign_claim: bool
) -> List[CitationProblem]:
    """What is wrong with a claim's citations, against the ledger of the claim's own run (pure).

    ``unknown_fact``: the ledger did not mint the id (a model made it up, or it is another run's or another
    tenant's). ``altered_fact``: the entry no longer matches its content hash. ``not_benign_evidence``: a
    benign claim cites an empty or failed call, or a fact no tool observed. An empty list: every id holds.
    """
    minted = {entry.fact_id: entry for entry in ledger}
    problems: List[CitationProblem] = []
    for fact_id in dict.fromkeys(cited):
        entry = minted.get(fact_id)
        if entry is None:
            problems.append(CitationProblem(fact_id[:128], "unknown_fact"))
        elif not entry.intact:
            problems.append(CitationProblem(fact_id, "altered_fact"))
        elif benign_claim and not entry.citable_as_benign_evidence:
            problems.append(CitationProblem(fact_id, "not_benign_evidence"))
    return problems


def planner_view(ledger: Sequence[LedgerEntry]) -> List[Dict[str, Any]]:
    """What a prompt may show of a ledger: ids, outcomes and typed fact fields, never a tool's raw answer.

    A typed field can still hold a string an attacker chose, so the caller renders this as untrusted data
    (``lg_sotf.llm.prompting``, the ``tool_data`` block), never as instructions.
    """
    view: List[Dict[str, Any]] = []
    for entry in ledger:
        shown: Dict[str, Any] = {
            "id": entry.fact_id, "tool": entry.tool, "outcome": entry.outcome, "complete": entry.complete,
        }
        if entry.fact is None:
            shown["reason"] = entry.reason
        else:
            shown.update({k: entry.fact.get(k) for k in ("kind", "subject", "observed_at", "value")})
        view.append(shown)
    return view
