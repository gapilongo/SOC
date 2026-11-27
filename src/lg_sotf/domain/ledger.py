"""The fact ledger's rules (AI-E3.2): what an investigation observed, and what a verdict may cite.

A ledger belongs to one **investigation run**: the id :func:`new_run_id` mints when a workflow run starts
(``WorkflowState.investigation_run_id``). A resumed run and a retried node keep the id; a reprocessed
alert starts a new run with a new id and an empty ledger.

A run's ledger is a list of :class:`LedgerEntry`, in the order the tool calls returned. One tool call
(:class:`ToolStep`) adds one entry per typed evidence fact it returned, or a single entry without a fact
when it returned none: the query matched nothing (``empty``), it did not run to an answer (``failed``),
or its answer holds no typed fact. Every entry carries the call it came from: the tool and its version,
the trace step's input and output hashes, the outcome and whether the answer was complete.

**Ids are minted here, by code.** :func:`build_entries` names each entry ``<evidence id>:<n>``, numbered
after the ids the run already has. Nothing else gives a fact an id: a tool's own id is overwritten, and a
model never supplies one. :func:`check_citations` tells a verdict's citations from ids the run's ledger
does not hold.

**Recording is idempotent** (:func:`plan_record`): the same call recorded again (same evidence id, same
tool, same input and output hash: a node retried after a crash) gets the entries the run already has,
and nothing new is minted. A call that does not fit in what is left of :data:`MAX_RUN_ENTRIES`, or holds a fact
larger than :data:`MAX_FACT_BYTES`, is recorded as one ``failed`` entry that says why.

**An empty or failed query is never benign evidence** (ADR-0014 Amendment 2).
:attr:`LedgerEntry.citable_as_benign_evidence` is computed from the entry, never stored and never set by
a caller: true only for a ``success`` entry that holds a typed fact a tool observed. A fact a reader
model extracted from free text (``source.name`` ``reader.<tool>``) is a lead, not evidence.

**One notion of complete.** An entry is ``complete`` only when the tool result was complete and the fact
itself says ``complete: true``; a fact the result cut is stored with ``complete: false``.

**What is stored is what is hashed.** A fact is put in its stored form before it is hashed
(:func:`canonical`: the replacements the database makes for a NUL or a lone surrogate, whole floats as
integers), and the content hash covers every field of the entry, so an entry read back from the table
is ``intact`` exactly when nothing in it changed.

Standard library and the fact schema only: no I/O. The store is
:class:`lg_sotf.db.repos.evidence_facts.EvidenceFactsRepo`; the executor's interface is
:class:`lg_sotf.agents.investigation.ledger.FactLedger`.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Collection, Dict, List, Literal, Mapping, NamedTuple, Optional, Sequence, Tuple, get_args
from uuid import uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from lg_sotf.models.evidence_fact import EvidenceFact, parse_fact

__all__ = [
    "EVIDENCE_ID_PATTERN",
    "FACT_ID_PATTERN",
    "MAX_FACT_BYTES",
    "MAX_PLANNER_CHARS",
    "MAX_RUN_ENTRIES",
    "OUTCOMES",
    "READER_SOURCE_PREFIX",
    "RUN_ID_PATTERN",
    "CitationProblem",
    "LedgerEntry",
    "LedgerError",
    "Outcome",
    "Recorded",
    "ToolStep",
    "build_entries",
    "canonical",
    "check_citations",
    "content_hash",
    "mint_fact_id",
    "new_run_id",
    "plan_record",
    "planner_view",
]

Outcome = Literal["success", "empty", "failed"]
OUTCOMES: Tuple[str, ...] = get_args(Outcome)
CitationCode = Literal["unknown_fact", "altered_fact", "not_benign_evidence", "incomplete_fact", "no_citation"]

RUN_ID_PATTERN = r"^inv_[0-9a-f]{32}$"
EVIDENCE_ID_PATTERN = r"^[a-z][a-z0-9_.-]{0,63}$"
FACT_ID_PATTERN = r"^[a-z][a-z0-9_.-]{0,63}:(0|[1-9][0-9]{0,5})$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_RUN_ENTRIES = 200
"""Entries one run's ledger holds: far above an investigation's query budget. The last one is kept for the
entry that says the ledger is full, so a run can always record that."""
MAX_FACT_BYTES = 1_048_576
"""The largest fact the ledger keeps, as compact UTF-8 JSON (the table allows twice that as text)."""
MAX_PLANNER_CHARS = 60_000
"""What :func:`planner_view` shows at most, as JSON: the prompt builder cuts further."""
MAX_REASON_CHARS = 64
READER_SOURCE_PREFIX = "reader."
LEDGER_CAPACITY = "ledger_capacity"
FACT_TOO_LARGE = "fact_too_large"
REPLACEMENT_CHAR = "�"
_EVIDENCE_ID = re.compile(EVIDENCE_ID_PATTERN)
# Every field of an entry but the hash itself: what is shown (the id, the reason, the time) and what binds
# the fact to its call (the hashes, and the id and provenance inside the fact).
_HASHED = (
    "fact_id", "evidence_id", "tool", "tool_version", "input_hash", "output_hash", "outcome", "complete", "reason",
    "fact",
)


class LedgerError(Exception):
    """A step the ledger refuses to record. The message never carries a value from the tool's answer."""


def new_run_id() -> str:
    """A new investigation run id (``inv_`` and 32 hex digits): random, so it names one run and nothing else."""
    return f"inv_{uuid4().hex}"


def canonical(value: Any) -> Any:
    """``value`` as the table gives it back: JSON types only, and nothing the database would rewrite.

    A NUL becomes U+FFFD and a lone surrogate ``?``, as ``lg_sotf.db.pool.json_dumps`` does for every JSON
    parameter (PostgreSQL stores neither). A whole float becomes an integer (``85.0`` is ``85``, ``-0.0`` is
    ``0``), because JSONB keeps numbers as decimals and has no negative zero. A float that is not a number
    becomes ``None``.
    """
    if isinstance(value, str):
        text = value.replace("\x00", REPLACEMENT_CHAR) if "\x00" in value else value
        return text if text.isascii() else text.encode("utf-8", "replace").decode("utf-8")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return int(value) if value.is_integer() else value
    if isinstance(value, Mapping):
        return {canonical(str(key)): canonical(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [canonical(item) for item in value]
    return canonical(str(value))


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
    """The tool result was complete and, for a fact, the fact itself says so. Never true of a failed call."""
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
        return self.content_hash == content_hash(_hashed(self.model_dump()))

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


def _hashed(fields: Mapping[str, Any]) -> Dict[str, Any]:
    """What the content hash covers: every field of the entry, the time as UTC to the microsecond."""
    as_of: datetime = fields["as_of"]
    return {**{name: fields.get(name) for name in _HASHED}, "as_of": as_of.astimezone(UTC).isoformat(timespec="microseconds")}


def mint_fact_id(evidence_id: str, taken: Collection[str]) -> str:
    """The next id of ``evidence_id`` in a run: ``<evidence_id>:<n>``, numbered after the ids already ``taken``."""
    if not _EVIDENCE_ID.fullmatch(evidence_id):
        raise LedgerError("an evidence id is lower-case letters, digits and _ . - (at most 64, a letter first)")
    prefix = f"{evidence_id}:"
    numbers = [int(i[len(prefix):]) for i in taken if i.startswith(prefix) and i[len(prefix):].isdecimal()]
    return f"{prefix}{max(numbers, default=-1) + 1}"


def _stamped(fact: EvidenceFact, fact_id: str, step: ToolStep) -> Dict[str, Any]:
    """The fact as the ledger stores it: under the ledger's id, bound to the call's hashes, ``complete`` only
    when the call was, and in its stored form. Validated again, so only schema facts enter."""
    stamps: Dict[str, Any] = {
        "id": fact_id,
        "provenance": {"input_hash": step.input_hash, "output_hash": step.output_hash or None},
    }
    if fact.complete is True and not step.complete:
        stamps["complete"] = False
    bound = parse_fact({**fact.model_dump(mode="json", exclude_none=True), **stamps})
    stored: Dict[str, Any] = canonical(bound.model_dump(mode="json", exclude_none=True))
    return stored


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
        stored = None if fact is None else _stamped(fact, fact_id, step)
        fields: Dict[str, Any] = {
            "fact_id": fact_id, "evidence_id": step.evidence_id, "tool": step.tool,
            "tool_version": step.tool_version, "input_hash": step.input_hash,
            "output_hash": step.output_hash or None, "outcome": step.outcome,
            "complete": step.complete if stored is None else stored.get("complete") is True,
            "reason": canonical(step.reason)[:MAX_REASON_CHARS] if step.reason else None, "as_of": as_of,
            "fact": stored,
        }
        entries.append(LedgerEntry(**fields, content_hash=content_hash(_hashed(fields))))
    if len(ids) > MAX_RUN_ENTRIES:
        raise LedgerError(f"a run's ledger holds at most {MAX_RUN_ENTRIES} entries")
    return tuple(entries)


class Recorded(NamedTuple):
    """What recording a step comes to: the entries to add to the store, and the step's entries on the ledger."""

    new: Tuple[LedgerEntry, ...]
    entries: Tuple[LedgerEntry, ...]


def _refused(step: ToolStep, ledger: Sequence[LedgerEntry], as_of: datetime, reason: str) -> Recorded:
    """The step as one failed entry that says why the ledger did not take its facts."""
    marker = replace(step, outcome="failed", complete=False, reason=reason, facts=())
    new = build_entries(marker, [entry.fact_id for entry in ledger], as_of)
    return Recorded(new, new)


def plan_record(step: ToolStep, ledger: Sequence[LedgerEntry], as_of: datetime) -> Recorded:
    """What recording ``step`` on a run's ``ledger`` (its current entries, in order) comes to. Never raises
    for a step that is too much: it is recorded as failed.

    * The same call again (same evidence id, tool and hashes): the entries it already has, nothing new.
    * A fact larger than :data:`MAX_FACT_BYTES`: one failed entry, reason ``fact_too_large``.
    * More entries than fit (the last place is kept for this): one failed entry, reason
      ``ledger_capacity``; on a full ledger, the entry that already says so.
    """
    # The tool is part of what makes a call the same: the members of a family call share one step's hashes.
    call = (step.evidence_id, step.tool, step.tool_version, step.input_hash, step.output_hash or None)
    same = tuple(
        entry for entry in ledger
        if (entry.evidence_id, entry.tool, entry.tool_version, entry.input_hash, entry.output_hash) == call
    )
    if same:
        return Recorded((), same)
    if len(ledger) >= MAX_RUN_ENTRIES:
        return Recorded((), tuple(entry for entry in ledger if entry.reason == LEDGER_CAPACITY)[-1:])
    if len(ledger) + max(1, len(step.facts)) > MAX_RUN_ENTRIES - 1:
        return _refused(step, ledger, as_of, LEDGER_CAPACITY)
    new = build_entries(step, [entry.fact_id for entry in ledger], as_of)
    if any(len(json.dumps(e.fact, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_FACT_BYTES for e in new):
        return _refused(step, ledger, as_of, FACT_TOO_LARGE)
    return Recorded(new, new)


class CitationProblem(NamedTuple):
    """A finding about a claim's citations: the id it is about (empty for ``no_citation``) and what is wrong."""

    fact_id: str
    code: CitationCode


def check_citations(
    cited: Sequence[str], ledger: Sequence[LedgerEntry], *, benign_claim: bool
) -> List[CitationProblem]:
    """What is wrong with a claim's citations, against the ledger of the claim's own run (pure).

    ``unknown_fact``: the ledger did not mint the id (a model made it up, or it is another run's or another
    tenant's). ``altered_fact``: the entry no longer matches its content hash. For a benign claim only:
    ``not_benign_evidence`` (it cites an empty or failed call, or a fact no tool observed),
    ``incomplete_fact`` (the fact, or the tool result it came from, is not complete: nothing can be
    concluded from what it does not show) and ``no_citation`` (it cites nothing at all). These are findings
    for the checker to act on, not errors. An empty list: every id holds.
    """
    if benign_claim and not cited:
        return [CitationProblem("", "no_citation")]
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
        elif benign_claim and not entry.complete:
            problems.append(CitationProblem(fact_id, "incomplete_fact"))
    return problems


def _sample_by_part(value: Any) -> Any:
    """A fact's value with a sample of events (each says what it is ``listed_for``) grouped by that part.

    A prompt that cannot hold a list cuts every member of it alike, so the volume of one part (an
    attacker's noise) would cut the events of the others down to nothing. Grouped, each part is fitted on its
    own, and a small part is shown whole (issue 452). A value without such a sample is returned as it is.
    """
    events = value.get("events") if isinstance(value, Mapping) else None
    if not isinstance(events, list) or not events or not all(isinstance(e, Mapping) and e.get("listed_for") for e in events):
        return value
    parts: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        parts.setdefault(str(event["listed_for"]), []).append({k: v for k, v in event.items() if k != "listed_for"})
    return {**value, "events": parts}


def planner_view(ledger: Sequence[LedgerEntry], *, max_chars: int = MAX_PLANNER_CHARS) -> List[Dict[str, Any]]:
    """What a prompt may show of a ledger: ids, outcomes and typed fact fields, never a tool's raw answer.

    In ledger order, at most ``max_chars`` of JSON in all: an entry that does not fit in what is left is
    left out (the caller says how many are missing). A typed field can still hold a string an attacker
    chose, so the caller renders this as untrusted data (``lg_sotf.llm.prompting``, the ``tool_data``
    block), never as instructions. A sample of events is shown by part (:func:`_sample_by_part`).
    """
    view: List[Dict[str, Any]] = []
    left = max_chars
    for entry in ledger:
        shown: Dict[str, Any] = {
            "id": entry.fact_id, "tool": entry.tool, "outcome": entry.outcome, "complete": entry.complete,
        }
        if entry.fact is None:
            shown["reason"] = entry.reason
        else:
            shown.update({k: entry.fact.get(k) for k in ("kind", "subject", "observed_at")})
            shown["value"] = _sample_by_part(entry.fact.get("value"))
        size = len(json.dumps(shown, separators=(",", ":"), ensure_ascii=False))
        if size <= left:
            view.append(shown)
            left -= size
    return view
