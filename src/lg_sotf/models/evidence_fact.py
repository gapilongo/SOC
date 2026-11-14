"""Evidence fact, schema v1: one typed observation an investigation tool returned.

A connector or tool produces facts; a verdict cites them by ``id``, and the
critic checks that every claim cites one (AI E3). Each ``kind`` carries its own
typed ``value``, so the planner reads typed data, never raw tool text.

A typed field can still hold a string an attacker chose (a service name, a
command line, a workstation name). Every string is therefore bounded and every
list capped at ``MAX_LIST_ITEMS``; a fact field is data to compare or display,
never an instruction.

Schema 1.1 (INT9.3, ADR 0014 section 3.3) adds the kinds the Wazuh evidence
tools return (``host_activity``, ``logon_fanout``, ``prevalence``), the
children of a process lineage, and ``complete``. Every 1.0 fact is a valid 1.1
fact.

This model is the source of the public JSON Schema ``schemas/evidence-fact/v1.json``
(``scripts/export_schemas.py`` writes it; ``tests/unit/models/test_evidence_fact.py``
fails when the two differ). The schema is a published contract with SemVer
(``SCHEMA_VERSION``): ``scripts/ci/schema_compat.py`` fails CI on a change that
needs a bigger version bump than the one made. A breaking change means a new
``EvidenceFactV2`` and ``v2.json``; see docs/evidence-facts.md.

``tenant_id`` is internal: it is never serialized and is not in the schema.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple, Union, get_args
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, TypeAdapter

from lg_sotf.models.vocabulary import Disposition, Severity

SCHEMA_NAME = "evidence-fact"
SCHEMA_VERSION = "1.1.0"
SCHEMA_ID = f"urn:lg-sotf:schema:{SCHEMA_NAME}:{SCHEMA_VERSION}"
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

MAX_TEXT_CHARS = 1_024
MAX_COMMAND_LINE_CHARS = 4_096
MAX_LIST_ITEMS = 50
MAX_LINEAGE_DEPTH = 32
MAX_NAME_CHARS = 255
MAX_TOKEN_CHARS = 128
MAX_RULE_LEVEL = 16

FactKind = Literal[
    "reputation", "process_lineage", "sign_in_history", "related_alert",
    "host_activity", "logon_fanout", "prevalence",  # 1.1
]
FACT_KINDS: Tuple[FactKind, ...] = get_args(FactKind)
SubjectType = Literal[
    "ip", "domain", "url", "user", "host", "process", "file", "alert",
    "service", "command_template",  # 1.1
]
SUBJECT_TYPES: Tuple[SubjectType, ...] = get_args(SubjectType)
ReputationVerdict = Literal["malicious", "suspicious", "benign", "unknown"]
SignInResult = Literal["success", "failure", "interrupted"]
SignInRisk = Literal["none", "low", "medium", "high"]
RedactionReason = Literal["secret", "pii", "truncated"]
LogonPivot = Literal["source_ip", "source_host", "target_user", "target_host"]
LogonFamily = Literal["windows", "sshd"]
PrevalenceScope = Literal["tenant_fleet", "tenant_alerts"]

Text = Annotated[str, Field(min_length=1, max_length=MAX_TEXT_CHARS)]
# A short identifier the source wrote: a rule id, a rule group, an event id, a logon type, a process GUID.
Token = Annotated[str, Field(min_length=1, max_length=MAX_TOKEN_CHARS)]
ImageName = Annotated[
    str,
    Field(min_length=1, max_length=MAX_NAME_CHARS, description="The executable's file name, without its directory."),
]
CommandTemplate = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_COMMAND_LINE_CHARS,
        description="The command line with its variable parts (paths, ids, values) replaced by placeholders.",
    ),
]
Technique = Annotated[
    str, Field(pattern=r"^T\d{4}(\.\d{3})?$", description="A MITRE ATT&CK technique id.", examples=["T1110.003"])
]
Count = Annotated[int, Field(ge=0)]
RuleLevel = Annotated[int, Field(ge=0, le=MAX_RULE_LEVEL)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", description="Lowercase hex SHA-256.")]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Subject(_Strict):
    """The entity the fact is about: an IP address, a user principal name, a file's SHA-256..."""

    type: SubjectType
    value: Text


class Source(_Strict):
    """The connector or tool that observed the fact."""

    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$", examples=["virustotal", "defender.ah"])]
    version: Optional[Annotated[str, Field(min_length=1, max_length=64)]] = None


class Provenance(_Strict):
    """Where the fact came from in the investigation trace (all hashes lowercase hex SHA-256)."""

    source_step_id: Optional[UUID] = Field(default=None, description="The trace step that produced the fact.")
    input_hash: Optional[Sha256] = None
    output_hash: Optional[Sha256] = None


class Redaction(_Strict):
    """A part of ``value`` removed or cut before the fact was stored, as a JSON Pointer into the fact."""

    path: Annotated[str, Field(pattern=r"^(/[^/]*)+$", max_length=256, examples=["/value/chain/0/command_line"])]
    reason: RedactionReason


# ---------------------------------------------------------------- values


class ReputationValue(_Strict):
    """A reputation lookup on an IP address, domain, URL or file hash."""

    verdict: ReputationVerdict
    score: Optional[Annotated[float, Field(ge=0, le=100)]] = Field(
        default=None, description="Provider risk score scaled to 0-100, higher is worse."
    )
    categories: List[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=20
    )


class ProcessNode(_Strict):
    name: Text
    pid: Optional[Annotated[int, Field(ge=0)]] = None
    command_line: Optional[Annotated[str, Field(max_length=MAX_COMMAND_LINE_CHARS)]] = None
    sha256: Optional[Sha256] = None
    user: Optional[Text] = None
    started_at: Optional[AwareDatetime] = None
    # 1.1: what makes a node comparable across hosts.
    command_template: Optional[CommandTemplate] = None
    image_name: Optional[ImageName] = None
    process_guid: Optional[Token] = Field(default=None, description="The source's id of the process instance.")


class ProcessLineageValue(_Strict):
    """The subject process's ancestry, oldest ancestor first, the subject process last."""

    chain: List[ProcessNode] = Field(min_length=1, max_length=MAX_LINEAGE_DEPTH)
    children: Optional[List[ProcessNode]] = Field(
        default=None,
        max_length=MAX_LIST_ITEMS,
        description="1.1: up to 50 processes the subject process started. Absent: the source did not look.",
    )


class SignIn(_Strict):
    at: AwareDatetime
    result: SignInResult
    ip: Optional[Text] = None
    country: Optional[Annotated[str, Field(pattern=r"^[A-Z]{2}$")]] = Field(
        default=None, description="ISO 3166-1 alpha-2."
    )
    app: Optional[Text] = None
    risk: Optional[SignInRisk] = None


class SignInHistoryValue(_Strict):
    """A user's sign-ins over a window: counts, and up to 50 sign-ins, newest first."""

    window_start: AwareDatetime
    window_end: AwareDatetime
    total: Annotated[int, Field(ge=0)]
    failed: Annotated[int, Field(ge=0)]
    sign_ins: List[SignIn] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)


class RelatedAlertValue(_Strict):
    """Another alert on the same subject."""

    alert_id: Text
    title: Text
    severity: Severity
    created_at: AwareDatetime
    disposition: Optional[Disposition] = None


class GroupCount(_Strict):
    group: Token
    count: Count


class HostEvent(_Strict):
    at: AwareDatetime
    rule_id: Optional[Token] = None
    level: Optional[RuleLevel] = None
    groups: List[Token] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    event_id: Optional[Token] = None
    user: Optional[Text] = None
    image_name: Optional[ImageName] = None
    command_template: Optional[CommandTemplate] = None


class HostActivityValue(_Strict):
    """What a host's detections show over a window around an alert (1.1)."""

    window_start: AwareDatetime
    window_end: AwareDatetime
    total: Count = Field(description="Events in the window.")
    max_level: Optional[RuleLevel] = Field(
        default=None, description="The highest rule level in the window, 0-16; absent when there was no event."
    )
    by_group: List[GroupCount] = Field(
        default_factory=list, max_length=MAX_LIST_ITEMS, description="Up to 50 rule groups, most frequent first."
    )
    techniques: List[Technique] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    events: List[HostEvent] = Field(
        default_factory=list, max_length=MAX_LIST_ITEMS, description="Up to 50 events, highest level first."
    )


class LogonFanoutValue(_Strict):
    """Logons around one pivot (a source, a user or a target host) over a window (1.1)."""

    pivot: LogonPivot = Field(description="What the subject is in these logons.")
    family: LogonFamily
    window_start: AwareDatetime
    window_end: AwareDatetime
    failures: Count
    successes: Count
    lockouts: Count
    unknown_user_failures: Count = Field(description="Failures for a user name that does not exist.")
    distinct_target_users: Count
    distinct_sources: Count
    distinct_target_hosts: Count
    first_success_after_failure_s: Optional[Count] = Field(
        default=None,
        description="Seconds from the first failure to the first success after it; absent when there was none.",
    )
    success_users: List[Text] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    failed_users: List[Text] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    sources: List[Text] = Field(
        default_factory=list, max_length=MAX_LIST_ITEMS, description="Up to 50 source addresses."
    )
    source_hosts: List[Text] = Field(
        default_factory=list,
        max_length=MAX_LIST_ITEMS,
        description="Up to 50 source host names as the client supplied them: a lead, never proof.",
    )
    logon_types: List[Token] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)


class PrevalenceValue(_Strict):
    """How widely the subject (a file, an image, a service, a command template) is seen (1.1)."""

    scope: PrevalenceScope = Field(
        description="tenant_fleet: the tenant's hosts in its telemetry; tenant_alerts: the tenant's alerts."
    )
    window_start: AwareDatetime = Field(description="The window the source actually covered.")
    window_end: AwareDatetime
    first_seen_at: Optional[AwareDatetime] = None
    last_seen_at: Optional[AwareDatetime] = None
    host_count: Count
    event_count: Count
    fleet_size: Optional[Count] = Field(default=None, description="The tenant's hosts in scope, when known.")


# ---------------------------------------------------------------- facts


class _Fact(_Strict):
    schema_version: Annotated[str, Field(pattern=r"^1\.\d+\.\d+$")] = Field(
        default=SCHEMA_VERSION, description="SemVer of the schema the producer wrote; major 1."
    )
    id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")] = Field(
        description="Stable within an investigation; verdicts cite it."
    )
    subject: Subject
    observed_at: AwareDatetime
    source: Source
    confidence: Optional[Annotated[float, Field(ge=0, le=1)]] = Field(
        default=None, description="The source's confidence in the observation, 0-1."
    )
    ttl_seconds: Optional[Annotated[int, Field(ge=0)]] = Field(
        default=None, description="How long after observed_at the fact stays current; absent means no expiry."
    )
    provenance: Optional[Provenance] = None
    redactions: List[Redaction] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    complete: Optional[StrictBool] = Field(
        default=None,
        description=(
            "1.1: false when the source cut the result or could not finish it (a timeout, a row cap, "
            "a window that had not closed). Only true lets a claim of absence rest on the fact; "
            "absent means the source did not say."
        ),
    )
    # Internal: never serialized, never in the published schema.
    tenant_id: Optional[str] = Field(default=None, exclude=True)


class ReputationFact(_Fact):
    kind: Literal["reputation"]
    value: ReputationValue


class ProcessLineageFact(_Fact):
    kind: Literal["process_lineage"]
    value: ProcessLineageValue


class SignInHistoryFact(_Fact):
    kind: Literal["sign_in_history"]
    value: SignInHistoryValue


class RelatedAlertFact(_Fact):
    kind: Literal["related_alert"]
    value: RelatedAlertValue


class HostActivityFact(_Fact):
    kind: Literal["host_activity"]
    value: HostActivityValue


class LogonFanoutFact(_Fact):
    kind: Literal["logon_fanout"]
    value: LogonFanoutValue


class PrevalenceFact(_Fact):
    kind: Literal["prevalence"]
    value: PrevalenceValue


EvidenceFact = Annotated[
    Union[
        ReputationFact,
        ProcessLineageFact,
        SignInHistoryFact,
        RelatedAlertFact,
        HostActivityFact,
        LogonFanoutFact,
        PrevalenceFact,
    ],
    Field(discriminator="kind"),
]
EVIDENCE_FACT: TypeAdapter[EvidenceFact] = TypeAdapter(EvidenceFact)


def parse_fact(data: Any) -> EvidenceFact:
    """Validate a fact (a dict or parsed JSON) against schema v1."""
    return EVIDENCE_FACT.validate_python(data)


def fact_is_complete(fact: EvidenceFact) -> bool:
    """Whether a claim of absence may rest on the fact: only an explicit ``complete: true`` counts."""
    return fact.complete is True


def fact_expires_at(fact: EvidenceFact) -> Optional[datetime]:

    return None if fact.ttl_seconds is None else fact.observed_at + timedelta(seconds=fact.ttl_seconds)


def evidence_fact_json_schema() -> Dict[str, Any]:
    """The published JSON Schema (2020-12), as written to ``schemas/evidence-fact/v1.json``."""
    body = EVIDENCE_FACT.json_schema(mode="serialization")
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": SCHEMA_ID,
        "title": "LG-SOTF evidence fact",
        "description": (
            "One typed observation an investigation tool returned; verdicts cite facts by id. "
            "See docs/evidence-facts.md."
        ),
        **body,
    }


__all__ = [
    "EVIDENCE_FACT",
    "FACT_KINDS",
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "SUBJECT_TYPES",
    "EvidenceFact",
    "FactKind",
    "HostActivityFact",
    "LogonFanoutFact",
    "MAX_LIST_ITEMS",
    "PrevalenceFact",
    "ProcessLineageFact",
    "ReputationFact",
    "RelatedAlertFact",
    "SignInHistoryFact",
    "SubjectType",
    "evidence_fact_json_schema",
    "fact_expires_at",
    "fact_is_complete",
    "parse_fact",
]
