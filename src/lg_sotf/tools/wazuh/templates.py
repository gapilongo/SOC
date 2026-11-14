"""The four evidence templates: typed, bounded parameters in, search bodies out (INT3.4, ADR 0014 section 3.1).

A template is a function from a validated parameter model to a search body built with
:mod:`lg_sotf.tools.wazuh.dsl`. Nobody writes a query: a caller chooses a tool and gives it values (a host,
an address, a path), and a value only ever becomes the right-hand side of a ``term`` or ``terms`` clause
or a bound of the time ``range``. The field, the index and the shape of the query are fixed here.

Windows event data reaches a Wazuh 4.x index with every backslash doubled. Parameters are plain Windows
strings (``C:\\Windows\\PSEXESVC.exe``); :func:`stored` gives both spellings, so a path matches however
the indexer holds it. Values are compared whole and case-sensitively (the indexer maps these fields as
``keyword``): addresses, GUIDs, hashes, paths, service names and sshd user names are exact. The one
exception is a Windows user or host name in a logon (:data:`lg_sotf.tools.wazuh.dsl.NAMES`): Windows
compares those without case and logs them as the client typed them, so they are matched without case.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Dict, List, Literal, Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lg_sotf.models.evidence_fact import LogonFamily, LogonPivot
from lg_sotf.tools.wazuh import dsl
from lg_sotf.tools.wazuh.dsl import Clause, all_of, between, named, search, term, terms

MAX_HOST_MINUTES = 60
MAX_LOGON_LOOKBACK_MINUTES = 1_440
MAX_LOGON_AFTER_MINUTES = 60
MAX_LINEAGE_AFTER_MINUTES = 30
MAX_LINEAGE_DEPTH = 8
MAX_CHILD_DEPTH = 4
MAX_LINEAGE_SUBJECTS = 3
"""Processes of one image a call describes; more than one is an ambiguous answer, and none of the facts is complete."""
MAX_PREVALENCE_DAYS = 30
LINEAGE_SLACK = timedelta(seconds=5)
"""A service's process can start a moment before the alert about the service is raised."""
LINEAGE_LOOKBACK = timedelta(days=1)
"""How far back a process named by its GUID, or a parent, is looked for."""
SYSMON = "Microsoft-Windows-Sysmon"
WINDOWS_SECURITY = "Microsoft-Windows-Security-Auditing"
"""The provider of the Windows logon events: an event with a logon's id from another provider is not a logon."""

Host = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")]
PrevalenceKind = Literal["sha256", "process_image", "service_image_path", "service_name"]
_USER = re.compile(r"^[A-Za-z0-9._$@\\-]{1,128}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")

EVENT_SOURCE = (
    dsl.TIME, dsl.RULE_ID, dsl.RULE_LEVEL, dsl.RULE_GROUPS, dsl.EVENT_ID, dsl.TARGET_USER, dsl.PROCESS_USER,
    dsl.IMAGE, dsl.COMMAND_LINE,
)
PROCESS_SOURCE = (
    dsl.TIME, dsl.IMAGE, dsl.COMMAND_LINE, dsl.PROCESS_GUID, dsl.PROCESS_ID, dsl.PROCESS_USER, dsl.PARENT_GUID,
    dsl.PARENT_ID, dsl.PARENT_IMAGE, dsl.PARENT_COMMAND_LINE, dsl.PARENT_USER,
)
PREVALENCE_FIELDS: Mapping[str, str] = {
    "sha256": dsl.FILE_SHA256,
    "process_image": dsl.IMAGE,
    "service_image_path": dsl.SERVICE_IMAGE_PATH,
    "service_name": dsl.SERVICE_NAME,
}


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    @field_validator("at", check_fields=False)
    @classmethod
    def _aware(cls, at: datetime) -> datetime:
        if at.tzinfo is None:
            raise ValueError("a time needs its offset")
        return at


class HostActivityParams(_Params):
    host: Host
    at: datetime
    before_min: int = Field(ge=0, le=MAX_HOST_MINUTES)
    after_min: int = Field(ge=0, le=MAX_HOST_MINUTES)


class LogonFanoutParams(_Params):
    """There is no filter on the outcome or the logon type: a call reads every logon of the pivot in the window,
    so a caller cannot choose what a fact leaves out."""

    pivot: LogonPivot
    value: str = Field(min_length=1, max_length=255)
    at: datetime
    before_min: int = Field(ge=1, le=MAX_LOGON_LOOKBACK_MINUTES)
    after_min: int = Field(default=0, ge=0, le=MAX_LOGON_AFTER_MINUTES)
    family: LogonFamily = "windows"

    @model_validator(mode="after")
    def _coherent(self) -> LogonFanoutParams:
        if self.pivot == "source_ip":
            ipaddress.ip_address(self.value)  # a ValueError: not an address
            shaped = True
        else:
            shaped = bool((_USER if self.pivot == "target_user" else _HOST).fullmatch(self.value))
        if not shaped or self.pivot not in LOGONS[self.family].pivots:
            raise ValueError("not a logon this family records")
        return self


class ProcessLineageParams(_Params):
    host: Host
    image: Optional[Annotated[str, Field(min_length=1, max_length=1_024)]] = None
    process_guid: Optional[Annotated[str, Field(min_length=36, max_length=38, pattern=r"^\{?[0-9A-Fa-f-]{36}\}?$")]] = None
    at: datetime
    after_min: int = Field(ge=0, le=MAX_LINEAGE_AFTER_MINUTES)
    depth: int = Field(default=MAX_LINEAGE_DEPTH, ge=0, le=MAX_LINEAGE_DEPTH)
    """How many parents up the chain is read."""
    child_depth: int = Field(default=2, ge=1, le=MAX_CHILD_DEPTH)
    """How many levels of started processes are read: 2 reaches what a shell the process started ran."""

    @model_validator(mode="after")
    def _one_subject(self) -> ProcessLineageParams:
        if (self.image is None) == (self.process_guid is None):
            raise ValueError("give the image or the process GUID, not both")
        return self


class PrevalenceParams(_Params):
    kind: PrevalenceKind
    value: str = Field(min_length=1, max_length=1_024)
    days: int = Field(ge=1, le=MAX_PREVALENCE_DAYS)

    @model_validator(mode="after")
    def _hash_is_a_hash(self) -> PrevalenceParams:
        if self.kind == "sha256" and not _SHA256.fullmatch(self.value):
            raise ValueError("not a SHA-256")
        return self


@dataclass(frozen=True)
class LogonFields:
    """How one log family writes logons: which documents they are, and where each pivot lives."""

    fixed: Tuple[Clause, ...]
    outcome_field: str
    outcomes: Mapping[str, Tuple[str, ...]]
    """Outcome -> the values of ``outcome_field`` that mean it."""
    unknown_user: Clause
    pivots: Mapping[str, str]
    lockout_pivots: Mapping[str, str]
    """Pivot -> the field a lockout names it in (a lockout carries no source address)."""
    user: str
    source: str
    source_host: Optional[str] = None
    logon_type: Optional[str] = None


_WINDOWS_FAILURES = ("4625", "4771", "4776")
LOGONS: Mapping[str, LogonFields] = {
    "windows": LogonFields(
        fixed=(term(dsl.PROVIDER, WINDOWS_SECURITY),),
        outcome_field=dsl.EVENT_ID,
        outcomes={"failure": _WINDOWS_FAILURES, "success": ("4624",), "lockout": ("4740",)},
        unknown_user=all_of(terms(dsl.EVENT_ID, _WINDOWS_FAILURES), term(dsl.SUB_STATUS, "0xc0000064")),
        pivots={
            "source_ip": dsl.SOURCE_IP, "source_host": dsl.WORKSTATION, "target_user": dsl.TARGET_USER,
            "target_host": dsl.AGENT,
        },
        lockout_pivots={"source_host": dsl.CALLER, "target_user": dsl.TARGET_USER, "target_host": dsl.AGENT},
        user=dsl.TARGET_USER,
        source=dsl.SOURCE_IP,
        source_host=dsl.WORKSTATION,
        logon_type=dsl.LOGON_TYPE,
    ),
    "sshd": LogonFields(
        fixed=(term(dsl.DECODER, "sshd"),),
        outcome_field=dsl.RULE_GROUPS,
        outcomes={"failure": ("authentication_failed",), "success": ("authentication_success",)},
        unknown_user=term(dsl.RULE_GROUPS, "invalid_login"),
        pivots={"source_ip": dsl.SSH_SOURCE, "target_user": dsl.SSH_USER, "target_host": dsl.AGENT},
        lockout_pivots={},
        user=dsl.SSH_USER,
        source=dsl.SSH_SOURCE,
    ),
}


def stored(value: str) -> List[str]:
    """``value`` as a Wazuh index may hold it: as it is, and with every backslash doubled (Wazuh 4.x)."""
    doubled = value.replace("\\", "\\\\")
    return [value] if doubled == value else [value, doubled]


def minutes(count: int) -> timedelta:
    return timedelta(minutes=count)


def _count(field: str = dsl.TIME) -> Dict[str, Any]:
    return {"value_count": {"field": field}}


def _distinct(field: str) -> Dict[str, Any]:
    return {"cardinality": {"field": field, "precision_threshold": dsl.PRECISION}}


def _top(field: str) -> Dict[str, Any]:
    return {"terms": {"field": field, "size": dsl.MAX_BUCKETS}}


def host_activity(params: HostActivityParams) -> Dict[str, Any]:
    """The host's alerts around ``at``: the 50 highest, and counts by rule group and technique over all of them."""
    start, end = params.at - minutes(params.before_min), params.at + minutes(params.after_min)
    return search(
        [term(dsl.AGENT, params.host), between(start, end)],
        size=dsl.MAX_HITS,
        source=EVENT_SOURCE,
        sort=[(dsl.RULE_LEVEL, "desc"), (dsl.TIME, "asc"), (dsl.DOC_ID, "asc")],
        aggs={
            "total": _count(),
            "max_level": {"max": {"field": dsl.RULE_LEVEL}},
            "groups": _top(dsl.RULE_GROUPS),
            "techniques": _top(dsl.TECHNIQUES),
        },
    )


def _logon_filters(params: LogonFanoutParams, outcomes: List[str], field: str, start: datetime) -> List[Clause]:
    logons = LOGONS[params.family]
    values = [value for outcome in outcomes for value in logons.outcomes[outcome]]
    pivot = named(field, params.value) if field in dsl.NAMES else term(field, params.value)
    return [*logons.fixed, terms(logons.outcome_field, values), pivot, between(start, params.at + minutes(params.after_min))]


def counted(params: LogonFanoutParams) -> List[str]:
    """The outcomes :func:`logons` counts: all of them, a lockout only where it names the pivot as a logon does."""
    spec = LOGONS[params.family]
    field = spec.pivots[params.pivot]
    return [o for o in spec.outcomes if o != "lockout" or spec.lockout_pivots.get(params.pivot) == field]


def logons(params: LogonFanoutParams) -> Dict[str, Any]:
    """Every logon where the pivot is ``value``: counts by outcome, distinct users, sources and hosts, who and from where.

    Always every outcome and every logon type. A lockout is counted here when it names the pivot in the same
    field as a logon does (the user, the host that raised it); :func:`lockouts` reads the others.
    """
    spec = LOGONS[params.family]
    field, outcomes = spec.pivots[params.pivot], counted(params)
    buckets = {outcome: terms(spec.outcome_field, spec.outcomes[outcome]) for outcome in outcomes}
    buckets["unknown_user"] = spec.unknown_user
    aggs: Dict[str, Any] = {
        "users": _distinct(spec.user),
        "sources": _distinct(spec.source),
        "hosts": _distinct(dsl.AGENT),
        "source_list": _top(spec.source),
        "outcomes": {"filters": {"filters": buckets}, "aggs": {"users": _top(spec.user), "first": {"min": {"field": dsl.TIME}}}},
    }
    if spec.source_host is not None:
        aggs["source_hosts"] = _top(spec.source_host)
    if spec.logon_type is not None:
        aggs["logon_types"] = _top(spec.logon_type)
    return search(_logon_filters(params, outcomes, field, params.at - minutes(params.before_min)), aggs=aggs)


def lockouts(params: LogonFanoutParams) -> Optional[Dict[str, Any]]:
    """The lockouts a source host caused: a lockout names it as the caller, not as a logon's workstation."""
    spec = LOGONS[params.family]
    field = spec.lockout_pivots.get(params.pivot)
    if field is None or field == spec.pivots[params.pivot]:
        return None
    start = params.at - minutes(params.before_min)
    return search(_logon_filters(params, ["lockout"], field, start), aggs={"total": _count()})


def first_success(params: LogonFanoutParams, since: datetime) -> Dict[str, Any]:
    """The first success at or after ``since`` (the first failure), when an earlier success hides it."""
    field = LOGONS[params.family].pivots[params.pivot]
    return search(_logon_filters(params, ["success"], field, since), aggs={"first": {"min": {"field": dsl.TIME}}})


def processes(host: str, field: str, values: List[str], start: datetime, end: datetime) -> Dict[str, Any]:
    """Process creations (Sysmon event 1) on ``host`` whose ``field`` is one of ``values``, oldest first."""
    return search(
        [term(dsl.EVENT_ID, "1"), term(dsl.PROVIDER, SYSMON), term(dsl.AGENT, host), terms(field, values), between(start, end)],
        size=dsl.MAX_HITS,
        source=PROCESS_SOURCE,
        sort=[(dsl.TIME, "asc"), (dsl.DOC_ID, "asc")],
    )


def prevalence(params: PrevalenceParams, end: datetime) -> Dict[str, Any]:
    """Where the value was seen over the ``days`` before ``end``: how many agents, how often, first and last."""
    values = [params.value.lower()] if params.kind == "sha256" else stored(params.value)
    return search(
        [terms(PREVALENCE_FIELDS[params.kind], values), between(end - timedelta(days=params.days), end)],
        aggs={
            "total": _count(),
            "hosts": _distinct(dsl.AGENT),
            "first": {"min": {"field": dsl.TIME}},
            "last": {"max": {"field": dsl.TIME}},
        },
    )


def coverage() -> Dict[str, Any]:
    """The oldest alert the index pattern still holds: a window that starts before it is not covered."""
    return search([], aggs={"oldest": {"min": {"field": dsl.TIME}}})
