"""Declared tenant context of an evaluation dataset (``_meta.tenant_context``) and what it covers.

A real customer tells its MSSP a few facts about its estate: who the IT
administrators and the helpdesk are, which service accounts and hosts run
automation, which host IT uses to administer workstations, when servers are
patched and which address the authorised vulnerability scanner uses. A
dataset declares those facts once, for the whole tenant::

    {"_meta": {"tenant_context": {
        "admin_accounts": ["adm.ksmith"], "admin_groups": ["IT-Admins"],
        "helpdesk_accounts": ["hd.ochen"],
        "automation_accounts": ["ansible"], "automation_hosts": ["build-01"],
        "jump_hosts": [{"host": "IT-WS-01", "ips": ["10.20.1.120"], "tools": ["psexec"]}],
        "patch_windows": [{"name": "servers", "days": ["mon"], "start": "01:00", "end": "05:00",
                           "hosts": ["db-01"]}],
        "scanners": ["10.20.5.10"]}}}

Only the scanner is consumed by the product today (through
``_meta.tenant_settings.triage.known_scanners``, which must list the same
scanners). Everything else is measurement: :func:`context_matches` says which
declared facts an alert touches, read from the alert as the platform
normalises it (structured entities, the event time) plus the acting-user
fields of Windows events, never from free text. A report then shows how many
benign alerts the context covers (closable with context) and, just as
important, how many malicious ones it covers too: context that also matches
attacks cannot close anything on its own.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, time
from typing import Annotated, Any, Dict, FrozenSet, Iterable, List, Literal, Mapping, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Day = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAYS: Tuple[Day, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MAX_ENTRIES = 256
_CLOCK = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")
#: The kinds :func:`context_matches` reports, in report order.
CONTEXT_KINDS: Tuple[str, ...] = (
    "admin_account",
    "admin_group",
    "helpdesk_account",
    "automation_account",
    "automation_host",
    "jump_host",
    "patch_window",
    "scanner",
)
# Windows fields that name who acted (Sysmon ``user``, Security-log subject and target); the Wazuh
# normalizer maps only some of them to entities.
_ACTING_USER_FIELDS = ("user", "subjectUserName", "targetUserName", "parentUser", "sourceUser")


def _key(value: str) -> str:
    """A host or account as the matcher compares it: lower case, without a ``DOMAIN\\`` prefix or ``@realm``."""
    text = value.strip().lower()
    if "\\" in text:
        text = text.rsplit("\\", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text


def _clock(value: str) -> time:
    match = _CLOCK.match(value)
    if match is None:
        raise ValueError("times are HH:MM (24-hour, UTC)")
    return time(int(match.group(1)), int(match.group(2)))


class PatchWindow(BaseModel):
    """A recurring maintenance window, in UTC; ``end`` before ``start`` crosses midnight."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Name
    days: List[Day] = Field(default_factory=lambda: list(DAYS), min_length=1, max_length=7)
    start: str
    end: str
    hosts: List[Name] = Field(min_length=1, max_length=MAX_ENTRIES)

    @field_validator("start", "end")
    @classmethod
    def _hhmm(cls, value: str) -> str:
        _clock(value)
        return value

    @model_validator(mode="after")
    def _not_empty(self) -> PatchWindow:
        if self.start == self.end:
            raise ValueError("a patch window needs different start and end times")
        return self

    def covers(self, at: datetime, hosts: Iterable[str]) -> bool:
        """``at`` (UTC) falls in the window on one of its days and one of ``hosts`` is in scope."""
        if not {_key(h) for h in self.hosts} & {_key(h) for h in hosts}:
            return False
        start, end, clock = _clock(self.start), _clock(self.end), at.time().replace(tzinfo=None)
        day = DAYS[at.weekday()]
        if start < end:
            return day in self.days and start <= clock < end
        if clock >= start:
            return day in self.days
        # After midnight: the window opened the previous day.
        return clock < end and DAYS[(at.weekday() - 1) % 7] in self.days


class JumpHost(BaseModel):
    """A host IT administers others from, and the tools it runs (``psexec``, ``rdp``, ``ssh``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: Name
    ips: List[Name] = Field(default_factory=list, max_length=16)
    tools: List[Name] = Field(default_factory=list, max_length=16)


class TenantContext(BaseModel):
    """``_meta.tenant_context``: facts about the estate a customer would plausibly declare."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: Optional[str] = Field(default=None, max_length=2_000)
    admin_accounts: List[Name] = Field(default_factory=list, max_length=MAX_ENTRIES)
    admin_groups: List[Name] = Field(default_factory=list, max_length=MAX_ENTRIES)
    helpdesk_accounts: List[Name] = Field(default_factory=list, max_length=MAX_ENTRIES)
    automation_accounts: List[Name] = Field(default_factory=list, max_length=MAX_ENTRIES)
    automation_hosts: List[Name] = Field(default_factory=list, max_length=MAX_ENTRIES)
    jump_hosts: List[JumpHost] = Field(default_factory=list, max_length=32)
    patch_windows: List[PatchWindow] = Field(default_factory=list, max_length=32)
    scanners: List[Name] = Field(default_factory=list, max_length=MAX_ENTRIES)

    @field_validator("scanners")
    @classmethod
    def _scanner(cls, values: List[str]) -> List[str]:
        for value in values:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)  # ValueError for a malformed range
        return values

    @model_validator(mode="after")
    def _accounts_once(self) -> TenantContext:
        lists = (self.admin_accounts, self.helpdesk_accounts, self.automation_accounts)
        seen: Set[str] = set()
        for names in lists:
            for name in names:
                if _key(name) in seen:
                    raise ValueError(f"account {name!r} is declared twice; give each account one role")
                seen.add(_key(name))
        return self

    def declared(self) -> Dict[str, int]:
        """How many entries each kind declares (for the report)."""
        counts = {
            "admin_account": len(self.admin_accounts),
            "admin_group": len(self.admin_groups),
            "helpdesk_account": len(self.helpdesk_accounts),
            "automation_account": len(self.automation_accounts),
            "automation_host": len(self.automation_hosts),
            "jump_host": len(self.jump_hosts),
            "patch_window": len(self.patch_windows),
            "scanner": len(self.scanners),
        }
        return {k: v for k, v in counts.items() if v}


def _mapping(value: Any, key: str) -> Mapping[str, Any]:
    found = value.get(key) if isinstance(value, Mapping) else None
    return found if isinstance(found, Mapping) else {}


def _raw_users(raw: Mapping[str, Any]) -> List[str]:
    eventdata = _mapping(_mapping(_mapping(raw, "data"), "win"), "eventdata")
    return [str(eventdata[k]) for k in _ACTING_USER_FIELDS if isinstance(eventdata.get(k), str)]


def _in_scanners(scanners: Sequence[str], hosts: FrozenSet[str], ips: Sequence[str]) -> bool:
    for scanner in scanners:
        if "/" in scanner:
            network = ipaddress.ip_network(scanner, strict=False)
            for ip in ips:
                try:
                    if ipaddress.ip_address(ip) in network:
                        return True
                except ValueError:
                    continue
        elif _key(scanner) in hosts or scanner.strip() in ips:
            return True
    return False


def context_matches(context: TenantContext, alert: Mapping[str, Any]) -> List[str]:
    """The declared facts ``alert`` (a canonical alert as a dict) touches, as :data:`CONTEXT_KINDS`."""
    entities = _mapping(alert, "entities")
    users = frozenset(
        _key(u) for u in [*(entities.get("users") or []), *_raw_users(_mapping(alert, "raw"))] if isinstance(u, str)
    )
    hosts = frozenset(_key(h) for h in entities.get("hosts") or [] if isinstance(h, str))
    ips = [str(ip) for ip in entities.get("ips") or []]
    found: Set[str] = set()
    # Group names are matched against the accounts too: a Windows group change reports the group as its target.
    for kind, names in (
        ("admin_account", context.admin_accounts),
        ("admin_group", context.admin_groups),
        ("helpdesk_account", context.helpdesk_accounts),
        ("automation_account", context.automation_accounts),
    ):
        if users & {_key(n) for n in names}:
            found.add(kind)
    if hosts & {_key(h) for h in context.automation_hosts}:
        found.add("automation_host")
    for jump in context.jump_hosts:
        if _key(jump.host) in hosts or set(jump.ips) & set(ips):
            found.add("jump_host")
    occurred = _occurred(alert.get("occurred_at"))
    if occurred is not None and any(w.covers(occurred, hosts) for w in context.patch_windows):
        found.add("patch_window")
    if _in_scanners(context.scanners, hosts, ips):
        found.add("scanner")
    return [kind for kind in CONTEXT_KINDS if kind in found]


def _occurred(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
