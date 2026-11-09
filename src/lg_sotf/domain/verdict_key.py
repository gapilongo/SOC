"""Verdict keys: what the verdict cache, suggested suppression rules and benign group decisions treat as "the same alert".

The alert fingerprint (``lg_sotf.ingestion.fingerprint``) is the rule plus
the key entities: hosts, users, IPs, hashes and domains. That is right for
grouping and correlation, but too coarse to close an alert on someone else's
decision: on one host, a ransomware ``PSEXESVC`` service and an Edge update
service share a fingerprint, and so do ``ps`` run by a web shell as uid 33
and ``ps`` run by monitoring as root.

``verdict_key = sha256(json({"v", "fingerprint", "behaviour"}))`` refines the
fingerprint with the behaviour of the alert. ``behaviour`` maps each field
the event has, by its role, to its values:

* the process: image fields (``image``, ``exe``, ``processName``,
  ``process.executable``, ``process.name``, GuardDuty ``ExecutablePath``,
  Defender ``FileName`` and ``FolderPath``, ``entities.processes``);
* the command: ``commandLine``, ``command``, ``process.args``, auditd
  ``execve`` arguments, PowerShell script blocks, ``entities.command_lines``;
* the service: name and image path;
* the user: uid, euid, auid and each user or account name field under its
  own name, so a subject and a target never swap unnoticed;
* the parent: parent image and command line (also ECS ``process.parent.*``
  and Defender ``InitiatingProcess*``);
* the objects an attacker creates and names: scheduled task name and
  content, registry key, target file name and, in Sysmon WMI events (19 to
  21), the filter, consumer and name;
* context that tells two requests or operations apart but says nothing about
  what ran: URLs and request paths and queries, user agents, registry value
  details, DNS and WMI queries, destinations, O365 operations and their
  parameters, Sysmon process-access rights (``GrantedAccess``) and call
  traces, file paths.

The fields are found by name anywhere in the alert's ``unmapped`` section and
its ``raw`` event, so they work for every normalizer. Values are compared in
full: whitespace runs collapse to one space, doubled backslashes (a JSON
escaping artefact) to one, and Windows paths (drive, UNC or ``%VAR%``
prefix) are lowercased, as Windows compares them. Nothing else is masked or
cut: an attacker controls command lines, directory and file names, so a
masked or truncated part would let a payload match a benign value.

:func:`verdict_key` returns ``None`` (the alert never closes from the cache,
gets no suggested rule and inherits no benign group decision) when:

* the event names no process, command, service or attacker-created object
  (the *anchors*): context alone, such as a user agent, a URL or an O365
  operation, is set by whoever sends the request, so the key would be the
  fingerprint plus attacker-chosen text;
* the alert is in a never-close class (:func:`lg_sotf.domain.closure.never_close_class`:
  credential access, log clearing, tampering, ransomware, persistence through
  named objects). Unmapped alerts keep a key: unlike a model-led close, a
  cache close or a suggested rule needs analysts' decisions on this exact
  behaviour, and most unmapped detections are routine noise;
* the alert was normalised by a model (``llm_normalized``): its fields are
  the model's reading of attacker-shaped text;
* the behaviour cannot be read completely: a truncated ``unmapped`` or
  ``raw`` document, a value over :data:`MAX_VALUE_CHARS`, or more fields
  than the caps.

Bump :data:`VERSION` when the recipe changes; old keys then never match.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterator, List, Mapping, Optional, Set, Tuple

from lg_sotf.domain.closure import UNMAPPED, never_close_class

VERSION = 4
MAX_VALUE_CHARS = 16_384
MAX_VALUES_PER_FIELD = 32
MAX_WALK_NODES = 5_000
MAX_WALK_DEPTH = 12
TRUNCATED_MARKER = "_lgsotf_truncated"  # lg_sotf.models.alert.TRUNCATED_MARKER
LLM_NORMALIZED_FLAG = "llm_normalized"  # lg_sotf.domain.routing.LLM_NORMALIZED_FLAG

PROCESS, COMMAND, SERVICE, USER, PARENT = "process", "command", "service", "user", "parent"
OBJECT, CONTEXT, META = "object", "context", "meta"
#: Roles that say what ran or what was created; without one of them the key is only the fingerprint.
ANCHORS = frozenset({PROCESS, COMMAND, SERVICE, OBJECT})
#: WMI fields that anchor the key only in a Sysmon WMI event (19 to 21): elsewhere they are generic.
WMI_ANCHORS = frozenset({"name.wmi", "consumer", "filter"})
SYSMON_WMI_EVENTS = frozenset({"19", "20", "21"})


def _names(role: str, *names: str) -> Dict[str, str]:
    return dict.fromkeys(names, role)


# Field names (lowercased, without "_", "-" and "."; a nested field as "<parent>.<name>") -> role.
# A field keeps its own name in the key (``subjectusername`` and ``targetusername`` are different fields).
FIELD_ROLES: Dict[str, str] = {
    **_names(PROCESS, "image", "exe", "processname", "newprocessname", "processpath", "originalfilename",
             "targetimage", "sourceimage", "imageloaded", "executable", "executablepath", "processes",
             "process.executable", "process.name", "process.path", "filename", "folderpath"),
    **_names(COMMAND, "commandline", "commandlines", "cmdline", "processcommandline", "command",
             "scriptblocktext", "process.commandline", "process.args", "process.command"),
    **_names(SERVICE, "servicename", "imagepath", "servicefilename"),
    **_names(USER, "uid", "euid", "auid", "user", "username", "accountname", "subjectusername", "targetusername",
             "samaccountname", "parentuser", "sourceuser", "targetuser", "user.name", "user.id"),
    **_names(PARENT, "parentimage", "parentprocessname", "parentcommandline", "parent.executable", "parent.name",
             "parent.commandline", "parent.args", "initiatingprocessfilename", "initiatingprocessfolderpath",
             "initiatingprocesscommandline"),
    # Objects the attacker creates and names (lg_sotf.domain.benign_evidence.ATTACKER_NAMED_RAW_FIELDS and the
    # Windows and Sysmon fields that carry them).
    **_names(OBJECT, "taskname", "taskcontent", "targetobject", "targetfilename"),
    # In the key, never an anchor: set by whoever sends the request, or too generic to say what ran.
    **_names(CONTEXT, "details", "filepath", "consumer", "filter", "query", "destination", "operation", "name.wmi",
             "useragent", "httpuseragent", "url", "urls", "uri", "httpurl", "urlpath", "uripath", "uriquery",
             "uristem", "querystring", "requestpath", "requesturi", "grantedaccess", "calltrace", "parameters"),
    # Read to recognise Sysmon WMI events, never part of the key.
    **_names(META, "eventid", "providername"),
}
ENTITY_FIELDS = (("processes", "processes"), ("command_lines", "commandlines"), ("urls", "urls"))
# Keys whose ``name`` child is a WMI object name (Sysmon 19-21 put it at eventdata.name).
_WMI_PARENTS = frozenset({"eventdata"})
_WINDOWS_PATH = re.compile(r"^(?:[a-z]:\\|\\\\|%[a-z_]+%)", re.IGNORECASE)


def _norm(name: str) -> str:
    return re.sub(r"[_\-.]", "", name.lower())


def _field(path: Tuple[str, ...]) -> Optional[str]:
    """The key field of the scalar at ``path`` (the dict keys leading to it), or ``None``."""
    last = _norm(path[-1])
    if len(path) >= 2:
        nested = f"{_norm(path[-2])}.{last}"
        if nested in FIELD_ROLES:
            return nested
        if last == "name" and _norm(path[-2]) in _WMI_PARENTS:
            return "name.wmi"
    return last if last in FIELD_ROLES else None


def normalize_value(field: str, value: str) -> str:
    """Whitespace collapsed, doubled backslashes made single, Windows paths lowercased; nothing masked or cut."""
    text = re.sub(r"\\{2,}", r"\\", " ".join(value.split()))
    if FIELD_ROLES.get(field) in (PROCESS, SERVICE, PARENT) and _WINDOWS_PATH.match(text):
        text = text.lower()
    return text


def _execve(args: Mapping[str, Any]) -> str:
    """auditd ``execve`` arguments (``a0``, ``a1``...) as one command line."""
    numbered = sorted((int(k[1:]), v) for k, v in args.items() if re.fullmatch(r"a\d{1,3}", str(k)))
    return " ".join(str(v) for _, v in numbered)


def _parameters(items: List[Any]) -> Iterator[Tuple[str, str]]:
    """O365 ``Parameters`` (``[{"Name": ..., "Value": ...}]``) as ``Name=Value`` pairs.

    A longer list than the cap gives no key (``OverflowError``): reading only its first items would let repeated
    benign parameters hide one appended after them.
    """
    if len(items) > MAX_VALUES_PER_FIELD:
        raise OverflowError("too many parameters to read the behaviour")
    for item in items:
        if isinstance(item, Mapping):
            named = {str(k).lower(): v for k, v in item.items()}
            yield "parameters", f"{named.get('name')}={named.get('value')}"


def _walk(node: Any) -> Iterator[Tuple[str, Any]]:
    """``(field, scalar value)`` pairs of a document; raises ``OverflowError`` past the caps.

    A list's items take the field of the key holding the list.
    """
    stack: List[Tuple[Tuple[str, ...], Optional[str], Any]] = [((), None, node)]
    seen = 0
    while stack:
        path, field, value = stack.pop()
        seen += 1
        if seen > MAX_WALK_NODES or len(path) > MAX_WALK_DEPTH:
            raise OverflowError("document too large to read its behaviour")
        if isinstance(value, Mapping):
            if TRUNCATED_MARKER in value:
                raise OverflowError("document was truncated at ingestion")
            for key, child in value.items():
                child_path = (*path, str(key))
                if str(key).lower() == "execve" and isinstance(child, Mapping):
                    yield "command", _execve(child)
                elif _norm(str(key)) == "parameters" and isinstance(child, list):
                    yield from _parameters(child)
                else:
                    stack.append((child_path, _field(child_path), child))
        elif isinstance(value, list):
            stack.extend((path, field, child) for child in value)
        elif field is not None and isinstance(value, (str, int)) and not isinstance(value, bool):
            yield field, value


def behaviour(normalized: Mapping[str, Any], raw: Optional[Mapping[str, Any]] = None) -> Optional[Dict[str, List[str]]]:
    """The behaviour fields of an alert by field name, or ``None`` when they cannot be read completely."""
    found = _fields(normalized, raw)
    if found is None:
        return None
    return {f: v for f, v in found.items() if FIELD_ROLES.get(f) != META}


def _sysmon_wmi(found: Mapping[str, List[str]]) -> bool:
    return bool(set(found.get("eventid", [])) & SYSMON_WMI_EVENTS) and any(
        "sysmon" in p.lower() for p in found.get("providername", [])
    )


def _anchored(found: Mapping[str, List[str]]) -> bool:
    wmi = _sysmon_wmi(found)
    return any(FIELD_ROLES.get(f) in ANCHORS or (wmi and f in WMI_ANCHORS) for f in found)


def _fields(normalized: Mapping[str, Any], raw: Optional[Mapping[str, Any]]) -> Optional[Dict[str, List[str]]]:
    pairs: List[Tuple[str, Any]] = []
    entities = normalized.get("entities")
    for kind, field in ENTITY_FIELDS:
        values = entities.get(kind) if isinstance(entities, Mapping) else None
        pairs.extend((field, v) for v in values or [] if isinstance(v, str))
    try:
        pairs.extend(_walk(normalized.get("unmapped") or {}))
        pairs.extend(_walk(raw or {}))
    except OverflowError:
        return None
    found: Dict[str, Set[str]] = {}
    for field, value in pairs:
        text = normalize_value(field, str(value)) if value is not None else ""
        if len(text) > MAX_VALUE_CHARS:
            return None
        if text:
            found.setdefault(field, set()).add(text)
    if any(len(values) > MAX_VALUES_PER_FIELD for values in found.values()):
        return None
    return {field: sorted(values) for field, values in sorted(found.items())}


def _flags(normalized: Mapping[str, Any]) -> List[Any]:
    flags = normalized.get("flags")
    return flags if isinstance(flags, list) else []


def verdict_key(fingerprint: Optional[str], normalized: Mapping[str, Any], raw: Optional[Mapping[str, Any]] = None) -> Optional[str]:
    """Lowercase hex sha256 (64 characters), or ``None`` when the alert must not use the verdict cache."""
    if not fingerprint or LLM_NORMALIZED_FLAG in _flags(normalized):
        return None
    if never_close_class(normalized) not in (None, UNMAPPED):
        return None
    found = _fields(normalized, raw)
    if found is None or not _anchored(found):
        return None
    fields = {f: v for f, v in found.items() if FIELD_ROLES.get(f) != META}
    payload = json.dumps({"v": VERSION, "fingerprint": fingerprint, "behaviour": fields}, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verdict_key_of(alert: Any) -> Optional[str]:
    """:func:`verdict_key` of a stored alert (an object or mapping with ``fingerprint``, ``normalized``, ``raw``)."""
    get = alert.get if isinstance(alert, Mapping) else lambda name: getattr(alert, name, None)
    normalized, raw = get("normalized"), get("raw")
    if not isinstance(normalized, Mapping):
        return None
    return verdict_key(get("fingerprint"), normalized, raw if isinstance(raw, Mapping) else None)
