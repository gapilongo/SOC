"""Verdict keys: what the verdict cache and benign group decisions treat as "the same alert".

The alert fingerprint (``lg_sotf.ingestion.fingerprint``) is the rule plus
the key entities: hosts, users, IPs, hashes and domains. That is right for
grouping and correlation, but too coarse to close an alert on someone else's
decision: on one host, a ransomware ``PSEXESVC`` service and an Edge update
service share a fingerprint, and so do ``ps`` run by a web shell as uid 33
and ``ps`` run by monitoring as root.

``verdict_key = sha256(json({"v", "fingerprint", "behaviour"}))`` refines the
fingerprint with the behaviour of the alert, where the event has it:

* ``process``: process images (``entities.processes`` and image fields such
  as ``image``, ``exe``, ``processName``, ``targetFilename``);
* ``command``: command lines (``entities.command_lines``, ``commandLine``,
  ``command``, auditd ``execve`` arguments, PowerShell script blocks);
* ``service``: service name and image path;
* ``user``: uid, euid, auid and user/account names;
* ``parent``: parent process image and command line.

The fields are found by name anywhere in the alert's ``unmapped`` section and
its ``raw`` event, so they work for every normalizer. Values are lowercased,
whitespace-collapsed and masked where they vary between repeats of the same
activity: GUIDs, timestamps, long hex and digit runs, and generated names
under a temp directory (the extension is kept). Process ids, logon ids and
other per-event ids are never read.

:func:`verdict_key` returns ``None`` (the alert is never closed from the
cache nor teaches it) when the behaviour cannot be read completely: a
truncated ``unmapped`` or ``raw`` document, or more fields than the caps.
Bump :data:`VERSION` when the recipe changes; old keys then never match.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterator, List, Mapping, Optional, Set, Tuple

VERSION = 2
MAX_VALUE_CHARS = 512
MAX_VALUES_PER_FIELD = 32
MAX_WALK_NODES = 5_000
MAX_WALK_DEPTH = 12
TRUNCATED_MARKER = "_lgsotf_truncated"  # lg_sotf.models.alert.TRUNCATED_MARKER

# Field names (lowercased, without "_", "-" and ".") -> behaviour field.
FIELD_NAMES: Dict[str, str] = {
    **dict.fromkeys(
        ("image", "exe", "processname", "newprocessname", "processpath", "originalfilename", "targetimage",
         "sourceimage", "targetfilename", "imageloaded", "executable", "processes"),
        "process",
    ),
    **dict.fromkeys(
        ("commandline", "commandlines", "cmdline", "processcommandline", "command", "scriptblocktext"), "command"
    ),
    **dict.fromkeys(("servicename", "imagepath", "servicefilename"), "service"),
    **dict.fromkeys(
        ("uid", "euid", "auid", "user", "username", "accountname", "subjectusername", "targetusername",
         "samaccountname", "parentuser", "sourceuser", "targetuser"),
        "user",
    ),
    **dict.fromkeys(("parentimage", "parentprocessname", "parentcommandline"), "parent"),
}
ENTITY_FIELDS = (("processes", "process"), ("command_lines", "command"))

_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}(?:[t ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:z|[+-]\d{2}:?\d{2})?)?|\d{2}:\d{2}:\d{2}")
_TEMP_NAME = re.compile(r"([\\/]te?mp[\\/])([^\\/\s\"']+)")
_EXTENSION = re.compile(r"\.[a-z0-9]{1,5}$")
_HEX = re.compile(r"\b[0-9a-f]{16,}\b")
_DIGITS = re.compile(r"\d{6,}")


def _mask_temp(match: re.Match[str]) -> str:
    name = match.group(2)
    if not (any(c.isdigit() for c in name) or name.startswith(("tmp", "~"))):
        return match.group(0)
    ext = _EXTENSION.search(name)
    return f"{match.group(1)}<tmp>{ext.group(0) if ext else ''}"


def normalize_value(value: str) -> str:
    """Lowercased, whitespace-collapsed, single backslashes, volatile parts masked, capped."""
    text = " ".join(value[: MAX_VALUE_CHARS * 8].lower().split())
    text = re.sub(r"\\{2,}", r"\\", text)
    text = _GUID.sub("<guid>", text)
    text = _TIME.sub("<time>", text)
    text = _TEMP_NAME.sub(_mask_temp, text)
    text = _HEX.sub("<hex>", text)
    text = _DIGITS.sub("<n>", text)
    return text[:MAX_VALUE_CHARS]


def _field(name: str) -> Optional[str]:
    return FIELD_NAMES.get(re.sub(r"[_\-.]", "", name.lower()))


def _execve(args: Mapping[str, Any]) -> str:
    """auditd ``execve`` arguments (``a0``, ``a1``...) as one command line."""
    numbered = sorted((int(k[1:]), v) for k, v in args.items() if re.fullmatch(r"a\d{1,3}", str(k)))
    return " ".join(str(v) for _, v in numbered)


def _walk(node: Any) -> Iterator[Tuple[str, Any]]:
    """``(field, scalar value)`` pairs of a document; raises ``OverflowError`` past the caps.

    A list's items take the field of the key holding the list.
    """
    stack: List[Tuple[Optional[str], Any, int]] = [(None, node, 0)]
    seen = 0
    while stack:
        field, value, depth = stack.pop()
        seen += 1
        if seen > MAX_WALK_NODES or depth > MAX_WALK_DEPTH:
            raise OverflowError("document too large to read its behaviour")
        if isinstance(value, Mapping):
            if TRUNCATED_MARKER in value:
                raise OverflowError("document was truncated at ingestion")
            for key, child in value.items():
                if str(key).lower() == "execve" and isinstance(child, Mapping):
                    yield "command", _execve(child)
                else:
                    stack.append((_field(str(key)), child, depth + 1))
        elif isinstance(value, list):
            stack.extend((field, child, depth + 1) for child in value)
        elif field is not None and isinstance(value, (str, int)) and not isinstance(value, bool):
            yield field, value


def behaviour(normalized: Mapping[str, Any], raw: Optional[Mapping[str, Any]] = None) -> Optional[Dict[str, List[str]]]:
    """The normalised behaviour fields of an alert, or ``None`` when they cannot be read completely."""
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
        text = normalize_value(str(value)) if value is not None else ""
        if text:
            found.setdefault(field, set()).add(text)
    if any(len(values) > MAX_VALUES_PER_FIELD for values in found.values()):
        return None
    return {field: sorted(values) for field, values in sorted(found.items())}


def verdict_key(fingerprint: Optional[str], normalized: Mapping[str, Any], raw: Optional[Mapping[str, Any]] = None) -> Optional[str]:
    """Lowercase hex sha256 (64 characters), or ``None`` when the alert must not use the verdict cache."""
    if not fingerprint:
        return None
    fields = behaviour(normalized, raw)
    if fields is None:
        return None
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
