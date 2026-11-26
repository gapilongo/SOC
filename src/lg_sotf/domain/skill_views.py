"""The typed view of an alert that an investigation skill binds its queries to (ADR 0014 section 2.1).

A skill never takes a query value from a model, from the alert's title or description, or from free
text. :func:`wazuh_alert_view` reads a fixed list of fields of the Wazuh document the detector wrote
(``agent.name``, the decoded event fields under ``data``, ``syscheck``) and parses each one: a host that
is not a host name, an address that is not an address or a user name outside the allowed characters is
``None``, and a query bound to a ``None`` field is skipped, never guessed.

The view is built only for an alert the Wazuh normalizer produced (``normalizer``, set by the ingestion
service and never read from the event). When the raw event was too large for the workflow state it is
not there to read: the view is empty and nothing runs.

Standard library only: no I/O.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, fields
from typing import Any, Callable, FrozenSet, Mapping, Optional, Tuple

__all__ = ["COMMON_BINARY", "VIEWS", "WAZUH", "WAZUH_ALERT_VIEW", "WazuhAlertView", "common_binary", "view_fields",
           "wazuh_alert_view"]

WAZUH = "wazuh"
WAZUH_ALERT_VIEW = "wazuh.alert"
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_USER = re.compile(r"^[A-Za-z0-9._$@\\-]{1,128}$")
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
MAX_OBJECT_CHARS = 1_024
_BACKSLASHES = re.compile(r"\\+")
_ADDRESS = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
COMMON_BINARY = "common_binary"
#: Where an operating system keeps its own programs: a process image there runs on every host, so how widely
#: it is seen says nothing about the alert.
_SYSTEM_DIRECTORY = re.compile(r"^(?:[a-z]:\\windows\\(?:(?:system32|syswow64|sysnative|winsxs)\\|[^\\]+$)|/(?:usr/)?s?bin/|/usr/libexec/)")
#: Interpreters and living-off-the-land programs, by file name: present everywhere, and what matters is what
#: they were told to run. A short reviewed list (our own; no third-party catalogue is bundled).
_COMMON_IMAGES = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe", "schtasks.exe", "sc.exe",
    "net.exe", "net1.exe", "reg.exe", "curl.exe", "python.exe", "pythonw.exe", "java.exe", "node.exe",
    "bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "node", "java", "curl", "wget", "nc",
})
_MASKED = "[REDACTED"
"""How the redaction of ``lg_sotf.security.redaction`` marks a masked secret."""
_ED = ("data", "win", "eventdata")
# Where the object an alert is about is read, in this order: a file's hash, a service's binary, a process image.
_OBJECTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("sha256", ("syscheck", "sha256_after")),
    ("service_image_path", (*_ED, "imagePath")),
    ("process_image", (*_ED, "image")),
)


@dataclass(frozen=True)
class WazuhAlertView:
    """What a skill may bind from a Wazuh alert. Every field is parsed; ``None``: absent or not well-formed."""

    host: Optional[str] = None
    """The agent that raised the alert (``agent.name``)."""
    user: Optional[str] = None
    """The account a logon was for (Windows ``targetUserName``, sshd ``dstuser``)."""
    source_ip: Optional[str] = None
    """The address a logon came from (Windows ``ipAddress``, sshd ``srcip``); never loopback."""
    logon_family: Optional[str] = None
    """``windows`` or ``sshd``: how the alert's log family writes logons."""
    object_kind: Optional[str] = None
    """What ``object_value`` is: ``sha256``, ``service_image_path`` or ``process_image``."""
    object_value: Optional[str] = None
    rule_id: Optional[str] = None
    """The detection rule that raised the alert (``rule.id``): with the alert's time it names the alert's own
    event, which a lookup of the host leaves out."""
    withheld: Tuple[Tuple[str, str], ...] = ()
    """Fields left ``None`` on purpose, with why (``object_value``: ``common_binary``). Not bindable."""

    def why_unbound(self, field_name: str) -> Optional[str]:
        return dict(self.withheld).get(field_name)


def _at(document: Mapping[str, Any], path: Tuple[str, ...]) -> Optional[str]:
    node: Any = document
    for part in path:
        node = node.get(part) if isinstance(node, Mapping) else None
    return node.strip() if isinstance(node, str) and node.strip() else None


def _address(text: Optional[str]) -> Optional[str]:
    try:
        address = ipaddress.ip_address(text or "")
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or not _ADDRESS.fullmatch(text or ""):
        return None
    # As the detector wrote it: an index holds an address as text, and a query compares it whole. The lookup
    # asks for this spelling and for the canonical one (``lg_sotf.tools.wazuh.templates.spellings``).
    return text


def _windows_text(text: Optional[str]) -> Optional[str]:
    """A Windows value as Windows wrote it. A Wazuh 4.x document holds every backslash doubled, so a value
    whose backslashes all come in pairs is halved; any other (a UNC path of a document that was not doubled)
    is left as it is."""
    if not text:
        return None
    doubled = all(len(run) % 2 == 0 for run in _BACKSLASHES.findall(text))
    return text.replace("\\\\", "\\") if doubled else text


def _altered(value: str) -> bool:
    """Whether ingestion changed the value (a secret masked, a long string cut): the index holds the original,
    so a lookup of the changed one would wrongly find nothing."""
    return _MASKED in value or value.endswith("...") or "\x00" in value


def common_binary(image: str) -> bool:
    """Whether a process image is one every host runs: under a system directory, or an interpreter or
    living-off-the-land program by name. Its prevalence would read as reassuring and mean nothing."""
    path = image.replace("/", "\\").lower() if "\\" in image else image.lower()
    name = re.split(r"[\\/]", path)[-1]
    return name in _COMMON_IMAGES or bool(_SYSTEM_DIRECTORY.match(path))


def _object(document: Mapping[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """``(kind, value, why not)``: the file's hash or the service's binary when the alert has one, else the
    process image unless it is a common binary (then nothing, and why)."""
    for kind, path in _OBJECTS:
        value = _at(document, path)
        if kind == "sha256":
            value = value.lower() if value and _SHA256.fullmatch(value) else None
        else:
            value = _windows_text(value)
        if value and len(value) <= MAX_OBJECT_CHARS and not _altered(value):
            if kind == "process_image" and common_binary(value):
                return None, None, COMMON_BINARY
            return kind, value, None
    return None, None, None


def wazuh_alert_view(alert: Mapping[str, Any]) -> Optional[WazuhAlertView]:
    """The view of a Wazuh alert as the workflow holds it; ``None`` when the Wazuh normalizer did not build it."""
    if not isinstance(alert, Mapping) or alert.get("normalizer") != WAZUH:
        return None
    document = alert.get("raw")
    if not isinstance(document, Mapping) or "_omitted" in document:
        return WazuhAlertView()
    host = _at(document, ("agent", "name"))
    sshd = _at(document, ("decoder", "name")) == "sshd" or _at(document, ("decoder", "parent")) == "sshd"
    windows = isinstance(document.get("data"), Mapping) and isinstance(document["data"].get("win"), Mapping)
    family = "sshd" if sshd else "windows" if windows else None
    user = _at(document, ("data", "dstuser")) if sshd else _at(document, (*_ED, "targetUserName")) if windows else None
    source = _at(document, ("data", "srcip")) if sshd else _at(document, (*_ED, "ipAddress")) if windows else None
    kind, value, why_not = _object(document)
    rule = document.get("rule")
    rule_id = rule.get("id") if isinstance(rule, Mapping) else None
    return WazuhAlertView(
        rule_id=rule_id if isinstance(rule_id, str) and _RULE_ID.fullmatch(rule_id) else None,
        withheld=(("object_kind", why_not), ("object_value", why_not)) if why_not else (),
        host=host if host and _HOST.fullmatch(host) else None,
        user=user if user and _USER.fullmatch(user) and user != "-" else None,
        source_ip=_address(source),
        logon_family=family,
        object_kind=kind,
        object_value=value,
    )


VIEWS: Mapping[str, Callable[[Mapping[str, Any]], Optional[WazuhAlertView]]] = {WAZUH_ALERT_VIEW: wazuh_alert_view}
"""The registered view extractors, by the name a skill file gives in ``view``."""


def view_fields(name: str) -> FrozenSet[str]:
    """The fields a skill may bind from the view ``name`` (empty for a view that is not registered)."""
    return frozenset(f.name for f in fields(WazuhAlertView)) - {"withheld"} if name in VIEWS else frozenset()
