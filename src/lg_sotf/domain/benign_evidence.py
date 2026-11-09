"""False-positive evidence an attacker cannot write (AI-E6.3, title camouflage).

A false-positive signal can close a low or medium alert without a model, so
it must come from something the attacker does not choose. The alert title
does not qualify: integrations and detectors build it from the names of the
objects involved ("Scheduled task created: Windows Update Test", "New service
installed: Scheduled Backup Maintenance"), and the attacker names those
objects. Any word in a title may be one the attacker typed.

Triage therefore takes false-positive evidence only from:

* **the detection rule's name** (:func:`detector_words`): the identifier the
  detection engineer or vendor gave the rule (``ups-test``,
  ``CERT-ROTATION-TEST``, a Splunk search name, a Wazuh rule description).
  Some products render values into rule names (Wazuh ``$(field)``, Sentinel
  alert-detail overrides), so before matching, quoted spans and every value
  the alert names as an entity or as an attacker-named raw field (task,
  service, process and file names, command lines, user agents, email
  subjects) are removed from the name. Whatever is left is detector text;
* **content the attacker cannot forge**: every file hash of the alert is a
  hash of the EICAR anti-virus test file (:func:`eicar_only`);
* **configuration**: a host or address the tenant lists as its own
  vulnerability scanner (``triage.known_scanners``, :class:`KnownScanners`)
  is the *source* of the activity: it appears in one of the event's
  structured source fields (:data:`SOURCE_FIELDS`: ``srcip``, ``src_ip``,
  ``source_ip``, Windows logon source address or workstation, ...). A
  scanner that is the host or address the activity reached (the victim, a
  destination, the agent that saw it) is no benign evidence: an attack on
  the scanner is still an attack;
* **source metadata**: the environment tag of the configured source id (in
  :mod:`lg_sotf.agents.triage.base`).

This is an allow list: text not known to be the detector's never counts, so
a new integration that copies object names into the title cannot reopen the
gap. True-positive evidence may still come from attacker-written fields: an
attacker gains nothing by making an alert look worse.

Not every benign word of a rule name states benign intent (AI-E6.4).
``test``, ``selftest``, ``maintenance`` and ``health_check`` do: the detection
engineer wrote the rule for a test, a maintenance window or a health check.
``scheduled``, ``update``, ``backup``, ``scan`` and ``monitoring`` name the
*activity* the rule detects, and attackers do the same things:
``scheduled-task-created`` is persistence (ATT&CK T1053), ``Windows Defender
real time monitoring was disabled`` is defence evasion (T1562.001), deleting
scheduled backups inhibits recovery (T1490). :func:`rule_name_keywords` therefore
counts an activity word only with a trusted qualifier: an intent word in the
same rule name (``Scheduled maintenance: package update installed``), a
test-environment source id, or, for ``scan``, one of the tenant's known
scanners as the source of the activity.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import Annotated, Any, Dict, FrozenSet, Iterable, List, Mapping, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator

__all__ = [
    "ACTIVITY_KEYWORDS",
    "EICAR_HASHES",
    "EICAR_MD5",
    "EICAR_SHA1",
    "EICAR_SHA256",
    "INJECTION_SIGNAL",
    "KnownScanners",
    "RULE_NAME_KEYWORDS",
    "SOURCE_FIELDS",
    "TriageSettings",
    "attacker_values",
    "detector_words",
    "eicar_only",
    "rule_name_keywords",
    "source_values",
    "validate_triage_settings",
]

#: The true-positive signal triage adds when alert text addresses a language model (steering text). It voids the
#: false-positive evidence taken from text, and a model never closes an alert that carries it.
INJECTION_SIGNAL = "prompt_injection_suspected"
#: Benign words of a detection rule's name (matched against :func:`detector_words`), in reporting order.
RULE_NAME_KEYWORDS = (
    "test", "testing", "selftest", "scheduled", "maintenance", "update", "backup", "scan", "health_check", "monitoring",
)
#: Words that name the detected activity, not benign intent: they count only with a trusted qualifier.
ACTIVITY_KEYWORDS = frozenset({"scheduled", "update", "backup", "scan", "monitoring"})
#: Activity words a configured scanner among the alert's entities also qualifies (``triage.known_scanners``).
SCANNER_ACTIVITY = frozenset({"scan"})

# Hashes of the 68-byte EICAR anti-virus test file (https://www.eicar.org).
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_HASHES = frozenset({EICAR_MD5, EICAR_SHA1, EICAR_SHA256})

MAX_RULE_NAME_CHARS = 300
MAX_MASKED_VALUES = 200
MIN_MASKED_CHARS = 3
MAX_SCANNERS = 256
#: Raw event fields (lower case) whose values an attacker names: tasks, services, files, processes, agents, subjects.
ATTACKER_NAMED_RAW_FIELDS = frozenset(
    {
        "task_name", "taskname", "service_name", "servicename", "file_name", "filename", "file_path",
        "target_filename", "process_name", "image", "parent_process", "parent_image", "command_line",
        "commandline", "cmdline", "parent_command_line", "user_agent", "useragent", "http_user_agent",
        "subject", "email_subject",
    }
)
# Quoted spans in a rule name are rendered values ('Windows Update Test'), never the rule's own words.
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"|`[^`]*`|\u2018[^\u2019]*\u2019|\u201c[^\u201d]*\u201d")
# Split on anything but letters, digits, dots and backslashes: "maintenance.exe" and "c:\\test" stay whole
# (a file name is never a word of the rule), "ups-test" and "CERT_ROTATION_TEST" split.
_SEPARATORS = re.compile(r"[^a-z0-9.\\]+")


def _fold(text: str) -> str:
    """NFKC, case-folded, without format characters (zero-width joiners cannot hide a span from masking)."""
    normalised = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in normalised if unicodedata.category(ch) != "Cf").casefold()


def _scalars(value: Any, limit: int) -> Iterable[str]:
    items = value if isinstance(value, (list, tuple)) else [value]
    for item in list(items)[:limit]:
        if isinstance(item, Mapping):
            item = item.get("name", item.get("value", item.get("id")))
        if isinstance(item, str) and item:
            yield item


def _raw(alert: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = alert.get("raw")
    if isinstance(raw, Mapping):
        nested = raw.get("raw_data")
        return nested if isinstance(nested, Mapping) else raw
    return {}


def attacker_values(alert: Mapping[str, Any]) -> List[str]:
    """Values the alert itself marks as attacker-chosen: every entity, and the attacker-named raw fields."""
    values: List[str] = []
    entities = alert.get("entities")
    if isinstance(entities, Mapping):
        for kind in sorted(str(k) for k in entities):
            values.extend(_scalars(entities.get(kind), MAX_MASKED_VALUES))
    for key, value in _raw(alert).items():
        if isinstance(key, str) and key.lower() in ATTACKER_NAMED_RAW_FIELDS:
            values.extend(_scalars(value, MAX_MASKED_VALUES))
    return values[:MAX_MASKED_VALUES]


def detector_words(rule_name: Any, masked: Iterable[str] = ()) -> FrozenSet[str]:
    """Words of a detection rule name, without quoted spans or any of the ``masked`` values.

    Adjacent words are also joined with ``_`` (``health-check`` gives
    ``health_check``), so multi-word keywords match whatever the separator.
    """
    if not isinstance(rule_name, str) or not rule_name:
        return frozenset()
    text = _QUOTED.sub(" ", _fold(rule_name[:MAX_RULE_NAME_CHARS]))
    # Longest first, so a value that contains another is removed whole.
    for value in sorted({_fold(v) for v in masked}, key=len, reverse=True):
        if len(value) >= MIN_MASKED_CHARS:
            text = text.replace(value, " ")
    tokens = [t.strip(".") for t in _SEPARATORS.split(text)]
    tokens = [t for t in tokens if t]
    return frozenset(tokens) | frozenset(f"{a}_{b}" for a, b in zip(tokens, tokens[1:], strict=False))


def rule_name_keywords(
    words: FrozenSet[str], *, test_environment: bool = False, known_scanner: bool = False
) -> List[str]:
    """The benign keywords among a rule name's ``words`` that count as evidence, in :data:`RULE_NAME_KEYWORDS` order.

    An intent word always counts. An activity word (:data:`ACTIVITY_KEYWORDS`)
    counts only with a trusted qualifier: an intent word in the same rule
    name, a test-environment source (``test_environment``) or, for ``scan``,
    a configured scanner as the source of the activity (``known_scanner``).
    """
    present = [k for k in RULE_NAME_KEYWORDS if k in words]
    qualified = test_environment or any(k not in ACTIVITY_KEYWORDS for k in present)
    return [
        k for k in present
        if k not in ACTIVITY_KEYWORDS or qualified or (known_scanner and k in SCANNER_ACTIVITY)
    ]


def _hashes(alert: Mapping[str, Any]) -> List[str]:
    found: List[str] = []
    entities = alert.get("entities")
    if isinstance(entities, Mapping):
        found.extend(_scalars(entities.get("hashes"), MAX_MASKED_VALUES))
    found.extend(_scalars(_raw(alert).get("file_hash"), MAX_MASKED_VALUES))
    return [h.strip().lower() for h in found]


def eicar_only(alert: Mapping[str, Any]) -> bool:
    """The alert names at least one file hash, and every one is a hash of the EICAR test file."""
    hashes = _hashes(alert)
    return bool(hashes) and all(h in EICAR_HASHES for h in hashes)


# --------------------------------------------------------------------------- known scanners

ScannerId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)]
_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}))*\.?$")
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _scanner_id(value: str) -> str:
    """A host name (lower case, no trailing dot), an IP address or a CIDR range; raises ``ValueError``."""
    text = value.strip().lower()
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        pass
    if not _HOST.match(text):
        raise ValueError(f"not a host name, IP address or CIDR range: {value[:64]!r}")
    return text.rstrip(".")


class TriageSettings(BaseModel):
    """Schema of ``tenants.settings["triage"]``.

    ``known_scanners``: host names, IP addresses or CIDR ranges of the
    tenant's own vulnerability scanners. An alert whose activity comes from one
    gets the ``known_scanner`` false-positive signal.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    known_scanners: List[ScannerId] = Field(default_factory=list, max_length=MAX_SCANNERS)

    @field_validator("known_scanners")
    @classmethod
    def _normalise(cls, values: List[str]) -> List[str]:
        return list(dict.fromkeys(_scanner_id(v) for v in values))


def validate_triage_settings(value: Any) -> Dict[str, Any]:
    """Normalised settings for the tenant settings API; raises ``ValueError`` listing the problems."""
    if not isinstance(value, Mapping):
        raise ValueError("triage: must be an object")
    try:
        return TriageSettings.model_validate(dict(value)).model_dump()
    except ValidationError as exc:
        problems = [f"triage.{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"[:200] for e in exc.errors()[:5]]
        raise ValueError("; ".join(problems)) from exc


def _ip(value: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address, None]:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


@dataclass(frozen=True)
class KnownScanners:
    """The tenant's configured scanners, parsed fail-closed (unreadable entries are ignored)."""

    hosts: FrozenSet[str] = frozenset()
    networks: Tuple[Network, ...] = ()

    @classmethod
    def from_settings(cls, tenant_settings: Mapping[str, Any]) -> KnownScanners:
        section = tenant_settings.get("triage") if isinstance(tenant_settings, Mapping) else None
        entries = section.get("known_scanners") if isinstance(section, Mapping) else None
        hosts: List[str] = []
        networks: List[Network] = []
        for entry in entries[:MAX_SCANNERS] if isinstance(entries, list) else []:
            try:
                normalised = _scanner_id(entry) if isinstance(entry, str) else None
            except ValueError:
                normalised = None
            if normalised is None:
                continue
            try:
                networks.append(ipaddress.ip_network(normalised))
            except ValueError:
                hosts.append(normalised)
        return cls(frozenset(hosts), tuple(networks))

    def __bool__(self) -> bool:
        return bool(self.hosts or self.networks)

    def matches(self, alert: Mapping[str, Any]) -> bool:
        """Whether a configured scanner is the source of the activity (:func:`source_values`); a scanner that is
        only a host or address entity (the victim, a destination, the agent) never matches."""
        if not self:
            return False
        for value in source_values(alert):
            if value.strip().lower().rstrip(".") in self.hosts:
                return True
            address = _ip(value)
            if address is not None and any(address in network for network in self.networks):
                return True
        return False


#: Paths in the raw event of the fields that name where the activity came from (an address or a host), across the
#: normalised vendors: generic and Splunk CIM names, Wazuh decoders, Windows logon events, AWS, webhook ``network``.
SOURCE_FIELDS: Tuple[Tuple[str, ...], ...] = (
    ("srcip",), ("src_ip",), ("source_ip",), ("sourceip",), ("src",), ("src_host",), ("source_host",), ("client_ip",),
    ("data", "srcip"), ("data", "src_ip"), ("data", "aws", "sourceIPAddress"),
    ("data", "win", "eventdata", "ipAddress"), ("data", "win", "eventdata", "sourceIp"),
    ("data", "win", "eventdata", "workstationName"), ("network", "src"),
)


def source_values(alert: Mapping[str, Any]) -> List[str]:
    """The values of the raw event's source fields (:data:`SOURCE_FIELDS`): where the activity came from."""
    raw = _raw(alert)
    found: List[str] = []
    for path in SOURCE_FIELDS:
        value: Any = raw
        for key in path:
            value = value.get(key) if isinstance(value, Mapping) else None
        found.extend(_scalars(value, MAX_MASKED_VALUES))
    return found[:MAX_MASKED_VALUES]
