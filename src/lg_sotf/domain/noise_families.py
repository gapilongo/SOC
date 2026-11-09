"""Catalogued routine-noise families (decision policy v2.1, FIX-2): vendor detection rules a model may close unmapped.

An alert whose detection rule maps it to no ATT&CK tactic or technique is a
never-close class (:data:`lg_sotf.domain.closure.UNMAPPED`): nothing shows
it is outside the dangerous classes. Some vendors ship their textbook
operational events without a mapping (a package installed, antivirus
signatures updated, a web client error), so ``unmapped`` alone would keep
routine noise in front of an analyst forever.

This catalogue lists, by **vendor and detection rule id**, the rules whose
meaning is known to be routine operational telemetry. A catalogued rule lifts
**only** the ``unmapped`` class; every other condition of a model-led close
still applies (the tenant tier, severity, both model tiers benign at the
install thresholds, no steering text, no recent true positive, no campaign).

What an entry is keyed on, and why:

* The rule id is chosen by the detection engine's ruleset (here the Wazuh
  manager), not written by the actor on the monitored host. The alert's
  title, description and rule name are never matched: a Wazuh rule
  description can interpolate event fields (``$(win.eventdata...)``), and a
  custom rule can copy a stock description word for word.
* The id is read from the vendor's own event (``raw.rule.id``), and only
  when the Wazuh normalizer built the alert: the ingestion service records
  the format on the alert (``normalizer``, never read from the event) and
  the canonical rule name is the one that normalizer writes
  (``"<id>: <description>"``). An alert from another format (a canonical
  or generic webhook push that copies a Wazuh document, an older alert
  stored before the format was recorded) or without its raw event (dropped
  by the state size cap) has no detection rule, so it stays ``unmapped``
  (fail closed).
* The actor can still choose **which** rule fires, often without
  privileges: any local user can write a syslog line (``logger -t yum
  Installed: x`` fires 2932) and a per-user MSI install produces 60612
  without admin rights. Each entry therefore records the abuse it could
  hide, and every family with a known abuse has a test that a malicious or
  suspicious model verdict still escalates it. A forged repeat can also be
  a decoy; while it waits for an analyst it blocks other model closes on
  the same entities (FIX-1's campaign check).

The module also holds the vendor facts that put an alert **into** a
never-close class whatever its ATT&CK mapping (:func:`vendor_never_close_class`):
Wazuh maps many authentication-failure rules outside credential access
(Windows logon failures 60122-60130 to T1531, a failed logon from a malicious
IP to T1078, "possible replay attack" to T1550), so the rule's own groups
(``authentication_failed``, ``authentication_failures``, ``invalid_login``,
``login_denied``) and a short list of rule ids without those groups make
it credential access. These checks only ever block a close, so they read
the raw event whatever format built the alert; a Wazuh-built alert whose
rule cannot be read at all is ``vendor_unknown`` and never closes.

Changing the catalogue is a reviewed change to the decision policy: bump
:data:`CATALOGUE_VERSION`, justify the entry from the vendor ruleset's
semantics (never from which evaluation items are labelled benign) and add
the abuse test when the family can hide one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Mapping, NamedTuple, Optional, Tuple

__all__ = [
    "AUTH_FAILURE_GROUPS",
    "CATALOGUE",
    "NEVER_CLOSE_RULE_IDS",
    "VENDOR_UNKNOWN",
    "CATALOGUE_VERSION",
    "WAZUH",
    "DetectionRule",
    "NoiseFamily",
    "detection_rule",
    "noise_family",
    "vendor_never_close_class",
]

#: Bumped on every reviewed change to :data:`CATALOGUE`.
CATALOGUE_VERSION = "2026-11-09.2"
WAZUH = "wazuh"
_RULE_ID = re.compile(r"^[0-9]{1,7}$")


class DetectionRule(NamedTuple):
    """The vendor detection rule that raised an alert."""

    vendor: str
    rule_id: str


@dataclass(frozen=True)
class NoiseFamily:
    """A family of vendor rules whose meaning is routine operational telemetry."""

    family: str
    vendor: str
    rule_ids: FrozenSet[str]
    #: Why the rule's meaning is routine: what it reports and why that reports no attack.
    rationale: str
    #: The attack the family could hide, or ``"none known"``.
    could_hide: str
    #: Whether :attr:`could_hide` names a known abuse (it then needs an escalation test).
    abuse_known: bool


CATALOGUE: Tuple[NoiseFamily, ...] = (
    NoiseFamily(
        family="linux_package_install",
        vendor=WAZUH,
        # 2901 dpkg "requested to install", 2902 dpkg "installed", 2932 yum "New Yum package installed",
        # 2933 yum "Yum package updated" (stock rules of the dpkg and yum decoders, levels 3 to 7).
        rule_ids=frozenset({"2901", "2902", "2932", "2933"}),
        rationale=(
            "The package manager's own log of an install or update: patching and provisioning produce these "
            "on every host, in bursts. Removals (dpkg 2903, yum 2934) are left out: removing a security agent "
            "or audit package is defense impairment (T1562.001)."
        ),
        could_hide=(
            "A malicious or backdoored package installed by an actor with root (T1546.016 installer packages, "
            "T1195 supply chain). Any local user can also fire these rules with a forged syslog line ("
            "`logger -t yum`, and likely dpkg lines through syslog): a decoy, or a flood of repeats."
        ),
        abuse_known=True,
    ),
    NoiseFamily(
        family="windows_software_install",
        vendor=WAZUH,
        # 60612 "Application installed": the Windows Installer (MsiInstaller) reports a completed product install.
        rule_ids=frozenset({"60612"}),
        rationale=(
            "Windows Installer's record of a completed product install; software deployment and self-updating "
            "applications produce these daily. The product name in the description is event data and is never "
            "read."
        ),
        could_hide=(
            "Software install as execution: a malicious MSI run through msiexec (T1218.007) or a remote-access "
            "tool installed for persistence (T1219). A per-user MSI install fires the rule without admin rights."
        ),
        abuse_known=True,
    ),
    NoiseFamily(
        family="antivirus_status",
        vendor=WAZUH,
        # 62107 "Antimalware scan started", 62108 "Antimalware scan finished",
        # 62130 "Antimalware definitions updated successfully" (Windows Defender operational rules).
        rule_ids=frozenset({"62107", "62108", "62130"}),
        rationale=(
            "Microsoft Defender's scheduled scans and signature updates: health telemetry that reports no "
            "finding. A detection is a different Defender event and rule (malware or potentially unwanted "
            "software found, action taken or failed), never one of these. Definition rollbacks, failed updates "
            "and protection being turned off are different rules and are not catalogued."
        ),
        could_hide="None known: a started, finished or updated scan engine gives an actor nothing.",
        abuse_known=False,
    ),
    NoiseFamily(
        family="web_client_error",
        vendor=WAZUH,
        # 31101 "Web server 400 error code." (web access-log rules); 31102 is the level-0 ignored-files variant.
        rule_ids=frozenset({"31101"}),
        rationale=(
            "A single 4xx answer in a web access log: broken links, crawlers and expired sessions produce these "
            "constantly. Attack signatures in the same access log (SQL injection, XSS, common web attacks, an "
            "attack answered with 200) and repeated 4xx from one source (31151, level 10, which maps to medium) "
            "are separate rules and are not catalogued. 5xx answers (31120-31123) are left out: a server error can "
            "be the side effect of an exploit attempt."
        ),
        could_hide=(
            "Probing or a failed exploit attempt that matched no attack signature (T1595 active scanning, T1190)."
        ),
        abuse_known=True,
    ),
)

_INDEX: Dict[DetectionRule, NoiseFamily] = {
    DetectionRule(entry.vendor, rule_id): entry for entry in CATALOGUE for rule_id in entry.rule_ids
}


#: Wazuh rule groups of authentication failures: credential access whatever ATT&CK id the rule carries.
AUTH_FAILURE_GROUPS: FrozenSet[str] = frozenset(
    {"authentication_failed", "authentication_failures", "invalid_login", "login_denied"}
)
#: Wazuh rules that report authentication failures without one of :data:`AUTH_FAILURE_GROUPS`.
NEVER_CLOSE_RULE_IDS: Mapping[str, str] = {
    "6250": "credential_access",  # Asterisk: multiple failed logins
    "44733": "credential_access",  # FortiAuthenticator: authentication failed
}
MAX_RULE_GROUPS = 50
#: The class of a Wazuh-built alert whose vendor rule cannot be read: its groups are unknown, so it never closes.
VENDOR_UNKNOWN = "vendor_unknown"


def _raw_rule(alert: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    raw = alert.get("raw")
    rule = raw.get("rule") if isinstance(raw, Mapping) else None
    return rule if isinstance(rule, Mapping) else None


def _rule_id(rule: Mapping[str, Any]) -> Optional[str]:
    rule_id = rule.get("id")
    if isinstance(rule_id, int) and not isinstance(rule_id, bool):
        rule_id = str(rule_id)
    if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id.strip()):
        return None
    return rule_id.strip()


def detection_rule(alert: Any) -> Optional[DetectionRule]:
    """The vendor detection rule of a canonical alert with its raw event, or ``None`` when it is not known.

    Only Wazuh is recognised today: the rule id of the event (``raw.rule.id``,
    digits only), when the Wazuh normalizer built the alert (``normalizer``
    is ``wazuh``, recorded by the ingestion service) and the canonical rule
    name is that normalizer's ``"<id>: <description>"``. Titles and
    descriptions are never read.
    """
    if not isinstance(alert, Mapping) or alert.get("normalizer") != WAZUH:
        return None
    rule = _raw_rule(alert)
    rule_id = _rule_id(rule) if rule is not None else None
    rule_name = alert.get("rule_name")
    if rule_id is None or not isinstance(rule_name, str) or not rule_name.startswith(f"{rule_id}: "):
        return None
    return DetectionRule(WAZUH, rule_id)


def noise_family(alert: Any) -> Optional[NoiseFamily]:
    """The catalogued noise family of the alert's detection rule, or ``None``."""
    rule = detection_rule(alert)
    return None if rule is None else _INDEX.get(rule)


def vendor_never_close_class(alert: Any) -> Optional[str]:
    """The never-close class the vendor's own rule puts the alert in, whatever its ATT&CK mapping, or ``None``.

    ``credential_access`` for a Wazuh rule in an authentication-failure group
    (:data:`AUTH_FAILURE_GROUPS`) or in :data:`NEVER_CLOSE_RULE_IDS`. These
    checks only block, so they read the raw event whatever format built the
    alert. The state size cap always keeps ``raw.rule``
    (:func:`lg_sotf.core.graph.cap_alert`); a Wazuh-built alert whose rule
    still cannot be read, or whose groups list the cap cut (``groups_truncated``)
    without an authentication-failure group in what it kept, is
    :data:`VENDOR_UNKNOWN`, a never-close class.
    """
    if not isinstance(alert, Mapping):
        return None
    rule = _raw_rule(alert)
    if rule is None:
        # A Wazuh alert whose rule cannot be read (the raw event is gone): its groups are unknown, so it may be an
        # authentication failure mapped elsewhere. Fail closed; this also blocks the catalogue lift.
        return VENDOR_UNKNOWN if alert.get("normalizer") == WAZUH else None
    groups = rule.get("groups")
    if isinstance(groups, list):
        names = {g.strip().lower() for g in groups[:MAX_RULE_GROUPS] if isinstance(g, str)}
        if names & AUTH_FAILURE_GROUPS:
            return "credential_access"
    if rule.get("groups_truncated") is True:
        return VENDOR_UNKNOWN  # the state cap cut the groups: an authentication-failure group may be among the rest
    rule_id = _rule_id(rule)
    return NEVER_CLOSE_RULE_IDS.get(rule_id) if rule_id is not None else None
