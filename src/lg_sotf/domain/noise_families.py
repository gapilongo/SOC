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
  when the canonical rule name is the one the Wazuh normalizer writes
  (``"<id>: <description>"``). A canonical alert without its raw event
  (dropped by the state size cap) has no detection rule, so it stays
  ``unmapped`` (fail closed).
* The actor can still choose **which** rule fires (writing a ``dpkg.log``
  line fires 2902). Each entry therefore records the abuse it could hide,
  and every family with a known abuse has a test that a malicious or
  suspicious model verdict still escalates it.

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
    "CATALOGUE",
    "CATALOGUE_VERSION",
    "WAZUH",
    "DetectionRule",
    "NoiseFamily",
    "detection_rule",
    "noise_family",
]

#: Bumped on every reviewed change to :data:`CATALOGUE`.
CATALOGUE_VERSION = "2026-11-09.1"
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
            "T1195 supply chain); the actor can also write a dpkg.log line to fire the rule."
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
            "tool installed for persistence (T1219)."
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
            "attack answered with 200) and repeated 4xx from one source (31151, level 10, high) are separate, "
            "mapped rules and are not catalogued. 5xx answers (31120-31123) are left out: a server error can be "
            "the side effect of an exploit attempt."
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


def _wazuh_rule(alert: Mapping[str, Any]) -> Optional[DetectionRule]:
    raw = alert.get("raw")
    rule = raw.get("rule") if isinstance(raw, Mapping) else None
    if not isinstance(rule, Mapping):
        return None
    rule_id = rule.get("id")
    if isinstance(rule_id, int) and not isinstance(rule_id, bool):
        rule_id = str(rule_id)
    if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id.strip()):
        return None
    rule_id = rule_id.strip()
    # What the Wazuh normalizer writes (``"<id>: <description>"``): the canonical alert was built from this event.
    rule_name = alert.get("rule_name")
    if not isinstance(rule_name, str) or not rule_name.startswith(f"{rule_id}: "):
        return None
    return DetectionRule(WAZUH, rule_id)


def detection_rule(alert: Any) -> Optional[DetectionRule]:
    """The vendor detection rule of a canonical alert with its raw event, or ``None`` when it is not known.

    Only Wazuh is recognised today: the rule id of the event (``raw.rule.id``,
    digits only), when the canonical rule name is the Wazuh normalizer's
    ``"<id>: <description>"``. Titles and descriptions are never read.
    """
    if not isinstance(alert, Mapping):
        return None
    return _wazuh_rule(alert)


def noise_family(alert: Any) -> Optional[NoiseFamily]:
    """The catalogued noise family of the alert's detection rule, or ``None``."""
    rule = detection_rule(alert)
    return None if rule is None else _INDEX.get(rule)
