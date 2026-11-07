"""Phishing signals for email alerts: pure functions over the alert's email section and a tenant profile.

Triage (:mod:`lg_sotf.agents.triage.base`) turns these into rule indicators
and score weights; analysis (:mod:`lg_sotf.agents.analysis.base`) reads the
strong ones back from the triage digest as corroborating evidence. The
signals are facts the platform derived itself: authentication verdicts
written by the receiving mail servers, the structure of the message (link
targets, attachment content) and comparisons with the tenant's own domains,
brands and executives. The message's words are only ever a weak signal.

True-positive signals (``rule_tp``):

``email_dmarc_fail`` / ``email_spf_fail`` / ``email_dkim_fail``
    the trusted Authentication-Results header reports a failure
``email_reply_to_mismatch``      Reply-To on another site than From
``email_return_path_mismatch``   bounce address on another site (weak: bulk senders do this)
``email_display_name_impersonation``  an external sender whose display name shows another
    address, an internal domain, a configured executive or a protected brand
``email_lookalike_domain``       a sender, reply or link domain imitating an internal domain or
    protected brand: homoglyphs (also in punycode), one or two edits, the same name under
    another suffix, or the name embedded in another domain
``email_link_text_mismatch``     link text shows one domain, the link goes to another
``email_url_shortener`` / ``email_ip_url``
``email_risky_attachment``       see :mod:`lg_sotf.ingestion.email.attachments`
``email_credential_wording``     credential-harvest or urgency phrases (weak)

False-positive signal (``rule_fp``): ``email_internal_sender_authenticated``
- the sender is in the tenant's internal domains and SPF, DKIM and DMARC all
pass in the trusted Authentication-Results header, and none of the strong
signals is present. It never closes an alert by itself: the existing routing
rules (rule corroboration of a benign model verdict, low/medium severity
only) still apply.

Which Authentication-Results header is trusted: the first one whose
``authserv-id`` is in the tenant's ``phishing.trusted_authserv_ids`` when that
list is set (recommended: headers below it can be forged by the sender),
otherwise the topmost header.

Links are the URLs the message leads to. A URL only shown as the text of a
link that goes elsewhere (``display_only`` in the section, see
:mod:`lg_sotf.ingestion.email.parser`) is not one: the deceiving link it
belongs to carries ``email_link_text_mismatch``, and the shown URL is often
the legitimate site the sender imitates. It never feeds a link or lookalike
signal, corroboration or a response target.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from lg_sotf.domain.urls import ascii_host, site, site_label, unicode_host

if TYPE_CHECKING:
    from lg_sotf.core.state import PhishingDigest

DMARC_FAIL = "email_dmarc_fail"
SPF_FAIL = "email_spf_fail"
DKIM_FAIL = "email_dkim_fail"
REPLY_TO_MISMATCH = "email_reply_to_mismatch"
RETURN_PATH_MISMATCH = "email_return_path_mismatch"
DISPLAY_NAME_IMPERSONATION = "email_display_name_impersonation"
LOOKALIKE_DOMAIN = "email_lookalike_domain"
LINK_TEXT_MISMATCH = "email_link_text_mismatch"
URL_SHORTENER = "email_url_shortener"
IP_URL = "email_ip_url"
RISKY_ATTACHMENT = "email_risky_attachment"
CREDENTIAL_WORDING = "email_credential_wording"
INTERNAL_AUTHENTICATED = "email_internal_sender_authenticated"

# Triage rule-score weights (added to the rules score; the benign signal subtracts).
TRIAGE_WEIGHTS: Dict[str, int] = {
    DMARC_FAIL: 15,
    SPF_FAIL: 5,
    DKIM_FAIL: 5,
    REPLY_TO_MISMATCH: 10,
    RETURN_PATH_MISMATCH: 3,
    DISPLAY_NAME_IMPERSONATION: 20,
    LOOKALIKE_DOMAIN: 25,
    LINK_TEXT_MISMATCH: 15,
    URL_SHORTENER: 5,
    IP_URL: 10,
    RISKY_ATTACHMENT: 25,
    CREDENTIAL_WORDING: 5,
    INTERNAL_AUTHENTICATED: -20,
}
# Strong signals: evidence that can corroborate an automatic response (weight 1 each; two are needed).
EVIDENCE_SIGNALS: FrozenSet[str] = frozenset(
    {DMARC_FAIL, DISPLAY_NAME_IMPERSONATION, LOOKALIKE_DOMAIN, LINK_TEXT_MISMATCH, IP_URL, RISKY_ATTACHMENT}
)
TP_SIGNALS: FrozenSet[str] = frozenset(k for k, v in TRIAGE_WEIGHTS.items() if v > 0)
FP_SIGNALS: FrozenSet[str] = frozenset({INTERNAL_AUTHENTICATED})
# Extra rule-threat reduction in analysis for the benign signal (on top of the per-FP-signal reduction).
ANALYSIS_BENIGN_ADJUSTMENT = -15

MAX_BRANDS = 200
MAX_EXECUTIVES = 500
MAX_AUTHSERV_IDS = 20
MAX_REFERENCES = 400
MAX_CANDIDATE_HOSTS = 30
MAX_DETAILS = 5
MIN_REFERENCE_LABEL = 4
MIN_EDIT_LABEL = 5
_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+)")
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
# Latin look-alikes from Cyrillic and Greek, plus digits and letter pairs read as letters.
# ``str.translate`` makes one pass, so every member of a confusable class must map to the same
# target: ASCII ``i`` folds to ``l``, so the Unicode i-lookalikes must fold to ``l`` too.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l", "ј": "j", "ԁ": "d",
        "ɡ": "g", "ո": "n", "ѕ": "s", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ʏ": "y", "ο": "o", "α": "a",
        "ν": "v", "ρ": "p", "τ": "t", "ι": "l", "κ": "k", "ε": "e", "υ": "u", "χ": "x", "ɑ": "a", "ı": "l",
        "0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "7": "t", "8": "b",
    }
)

BrandName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)]
ExecutiveName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
AuthservId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


class PhishingSettings(BaseModel):
    """Schema of ``tenants.settings["phishing"]``.

    ``protected_brands``: brand names (``Example Bank``) or domains
    (``examplebank.example``) that lookalike and display-name checks protect;
    ``executives``: display names of people attackers impersonate;
    ``trusted_authserv_ids``: ``authserv-id`` values of your own receiving
    mail servers (see the module docs).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    protected_brands: List[BrandName] = Field(default_factory=list, max_length=MAX_BRANDS)
    executives: List[ExecutiveName] = Field(default_factory=list, max_length=MAX_EXECUTIVES)
    trusted_authserv_ids: List[AuthservId] = Field(default_factory=list, max_length=MAX_AUTHSERV_IDS)


def validate_phishing_settings(value: Any) -> Dict[str, Any]:
    """Normalised settings for the tenant settings API; raises ``ValueError`` listing the problems."""
    if not isinstance(value, Mapping):
        raise ValueError("phishing: must be an object")
    try:
        return PhishingSettings.model_validate(dict(value)).model_dump()
    except ValidationError as exc:
        problems = [
            f"phishing.{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"[:200] for e in exc.errors()[:5]
        ]
        raise ValueError("; ".join(problems)) from exc


# --------------------------------------------------------------------------- profile


def _domains(values: Any) -> List[str]:
    out: List[str] = []
    for value in values if isinstance(values, (list, tuple)) else []:
        if isinstance(value, str) and value.strip():
            name = value.strip().lstrip("*.").rstrip(".").lower()
            out.append(ascii_host(name))
    return out


def fold(text: str) -> str:
    """NFKC, case-folded, look-alike characters mapped to ASCII letters (the comparison skeleton)."""
    normalised = unicodedata.normalize("NFKC", text).casefold()
    stripped = "".join(ch for ch in normalised if unicodedata.category(ch) not in ("Cf", "Mn"))
    return stripped.translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w")


def _name_tokens(text: str) -> Tuple[str, ...]:
    folded = unicodedata.normalize("NFKC", text).casefold()
    return tuple(t for t in _TOKEN_SPLIT.split(folded) if t)


def _compact(text: str) -> str:
    return "".join(_name_tokens(text))


@dataclass(frozen=True)
class Brand:
    label: str
    sites: FrozenSet[str]


@dataclass(frozen=True)
class PhishingProfile:
    """The tenant context the signals compare against (see :meth:`from_settings`)."""

    internal_domains: Tuple[str, ...] = ()
    brands: Tuple[Brand, ...] = ()
    executives: Tuple[Tuple[str, ...], ...] = ()
    trusted_authserv_ids: FrozenSet[str] = frozenset()

    @classmethod
    def from_settings(
        cls, tenant_settings: Mapping[str, Any], install_tools: Optional[Mapping[str, Any]] = None
    ) -> PhishingProfile:
        """Internal domains from ``tools.internal_domains`` (tenant and install); the ``phishing`` section.

        A malformed ``phishing`` section is ignored (the settings API rejects
        it on write): brands, executives and trusted ids are then empty, which
        only removes signals and the benign signal's trusted-header choice
        falls back to the topmost header.
        """
        tools = tenant_settings.get("tools") if isinstance(tenant_settings.get("tools"), Mapping) else {}
        internal = _domains((tools or {}).get("internal_domains")) + _domains((install_tools or {}).get("internal_domains"))
        try:
            parsed = PhishingSettings.model_validate(dict(tenant_settings.get("phishing") or {}))
        except (ValidationError, TypeError, ValueError):
            parsed = PhishingSettings()
        by_label: Dict[str, set[str]] = {}
        for entry in parsed.protected_brands:
            text = entry.strip().lower()
            if "." in text and " " not in text:
                host = ascii_host(text.lstrip("*.").rstrip("."))
                by_label.setdefault(site_label(host), set()).add(site(host))
            else:
                label = _compact(text)
                if label:
                    by_label.setdefault(label, set())
        executives = tuple(dict.fromkeys(t for t in (_name_tokens(e) for e in parsed.executives) if t))
        return cls(
            internal_domains=tuple(dict.fromkeys(internal)),
            brands=tuple(Brand(label, frozenset(sites)) for label, sites in by_label.items() if label),
            executives=executives,
            trusted_authserv_ids=frozenset(a.lower() for a in parsed.trusted_authserv_ids),
        )

    def is_internal(self, domain: Optional[str]) -> bool:
        if not domain:
            return False
        host = ascii_host(domain.rstrip(".").lower())
        return any(host == d or host.endswith("." + d) for d in self.internal_domains)

    def references(self) -> List[Tuple[str, FrozenSet[str], str]]:
        """(label, legitimate sites, name) of every domain and brand lookalikes are compared with."""
        refs: List[Tuple[str, FrozenSet[str], str]] = []
        for domain in self.internal_domains:
            refs.append((site_label(domain), frozenset({site(domain)}), domain))
        for brand in self.brands:
            refs.append((brand.label, brand.sites, brand.label))
        return [r for r in refs if len(r[0]) >= MIN_REFERENCE_LABEL][:MAX_REFERENCES]


# --------------------------------------------------------------------------- helpers


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else []


def _domain_of(address: Any) -> Optional[str]:
    if isinstance(address, str) and "@" in address:
        return address.rsplit("@", 1)[1].lower() or None
    return None


def effective_auth(section: Mapping[str, Any], profile: PhishingProfile) -> Mapping[str, Any]:
    """The Authentication-Results entry the signals trust (see the module docs); empty when none qualifies."""
    results = [_mapping(r) for r in _list(section.get("auth"))]
    if profile.trusted_authserv_ids:
        for result in results:
            if str(result.get("authserv_id") or "").lower() in profile.trusted_authserv_ids:
                return result
        return {}
    return results[0] if results else {}


def damerau_levenshtein(a: str, b: str, limit: int) -> int:
    """Optimal string alignment distance, or ``limit + 1`` as soon as it must exceed ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous2: List[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                current[j] = min(current[j], previous2[j - 2] + 1)
        if min(current) > limit:
            return limit + 1
        previous2, previous = previous, current
    return previous[-1]


def lookalike(host: str, profile: PhishingProfile, refs: Sequence[Tuple[str, FrozenSet[str], str]]) -> Optional[str]:
    """The internal domain or brand ``host`` imitates, with the technique, or ``None``."""
    host_ascii = ascii_host(host.rstrip(".").lower())
    host_site = site(host_ascii)
    if not host_site or "." not in host_site or profile.is_internal(host_ascii):
        return None
    if any(host_site in sites for _, sites, _ in refs):
        return None
    label = site_label(host_ascii)
    shown = fold(unicode_host(label))
    tokens = set(_TOKEN_SPLIT.split(host_ascii))
    for ref_label, _, name in refs:
        if label == ref_label:
            return f"{host_site} uses the name of {name} under another domain"
        if shown == fold(ref_label):
            return f"{host_site} spells {name} with look-alike characters"
        if len(ref_label) >= MIN_EDIT_LABEL:
            allowed = 1 if len(ref_label) < 9 else 2
            if damerau_levenshtein(label, ref_label, allowed) <= allowed:
                return f"{host_site} is {name} with a typo"
            if ref_label in tokens:
                return f"{host_site} embeds the name {name}"
    return None


def _impersonation(section: Mapping[str, Any], profile: PhishingProfile) -> Optional[str]:
    sender = _mapping(section.get("from"))
    display = str(sender.get("display_name") or "")
    domain = str(sender.get("domain") or _domain_of(sender.get("address")) or "")
    if not display or profile.is_internal(domain):
        return None
    for match in _EMAIL_IN_TEXT.finditer(display):
        shown = match.group(1).lower()
        if not domain or site(shown) != site(domain):
            return "the display name shows another sender address"
    lowered = display.lower()
    for internal in profile.internal_domains:
        if internal in lowered:
            return f"the display name names the internal domain {internal}"
    tokens = set(_name_tokens(display))
    for executive in profile.executives:
        if (len(executive) >= 2 and set(executive) <= tokens) or (len(executive) == 1 and tokens == set(executive)):
            return "the display name matches a protected executive"
    compact = _compact(display)
    sender_site = site(domain) if domain else ""
    for brand in profile.brands:
        if len(brand.label) >= MIN_REFERENCE_LABEL and brand.label in compact and sender_site not in brand.sites:
            return f"the display name uses the brand {brand.label}"
    return None


# --------------------------------------------------------------------------- assessment


@dataclass
class PhishingAssessment:
    tp: List[str] = field(default_factory=list)
    fp: List[str] = field(default_factory=list)
    sender_authenticated: bool = False
    lookalikes: List[str] = field(default_factory=list)
    lookalike_hosts: List[str] = field(default_factory=list)
    impersonation: Optional[str] = None
    suspicious_urls: List[str] = field(default_factory=list)

    @property
    def weight(self) -> int:
        return sum(TRIAGE_WEIGHTS.get(s, 0) for s in (*self.tp, *self.fp))

    @property
    def benign_weight(self) -> int:
        return sum(TRIAGE_WEIGHTS.get(s, 0) for s in self.fp)

    def without_benign(self) -> PhishingAssessment:
        return PhishingAssessment(
            tp=list(self.tp),
            fp=[],
            sender_authenticated=self.sender_authenticated,
            lookalikes=list(self.lookalikes),
            lookalike_hosts=list(self.lookalike_hosts),
            impersonation=self.impersonation,
            suspicious_urls=list(self.suspicious_urls),
        )

    def digest(self) -> PhishingDigest:
        """For the triage digest: what analysis and the response planner read back."""
        out: PhishingDigest = {"sender_authenticated": self.sender_authenticated}
        if self.lookalikes:
            out["lookalikes"] = self.lookalikes[:MAX_DETAILS]
            out["lookalike_hosts"] = self.lookalike_hosts[:MAX_DETAILS]
        if self.impersonation:
            out["impersonation"] = self.impersonation
        if self.suspicious_urls:
            out["suspicious_urls"] = self.suspicious_urls[:MAX_DETAILS]
        return out


def links(section: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """The section's URLs the message leads to (without the display-only ones, see the module docs)."""
    return [u for u in (_mapping(x) for x in _list(section.get("urls"))) if not u.get("display_only")]


def _candidate_hosts(section: Mapping[str, Any]) -> List[str]:
    sender = _mapping(section.get("from"))
    hosts = [sender.get("domain"), *(_domain_of(a) for a in _list(section.get("reply_to")))]
    hosts.append(_domain_of(section.get("return_path")))
    hosts.extend(u.get("host") for u in links(section))
    return list(dict.fromkeys(h for h in hosts if isinstance(h, str) and h))[:MAX_CANDIDATE_HOSTS]


def assess(section: Mapping[str, Any], profile: PhishingProfile) -> PhishingAssessment:
    """Signals for one email section (``CanonicalAlert.email``)."""
    result = PhishingAssessment()
    tp = result.tp
    sender = _mapping(section.get("from"))
    from_domain = str(sender.get("domain") or _domain_of(sender.get("address")) or "")
    from_site = site(from_domain) if from_domain else ""

    auth = effective_auth(section, profile)
    if auth.get("dmarc") == "fail" or (auth.get("dmarc") in (None, "none") and auth.get("compauth") == "fail"):
        tp.append(DMARC_FAIL)
    if auth.get("spf") in ("fail", "softfail", "hardfail"):
        tp.append(SPF_FAIL)
    if auth.get("dkim") == "fail":
        tp.append(DKIM_FAIL)
    dkim_sites = {site(d) for d in _list(auth.get("dkim_domains")) if isinstance(d, str)}
    mailfrom = auth.get("smtp_mailfrom")
    result.sender_authenticated = bool(from_site) and (
        auth.get("dmarc") == "pass"
        or (auth.get("spf") == "pass" and isinstance(mailfrom, str) and site(mailfrom) == from_site)
        or (auth.get("dkim") == "pass" and from_site in dkim_sites)
    )

    if from_site and any(
        (d := _domain_of(a)) is not None and site(d) != from_site for a in _list(section.get("reply_to"))
    ):
        tp.append(REPLY_TO_MISMATCH)
    return_domain = _domain_of(section.get("return_path"))
    if from_site and return_domain and site(return_domain) != from_site:
        tp.append(RETURN_PATH_MISMATCH)

    result.impersonation = _impersonation(section, profile)
    if result.impersonation:
        tp.append(DISPLAY_NAME_IMPERSONATION)

    refs = profile.references()
    if refs:
        for host in _candidate_hosts(section):
            found = lookalike(host, profile, refs)
            if found and len(result.lookalikes) < MAX_DETAILS:
                result.lookalikes.append(found)
                result.lookalike_hosts.append(ascii_host(host))
        if result.lookalikes:
            tp.append(LOOKALIKE_DOMAIN)

    urls = links(section)
    if any(u.get("mismatch") for u in urls):
        tp.append(LINK_TEXT_MISMATCH)
    if any(u.get("shortener") for u in urls):
        tp.append(URL_SHORTENER)
    if any(u.get("ip_host") for u in urls):
        tp.append(IP_URL)
    result.suspicious_urls = [
        str(u["url"]) for u in urls if isinstance(u.get("url"), str) and (u.get("mismatch") or u.get("ip_host"))
    ][:MAX_DETAILS]
    if any(_list(_mapping(a).get("risks")) for a in _list(section.get("attachments"))):
        tp.append(RISKY_ATTACHMENT)
    if _list(section.get("credential_wording")):
        tp.append(CREDENTIAL_WORDING)

    all_pass = auth.get("spf") == "pass" and auth.get("dkim") == "pass" and auth.get("dmarc") == "pass"
    header_from = auth.get("header_from")
    aligned = not isinstance(header_from, str) or not from_site or site(header_from) == from_site
    if (
        profile.is_internal(from_domain)
        and all_pass
        and aligned
        and not any(s in EVIDENCE_SIGNALS for s in tp)
        and REPLY_TO_MISMATCH not in tp
    ):
        result.fp.append(INTERNAL_AUTHENTICATED)
    return result


def evidence_from_triage(triage: Mapping[str, Any]) -> List[str]:
    """The strong phishing signals among triage's rule indicators (analysis evidence)."""
    return [s for s in _list(triage.get("rule_tp")) if s in EVIDENCE_SIGNALS]


def benign_from_triage(triage: Mapping[str, Any]) -> bool:
    return INTERNAL_AUTHENTICATED in _list(triage.get("rule_fp"))


def corroborated_email_targets(alert: Mapping[str, Any], triage: Mapping[str, Any]) -> List[List[str]]:
    """``[kind, value]`` targets strong phishing evidence is about (per-target corroboration).

    The message itself; the sender only when its identity is authenticated
    or its domain is a lookalike (a spoofed sender is someone else's
    address, so blocking it would hit the impersonated party); Reply-To
    addresses on lookalike domains; the deceptive or raw-IP links; the
    lookalike domains.
    """
    section = _mapping(alert.get("email"))
    details = _mapping(triage.get("phishing"))
    lookalike_hosts = {h for h in _list(details.get("lookalike_hosts")) if isinstance(h, str)}
    out: List[List[str]] = []
    message_id = section.get("message_id")
    if isinstance(message_id, str) and message_id:
        out.append(["message", message_id])
    sender = _mapping(section.get("from"))
    address = sender.get("address")
    domain = _domain_of(address)
    if isinstance(address, str) and address and (
        details.get("sender_authenticated") is True or (domain is not None and ascii_host(domain) in lookalike_hosts)
    ):
        out.append(["email", address])
    for reply in _list(section.get("reply_to")):
        reply_domain = _domain_of(reply)
        if isinstance(reply, str) and reply_domain is not None and ascii_host(reply_domain) in lookalike_hosts:
            out.append(["email", reply])
    out.extend(["url", u] for u in _list(details.get("suspicious_urls")) if isinstance(u, str))
    out.extend(["domain", h] for h in sorted(lookalike_hosts))
    return out


def plan_email_entities(alert: Mapping[str, Any]) -> Dict[str, List[str]]:
    """Response targets from the email section: senders (``email``), the message and the reporter."""
    section = _mapping(alert.get("email"))
    if not section:
        return {}
    out: Dict[str, List[str]] = {}
    sender = _mapping(section.get("from")).get("address")
    senders = [s for s in [sender, *_list(section.get("reply_to"))] if isinstance(s, str) and s]
    if senders:
        out["email"] = list(dict.fromkeys(senders))
    message_id = section.get("message_id")
    if isinstance(message_id, str) and message_id:
        out["message"] = [message_id]
    reporter = section.get("reporter")
    if isinstance(reporter, str) and reporter:
        out["reporter"] = [reporter]
    return out


def email_block_targets(alert: Mapping[str, Any]) -> Dict[str, List[str]]:
    """The ``url``, ``domain`` and ``ip`` values a block may target in an email alert (empty for other alerts).

    Where the message leads (its links and their hosts) and where it came
    from (the sender, Reply-To and Return-Path domains, the relay), nothing
    else: a display-only URL or its domain is never one, whatever a model
    recommends or an entity list holds.
    """
    section = _mapping(alert.get("email"))
    if not section:
        return {}
    sender = _mapping(section.get("from"))
    urls: List[Any] = []
    domains: List[Any] = [sender.get("domain"), _domain_of(sender.get("address"))]
    domains += [_domain_of(a) for a in [*_list(section.get("reply_to")), section.get("return_path")]]
    ips: List[Any] = [section.get("relay_ip")]
    for link in links(section):
        urls.append(link.get("url"))
        if link.get("ip_host"):
            ips.append(link.get("host"))
        else:
            domains.append(link.get("host"))
    return {
        kind: list(dict.fromkeys(v for v in values if isinstance(v, str) and v))
        for kind, values in (("url", urls), ("domain", domains), ("ip", ips))
    }


def message_context(alert: Mapping[str, Any]) -> Dict[str, str]:
    """What a purge needs besides the Message-ID so a SOAR never matches another message by id alone."""
    section = _mapping(alert.get("email"))
    sender = _mapping(section.get("from")).get("address")
    out: Dict[str, str] = {}
    if isinstance(sender, str) and sender:
        out["sender"] = sender[:320]
    subject = section.get("subject")
    if isinstance(subject, str) and subject:
        out["subject"] = subject[:200]
    return out


def is_email_alert(alert: Mapping[str, Any]) -> bool:
    return isinstance(alert.get("email"), Mapping)
