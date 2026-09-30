"""Phishing signals over the email section: authentication, impersonation, lookalikes, links, attachments."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.core import phishing as p
from lg_sotf.core.phishing import PhishingProfile, assess, validate_phishing_settings

TENANT: Dict[str, Any] = {
    "tools": {"internal_domains": ["example.com"]},
    "phishing": {
        "protected_brands": ["Example Bank", "examplebank.test"],
        "executives": ["Jane Doe", "Smith, John"],
    },
}
PROFILE = PhishingProfile.from_settings(TENANT, {})


def ar(domain: str, spf: str = "pass", dkim: str = "pass", dmarc: str = "pass", authserv: Optional[str] = "mx.example.com",
       **extra: Any) -> Dict[str, Any]:
    return {"authserv_id": authserv, "spf": spf, "dkim": dkim, "dmarc": dmarc, "header_from": domain,
            "smtp_mailfrom": domain, "dkim_domains": [domain] if dkim == "pass" else [], **extra}


def section(sender: str = "news@partner.test", display: str = "", **fields: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "message_id": "<m1@partner.test>",
        "subject": "Hello",
        "from": {"address": sender, "display_name": display, "domain": sender.rsplit("@", 1)[1]},
        "reply_to": [],
        "return_path": None,
        "auth": [ar(sender.rsplit("@", 1)[1])],
        "urls": [],
        "attachments": [],
        "credential_wording": [],
    }
    base.update(fields)
    return base


def signals(sec: Dict[str, Any], profile: PhishingProfile = PROFILE) -> List[str]:
    result = assess(sec, profile)
    return result.tp + result.fp


def test_internal_sender_with_all_checks_passing_is_the_benign_signal() -> None:
    assert signals(section("comms@example.com")) == [p.INTERNAL_AUTHENTICATED]
    assert signals(section("comms@mail.example.com", auth=[ar("mail.example.com")])) == [p.INTERNAL_AUTHENTICATED]
    # Any failing (or missing) check, or an external sender: no benign signal.
    assert p.INTERNAL_AUTHENTICATED not in signals(section("comms@example.com", auth=[ar("example.com", dkim="none")]))
    assert p.INTERNAL_AUTHENTICATED not in signals(section("comms@example.com", auth=[]))
    assert signals(section("news@partner.test")) == []
    # A strong signal (a compromised internal account sending a deceptive link) suppresses it.
    deceptive = section("comms@example.com", urls=[{"url": "https://x.test/", "host": "x.test", "mismatch": True}])
    assert signals(deceptive) == [p.LINK_TEXT_MISMATCH]


def test_trusted_authserv_ids_pick_the_receiving_servers_header() -> None:
    forged_below = section("ceo@example.com", auth=[ar("example.com", spf="fail", dmarc="fail"), ar("example.com")])
    assert signals(forged_below)[:2] == [p.DMARC_FAIL, p.SPF_FAIL]
    trusted = PhishingProfile.from_settings({**TENANT, "phishing": {"trusted_authserv_ids": ["mx.example.com"]}}, {})
    forged_on_top = section("ceo@example.com", auth=[ar("example.com", authserv="evil.test"), ar("example.com", dmarc="fail")])
    assert p.INTERNAL_AUTHENTICATED not in signals(forged_on_top, trusted)
    assert p.DMARC_FAIL in signals(forged_on_top, trusted)
    # No header from a trusted server: no authentication verdict at all.
    assert signals(section("ceo@example.com", auth=[ar("example.com", authserv="evil.test")]), trusted) == []


def test_authentication_failures_and_m365_composite_auth() -> None:
    assert signals(section(auth=[ar("partner.test", spf="softfail", dkim="fail", dmarc="fail")])) == [
        p.DMARC_FAIL, p.SPF_FAIL, p.DKIM_FAIL,
    ]
    compauth = section(auth=[{"authserv_id": None, "spf": "pass", "dmarc": "none", "compauth": "fail"}])
    assert signals(compauth) == [p.DMARC_FAIL]


def test_reply_to_and_return_path_on_other_sites() -> None:
    assert signals(section(reply_to=["x@collect.test"])) == [p.REPLY_TO_MISMATCH]
    assert signals(section(reply_to=["x@mail.partner.test"])) == []
    assert signals(section(return_path="bounce@mailer.test")) == [p.RETURN_PATH_MISMATCH]


@pytest.mark.parametrize(
    "display",
    ["Jane Doe", "jane  DOE (via mobile)", "John Smith", "support@partner-helpdesk.test", "example.com IT desk",
     "Example Bank Security"],
)
def test_display_name_impersonation(display: str) -> None:
    assert signals(section("someone@freemail.test", display)) == [p.DISPLAY_NAME_IMPERSONATION]


def test_display_names_that_are_not_impersonation() -> None:
    assert signals(section("jane.doe@example.com", "Jane Doe")) == [p.INTERNAL_AUTHENTICATED]
    assert signals(section("someone@freemail.test", "Jane")) == []
    assert signals(section("alerts@examplebank.test", "Example Bank")) == []
    assert signals(section("news@partner.test", "news@partner.test")) == []


@pytest.mark.parametrize(
    ("host", "technique"),
    [
        ("examp1e.test", "look-alike"),
        ("exarnple.test", "look-alike"),
        ("xn--exmple-4nf.test", "look-alike"),
        ("exampel.test", "typo"),
        ("example.net", "another domain"),
        ("example-login.test", "embeds"),
        ("secure.examplebank-verify.test", "embeds"),
        ("examp1ebank.test", "look-alike"),
    ],
)
def test_lookalike_domains(host: str, technique: str) -> None:
    result = assess(section(urls=[{"url": f"https://{host}/", "host": host}]), PROFILE)
    assert result.tp == [p.LOOKALIKE_DOMAIN] and technique in result.lookalikes[0]


@pytest.mark.parametrize("host", ["example.com", "intranet.example.com", "examplebank.test", "partner.test", "sample.test"])
def test_legitimate_domains_are_not_lookalikes(host: str) -> None:
    assert assess(section(urls=[{"url": f"https://{host}/", "host": host}]), PROFILE).lookalikes == []


def test_link_attachment_and_wording_signals() -> None:
    sec = section(
        urls=[
            {"url": "https://bit.ly/x", "host": "bit.ly", "shortener": True},
            {"url": "http://198.51.100.9/", "host": "198.51.100.9", "ip_host": True},
        ],
        attachments=[{"filename": "a.iso", "risks": ["disk_image"]}],
        credential_wording=["verify_account"],
    )
    result = assess(sec, PROFILE)
    assert result.tp == [p.URL_SHORTENER, p.IP_URL, p.RISKY_ATTACHMENT, p.CREDENTIAL_WORDING]
    assert result.suspicious_urls == ["http://198.51.100.9/"]


def test_weights_and_evidence_sets() -> None:
    assert p.TRIAGE_WEIGHTS[p.INTERNAL_AUTHENTICATED] < 0
    assert p.CREDENTIAL_WORDING not in p.EVIDENCE_SIGNALS and p.RETURN_PATH_MISMATCH not in p.EVIDENCE_SIGNALS
    result = assess(section("comms@example.com"), PROFILE)
    assert result.weight == result.benign_weight == p.TRIAGE_WEIGHTS[p.INTERNAL_AUTHENTICATED]
    assert result.without_benign().fp == []


def test_corroborated_targets_never_include_a_spoofed_sender() -> None:
    alert = {"email": section("ceo@partner.test", reply_to=["pay@examp1e.test"])}
    spoofed = {"phishing": {"sender_authenticated": False, "lookalike_hosts": ["examp1e.test"],
                            "suspicious_urls": ["http://198.51.100.9/"]}}
    targets = p.corroborated_email_targets(alert, spoofed)
    assert ["message", "<m1@partner.test>"] in targets and ["email", "pay@examp1e.test"] in targets
    assert ["email", "ceo@partner.test"] not in targets
    assert ["url", "http://198.51.100.9/"] in targets and ["domain", "examp1e.test"] in targets
    authenticated = {"phishing": {"sender_authenticated": True}}
    assert ["email", "ceo@partner.test"] in p.corroborated_email_targets(alert, authenticated)


def test_plan_entities_and_message_context() -> None:
    alert = {"email": {**section("a@partner.test", reply_to=["b@other.test"]), "reporter": "bob@example.com"}}
    assert p.plan_email_entities(alert) == {
        "email": ["a@partner.test", "b@other.test"], "message": ["<m1@partner.test>"], "reporter": ["bob@example.com"],
    }
    assert p.message_context(alert) == {"sender": "a@partner.test", "subject": "Hello"}
    assert p.plan_email_entities({"title": "not an email"}) == {}


def test_settings_validation_and_malformed_sections() -> None:
    assert validate_phishing_settings({"protected_brands": [" Example Bank "]})["protected_brands"] == ["Example Bank"]
    with pytest.raises(ValueError, match="phishing"):
        validate_phishing_settings({"protected_brands": "not a list"})
    with pytest.raises(ValueError, match="phishing.unknown"):
        validate_phishing_settings({"unknown": []})
    with pytest.raises(ValueError, match="must be an object"):
        validate_phishing_settings(["x"])
    broken = PhishingProfile.from_settings({"phishing": {"executives": 7}, "tools": {"internal_domains": ["Example.COM."]}}, {})
    assert broken.executives == () and broken.internal_domains == ("example.com",)
    install = PhishingProfile.from_settings({}, {"internal_domains": ["corp.example"]})
    assert install.is_internal("mail.corp.example") and not install.is_internal("corp.example.test")


def test_damerau_levenshtein_is_bounded() -> None:
    assert p.damerau_levenshtein("example", "exampel", 1) == 1
    assert p.damerau_levenshtein("example", "sample", 1) == 2
    assert p.damerau_levenshtein("a" * 60, "b" * 60, 2) == 3
