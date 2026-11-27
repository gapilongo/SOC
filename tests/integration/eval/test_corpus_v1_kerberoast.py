"""The Kerberoasting ticket requests of corpus_v1 with a model that reads them as normal sign-ins (AI-E3.15, #456).

Six corpus alerts are Windows event 4769 with an RC4 ticket: Wazuh rule 60106 "Windows Logon Success", level 3,
T1078. Judged one at a time the real model called such requests benign, and at the tier ``auto_full_audit`` they
closed. The stand-in model rates them in the grey zone, so the corpus measurement
(``test_corpus_v1_investigation.py``) cannot show that; here the stand-in is told to read a ticket request as the
real model did, and the six alerts run through the real pipeline alone, without the earlier steps of their attack
chains (the case the related-alert holds do not cover).

* Control, the policy before #456 (the ticket check switched off): all six close on the models' word.
* With the check: none closes. Each is a never-close class and goes to a person with the benign verdict on record.
"""

from __future__ import annotations

import dataclasses
import secrets
from typing import Any

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.domain import noise_families
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.runner import run_evaluation
from lg_sotf.llm import fake
from lg_sotf.settings import Settings
from tests.integration.eval._investigation import DATASET, KERBEROAST_TICKETS, outcomes, records
from tests.integration.eval._support import NetworkGuard, at_tier

pytestmark = pytest.mark.integration


def reads_a_sign_in(real: Any) -> Any:
    """The stand-in, except that it reads a Kerberos service ticket request as a routine sign-in to a service:
    threat score 8, benign."""
    def analyse(text: str) -> Any:
        if "ticketencryptiontype" not in text.lower():
            return real(text)
        reasons = ("successful logon", "audit success", "a domain user requesting a service ticket is routine")
        return fake.Signals(threat_score=8, confidence=90, malicious=(), benign=reasons)

    return analyse


async def test_the_corpus_ticket_requests_never_close_when_the_model_calls_them_benign(
    eval_settings: Settings, monkeypatch: pytest.MonkeyPatch, repos: Repositories
) -> None:
    corpus = load_dataset(DATASET)
    tickets = [item for item in corpus.items if item.id in KERBEROAST_TICKETS]
    assert [item.id for item in tickets] == list(KERBEROAST_TICKETS)
    assert {item.expected.disposition for item in tickets} == {"malicious"}
    dataset = at_tier(dataclasses.replace(corpus, items=tickets), "auto_full_audit")
    net = NetworkGuard(eval_settings)
    net.install(monkeypatch)
    monkeypatch.setattr(fake, "analyse_text", reads_a_sign_in(fake.analyse_text))

    with monkeypatch.context() as before:  # the policy before #456: nothing reads the ticket's encryption type
        before.setattr(noise_families, "_weak_service_ticket", lambda alert: False)
        control = await run_evaluation(eval_settings, dataset, tenant_id=f"krb-before-{secrets.token_hex(3)}")
    held = await run_evaluation(eval_settings, dataset, tenant_id=f"krb-held-{secrets.token_hex(3)}")

    assert [r.error for r in (*control.results, *held.results) if r.status == "error"] == [] and net.attempts == []
    for run in (control, held):  # the model's word is the same in both runs: benign
        assert {a.get("verdict") for a in (await records(repos, run)).values()} == {"benign"}
    was, now = outcomes(control), outcomes(held)
    assert {i: (o[0], o[2]) for i, o in was.items()} == {i: ("closed", "model_closed") for i in KERBEROAST_TICKETS}
    # With a person, undecided, as a benign verdict the policy may not act on alone (``false_positive_review``).
    assert set(now) == set(KERBEROAST_TICKETS)
    assert all(o[:3] == ("waiting_human", None, "false_positive_review") for o in now.values()), now
