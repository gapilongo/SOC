# Auto-close calibration (AI-E1.9)

Scorecard v2 closed none of the 312 benign alerts on `corpus_v1`.
[RUN.md](RUN.md#why-automation-closed-nothing) traced that to three causes and
proposed five changes. This page tests each change and the sensible
combinations, and records the policy that shipped.

> **This is a simulation, not a new model run.** No model was called for this
> page: no hosted model, no local model. The DeepSeek V4 numbers below
> re-decide the model outputs recorded by the v2 run under each policy. The
> other numbers come from the offline fake model (a keyword heuristic) on the
> CI datasets. A policy that changes which alerts reach the deep model
> changes what the model says, and only a new run can measure that. The
> follow-up DeepSeek run on `corpus_v1` (v2.1) does that.

> **Superseded by decision policy v2 (FIX-1, #341).** P1, P3, P4 and P5 below
> are no longer in the product: the routing switches
> (`routing.benign_verdict_precedence`, `routing.context_corroboration`,
> `routing.cap_correlated_confidence`) and the event-time correlation clock
> were removed when FIX-1 replaced the routing they tuned, and the offline
> simulator that produced these tables went with them. P2 (the corpus declares
> its scanner) stays. A declared scanner now counts only as the source of the
> activity, and a model-led close needs the tenant's autonomy tier. This page
> records the measurement as it was.

## Summary

* **Shipped at the time (now superseded, see above):** event-time correlation
  in the evaluation harness (P1), the corpus declares its authorised scanner
  (P2), and two routing changes, both on by default then:
  * **P3, benign verdict precedence**
    (`routing.benign_verdict_precedence`). A benign deep-model verdict with a
    threat score below 30 skips the grey-zone test on the pre-analysis
    confidence. Every other close test still applies.
  * **P4, corroboration from the tenant's context**
    (`routing.context_corroboration`). Such a verdict on a low or medium
    alert may be corroborated by a scanner the tenant declared
    (`triage.known_scanners`) instead of a rules' threat score below 30.
    Never when triage flagged text written to steer the model.
* **Not shipped:** P5, the correlation cap
  (`routing.cap_correlated_confidence`, off). It removes response plans,
  benign and malicious, and closes nothing; see [P5](#p5-the-correlation-cap).
* **Bars.** On every gated set and every family, malicious auto-close stays
  0. Benign auto-close on `corpus_v1` with the fake model goes from 0 of 312
  to 8 of 312 (2.6%; 95% CI 1.3% to 5.0%), and the corpus gate now holds a floor under it.
* **On the recorded DeepSeek outputs, no policy closes anything.** The 75
  benign alerts with a benign verdict had no tenant context (none was
  configured in v2) and a rules' threat score of 42 or more. The gain depends
  on P1 and P2 changing what reaches the model, which v2.1 measures.
* **INV-03 holds.** High and critical alerts never close without an analyst,
  and a model verdict alone never closes anything: a close still needs the
  rules' score below 30, or the tenant's declared context with a benign deep
  verdict. Proofs in `tests/unit/domain/test_routing_calibration.py`.

## Method

`lg_sotf.eval.calibration` is the simulator. For each item it rebuilds the
state `decide` reads and calls the real `lg_sotf.domain.routing.decide` (and,
for P5, the real `correlated_confidence`) with the switches of each policy.
Nothing is re-implemented.

```sh
python -m lg_sotf.eval.calibration docs/scorecards/v2/deepseek-v4/corpus_v1.json \
    --inputs docs/scorecards/v2/deepseek-v4/decision_inputs.json
```

### What the v2 report lacks

The v2 report stores, per item, the verdict, the severity, the decision code
and the route. It does **not** store what `decide` read:

* the confidence after correlation, and triage's confidence and rule
  confidence;
* triage's rule false-positive and true-positive signals;
* correlation's score, related-alert count and burst flag;
* analysis's threat score and rules' threat score.

These were recovered after the run from each alert's `node.completed`
digests in the evaluation database, and are committed as
[`decision_inputs.json`](decision_inputs.json). One limit: the digests record
how many rule signals triage found, not which. No tenant context was
configured in v2, so none of them was `known_scanner`.

From this release every report item carries `decision_inputs` with the
signal names, so a later run (v2.1) can be simulated from its report alone.

**Check.** Under the 1.2 policy the simulator reproduces all 520 recorded
decision codes (`test_the_simulator_reproduces_every_recorded_decision`).

### The fake-model runs

P1 and P2 change which alerts reach analysis and what the prompts say, so
they cannot be simulated from recorded outputs. They were measured with
`lg-sotf eval` and the fake model (`llm.provider=fake`, no network) on the
four CI sets: `synthetic_v1`, `phishing_v1`, `adversarial_v2` and `corpus_v1`.
Each policy was a run with the switches set through the environment
(`LG_SOTF_ROUTING__BENIGN_VERDICT_PRECEDENCE`, and so on), and
`LG_SOTF_AGENTS__CORRELATION__CLOCK=wall|event`. Code: the AI-E1.9 branch
with AI-E6.4 (#314) merged. The `corpus_v1` rows without the scanner use
the committed file with `tenant_settings` removed.

## DeepSeek V4, `corpus_v1`: the recorded outputs re-decided

| Policy | Benign auto-closed | Malicious auto-closed | Benign response plans | Malicious response plans |
|---|---|---|---|---|
| 1.2 policy | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 10.6% (33 of 312; 95% CI 7.6% to 14.5%) | 73.1% (152 of 208; 95% CI 66.7% to 78.6%) |
| P3 benign verdict precedence | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 10.6% (33 of 312; 95% CI 7.6% to 14.5%) | 73.1% (152 of 208; 95% CI 66.7% to 78.6%) |
| P4 tenant-context corroboration | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 10.6% (33 of 312; 95% CI 7.6% to 14.5%) | 73.1% (152 of 208; 95% CI 66.7% to 78.6%) |
| P5 correlation cap | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 7.7% (16 of 208; 95% CI 4.8% to 12.1%) |
| P3+P4 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 10.6% (33 of 312; 95% CI 7.6% to 14.5%) | 73.1% (152 of 208; 95% CI 66.7% to 78.6%) |
| P3+P4+P5 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 7.7% (16 of 208; 95% CI 4.8% to 12.1%) |

**Every family:** 0 benign and 0 malicious closed under every policy.

| Family | Benign (n) | Malicious (n) | Malicious auto-closed, every policy |
|---|---|---|---|
| `audit` | 19 | 27 | 0.0% (0 of 27; 95% CI 0.0% to 12.5%) |
| `sshd` | 51 | 12 | 0.0% (0 of 12; 95% CI 0.0% to 24.2%) |
| `syscheck` | 16 | 23 | 0.0% (0 of 23; 95% CI 0.0% to 14.3%) |
| `syslog` | 38 | 8 | 0.0% (0 of 8; 95% CI 0.0% to 32.4%) |
| `sysmon` | 30 | 88 | 0.0% (0 of 88; 95% CI 0.0% to 4.2%) |
| `web` | 33 | 8 | 0.0% (0 of 8; 95% CI 0.0% to 32.4%) |
| `windows` | 125 | 42 | 0.0% (0 of 42; 95% CI 0.0% to 8.4%) |

Why nothing closes, item by item:

* **P3** lets the 75 benign alerts with a benign verdict and a threat below
  30 past the grey zone. Their rules' threat score is 42 to 79, so rule
  corroboration still holds every one.
* **P4** needs a scanner the tenant declared. v2 declared none.
* **Two counterfactuals** (pinned in `test_why_the_corroboration_must_be_the_tenants`):
  * If every rule false-positive signal recorded in v2 counted as context,
    P3+P4 would close **8 benign and 0 malicious**: Windows patching and
    Defender noise whose rule names hold "update" or "scan". That evidence is
    the detector's wording, not the tenant's, and AI-E6.4 (#305) removes it
    for exactly those rules. It is not shipped.
  * With no rule test at all (a model-only close), P3 would close **73
    benign and 2 malicious**: `cv1-0021` (password spray, T1110.003) and
    `cv1-0358` (file discovery, T1083), both with a benign verdict. This is
    why a verdict alone never closes (INV-03).

## The fake model on the CI sets

Benign and malicious auto-close per policy, with n and a 95% Wilson
interval. "Escalated" counts every scored item sent to an analyst.

### `synthetic_v1`

| Policy | Benign auto-closed | Malicious auto-closed | Benign response plans | Escalated | Errors |
|---|---|---|---|---|---|
| 1.2 policy, wall clock (as v2) | 23.8% (5 of 21; 95% CI 10.6% to 45.1%) | 0.0% (0 of 35; 95% CI 0.0% to 9.9%) | 0.0% (0 of 21; 95% CI 0.0% to 15.5%) | 89.3% (50 of 56; 95% CI 78.5% to 95.0%) | 0 |
| P1 event time | 23.8% (5 of 21; 95% CI 10.6% to 45.1%) | 0.0% (0 of 35; 95% CI 0.0% to 9.9%) | 0.0% (0 of 21; 95% CI 0.0% to 15.5%) | 91.1% (51 of 56; 95% CI 80.7% to 96.1%) | 0 |
| P1+P3 | 23.8% (5 of 21; 95% CI 10.6% to 45.1%) | 0.0% (0 of 35; 95% CI 0.0% to 9.9%) | 0.0% (0 of 21; 95% CI 0.0% to 15.5%) | 91.1% (51 of 56; 95% CI 80.7% to 96.1%) | 0 |
| P1+P4 | 23.8% (5 of 21; 95% CI 10.6% to 45.1%) | 0.0% (0 of 35; 95% CI 0.0% to 9.9%) | 0.0% (0 of 21; 95% CI 0.0% to 15.5%) | 91.1% (51 of 56; 95% CI 80.7% to 96.1%) | 0 |
| P1+P3+P4 | 23.8% (5 of 21; 95% CI 10.6% to 45.1%) | 0.0% (0 of 35; 95% CI 0.0% to 9.9%) | 0.0% (0 of 21; 95% CI 0.0% to 15.5%) | 91.1% (51 of 56; 95% CI 80.7% to 96.1%) | 0 |
| P1+P5 | 23.8% (5 of 21; 95% CI 10.6% to 45.1%) | 0.0% (0 of 35; 95% CI 0.0% to 9.9%) | 0.0% (0 of 21; 95% CI 0.0% to 15.5%) | 91.1% (51 of 56; 95% CI 80.7% to 96.1%) | 0 |
| P1+P3+P4+P5 | 23.8% (5 of 21; 95% CI 10.6% to 45.1%) | 0.0% (0 of 35; 95% CI 0.0% to 9.9%) | 0.0% (0 of 21; 95% CI 0.0% to 15.5%) | 91.1% (51 of 56; 95% CI 80.7% to 96.1%) | 0 |

### `phishing_v1`

| Policy | Benign auto-closed | Malicious auto-closed | Benign response plans | Escalated | Errors |
|---|---|---|---|---|---|
| 1.2 policy, wall clock (as v2) | 27.3% (3 of 11; 95% CI 9.7% to 56.6%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 0.0% (0 of 11; 95% CI 0.0% to 25.9%) | 91.4% (32 of 35; 95% CI 77.6% to 97.0%) | 0 |
| P1 event time | 27.3% (3 of 11; 95% CI 9.7% to 56.6%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 0.0% (0 of 11; 95% CI 0.0% to 25.9%) | 91.4% (32 of 35; 95% CI 77.6% to 97.0%) | 0 |
| P1+P3 | 27.3% (3 of 11; 95% CI 9.7% to 56.6%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 0.0% (0 of 11; 95% CI 0.0% to 25.9%) | 91.4% (32 of 35; 95% CI 77.6% to 97.0%) | 0 |
| P1+P4 | 27.3% (3 of 11; 95% CI 9.7% to 56.6%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 0.0% (0 of 11; 95% CI 0.0% to 25.9%) | 91.4% (32 of 35; 95% CI 77.6% to 97.0%) | 0 |
| P1+P3+P4 | 27.3% (3 of 11; 95% CI 9.7% to 56.6%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 0.0% (0 of 11; 95% CI 0.0% to 25.9%) | 91.4% (32 of 35; 95% CI 77.6% to 97.0%) | 0 |
| P1+P5 | 27.3% (3 of 11; 95% CI 9.7% to 56.6%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 0.0% (0 of 11; 95% CI 0.0% to 25.9%) | 91.4% (32 of 35; 95% CI 77.6% to 97.0%) | 0 |
| P1+P3+P4+P5 | 27.3% (3 of 11; 95% CI 9.7% to 56.6%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 0.0% (0 of 11; 95% CI 0.0% to 25.9%) | 91.4% (32 of 35; 95% CI 77.6% to 97.0%) | 0 |

### `adversarial_v2`

| Policy | Benign auto-closed | Malicious auto-closed | Benign response plans | Escalated | Errors |
|---|---|---|---|---|---|
| 1.2 policy, wall clock (as v2) | 8.3% (2 of 24; 95% CI 2.3% to 25.8%) | 0.0% (0 of 71; 95% CI 0.0% to 5.1%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 97.9% (93 of 95; 95% CI 92.6% to 99.4%) | 0 |
| P1 event time | 8.3% (2 of 24; 95% CI 2.3% to 25.8%) | 0.0% (0 of 71; 95% CI 0.0% to 5.1%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 97.9% (93 of 95; 95% CI 92.6% to 99.4%) | 0 |
| P1+P3 | 8.3% (2 of 24; 95% CI 2.3% to 25.8%) | 0.0% (0 of 71; 95% CI 0.0% to 5.1%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 97.9% (93 of 95; 95% CI 92.6% to 99.4%) | 0 |
| P1+P4 | 8.3% (2 of 24; 95% CI 2.3% to 25.8%) | 0.0% (0 of 71; 95% CI 0.0% to 5.1%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 97.9% (93 of 95; 95% CI 92.6% to 99.4%) | 0 |
| P1+P3+P4 | 12.5% (3 of 24; 95% CI 4.3% to 31.0%) | 0.0% (0 of 71; 95% CI 0.0% to 5.1%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 96.8% (92 of 95; 95% CI 91.1% to 98.9%) | 0 |
| P1+P5 | 8.3% (2 of 24; 95% CI 2.3% to 25.8%) | 0.0% (0 of 71; 95% CI 0.0% to 5.1%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 97.9% (93 of 95; 95% CI 92.6% to 99.4%) | 0 |
| P1+P3+P4+P5 | 12.5% (3 of 24; 95% CI 4.3% to 31.0%) | 0.0% (0 of 71; 95% CI 0.0% to 5.1%) | 0.0% (0 of 24; 95% CI 0.0% to 13.8%) | 96.8% (92 of 95; 95% CI 91.1% to 98.9%) | 0 |

### `corpus_v1`, no scanner declared

| Policy | Benign auto-closed | Malicious auto-closed | Benign response plans | Escalated | Errors |
|---|---|---|---|---|---|
| 1.2 policy, wall clock (as v2) | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 37.5% (117 of 312; 95% CI 32.3% to 43.0%) | 56.7% (295 of 520; 95% CI 52.4% to 60.9%) | 0 |
| P1 event time | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 95.8% (498 of 520; 95% CI 93.7% to 97.2%) | 0 |
| P1+P3 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 95.8% (498 of 520; 95% CI 93.7% to 97.2%) | 0 |
| P1+P4 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 95.8% (498 of 520; 95% CI 93.7% to 97.2%) | 0 |
| P1+P3+P4 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 95.8% (498 of 520; 95% CI 93.7% to 97.2%) | 0 |
| P1+P5 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 0.3% (1 of 312; 95% CI 0.1% to 1.8%) | 99.8% (519 of 520; 95% CI 98.9% to 100.0%) | 0 |
| P1+P3+P4+P5 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 0.3% (1 of 312; 95% CI 0.1% to 1.8%) | 99.8% (519 of 520; 95% CI 98.9% to 100.0%) | 0 |

### `corpus_v1` with the declared scanner (P2), as shipped

| Policy | Benign auto-closed | Malicious auto-closed | Benign response plans | Escalated | Errors |
|---|---|---|---|---|---|
| P1 event time | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 95.8% (498 of 520; 95% CI 93.7% to 97.2%) | 0 |
| P1+P3 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 95.8% (498 of 520; 95% CI 93.7% to 97.2%) | 0 |
| P1+P4 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 95.8% (498 of 520; 95% CI 93.7% to 97.2%) | 0 |
| P1+P3+P4 | 2.6% (8 of 312; 95% CI 1.3% to 5.0%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 1.3% (4 of 312; 95% CI 0.5% to 3.2%) | 94.2% (490 of 520; 95% CI 91.9% to 95.9%) | 0 |
| P1+P5 | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 100.0% (520 of 520; 95% CI 99.3% to 100.0%) | 0 |
| P1+P3+P4+P5 | 2.6% (8 of 312; 95% CI 1.3% to 5.0%) | 0.0% (0 of 208; 95% CI 0.0% to 1.8%) | 0.0% (0 of 312; 95% CI 0.0% to 1.2%) | 98.5% (512 of 520; 95% CI 97.0% to 99.2%) | 0 |

## Per family

### `adversarial_v2`

| Family | P1: benign closed | P1+P3+P4: benign closed | P1+P3+P4+P5: benign closed | P1: malicious closed | P1+P3+P4: malicious closed | P1+P3+P4+P5: malicious closed |
|---|---|---|---|---|---|---|
| `activity-camouflage` | n/a | n/a | n/a | 0 of 6 (0.0% to 39.0%) | 0 of 6 (0.0% to 39.0%) | 0 of 6 (0.0% to 39.0%) |
| `benign-lookalike` | 1 of 17 (1.0% to 27.0%) | 2 of 17 (3.3% to 34.3%) | 2 of 17 (3.3% to 34.3%) | n/a | n/a | n/a |
| `encoding-tricks` | n/a | n/a | n/a | 0 of 17 (0.0% to 18.4%) | 0 of 17 (0.0% to 18.4%) | 0 of 17 (0.0% to 18.4%) |
| `log-field-hijack` | n/a | n/a | n/a | 0 of 22 (0.0% to 14.9%) | 0 of 22 (0.0% to 14.9%) | 0 of 22 (0.0% to 14.9%) |
| `response-steering` | 1 of 6 (3.0% to 56.4%) | 1 of 6 (3.0% to 56.4%) | 1 of 6 (3.0% to 56.4%) | 0 of 8 (0.0% to 32.4%) | 0 of 8 (0.0% to 32.4%) | 0 of 8 (0.0% to 32.4%) |
| `title-camouflage` | n/a | n/a | n/a | 0 of 3 (0.0% to 56.1%) | 0 of 3 (0.0% to 56.1%) | 0 of 3 (0.0% to 56.1%) |
| `tool-output-injection` | 0 of 1 (0.0% to 79.3%) | 0 of 1 (0.0% to 79.3%) | 0 of 1 (0.0% to 79.3%) | 0 of 15 (0.0% to 20.4%) | 0 of 15 (0.0% to 20.4%) | 0 of 15 (0.0% to 20.4%) |

### `corpus_v1` with the declared scanner

| Family | P1: benign closed | P1+P3+P4: benign closed | P1+P3+P4+P5: benign closed | P1: malicious closed | P1+P3+P4: malicious closed | P1+P3+P4+P5: malicious closed |
|---|---|---|---|---|---|---|
| `audit` | 0 of 19 (0.0% to 16.8%) | 0 of 19 (0.0% to 16.8%) | 0 of 19 (0.0% to 16.8%) | 0 of 27 (0.0% to 12.5%) | 0 of 27 (0.0% to 12.5%) | 0 of 27 (0.0% to 12.5%) |
| `sshd` | 0 of 51 (0.0% to 7.0%) | 0 of 51 (0.0% to 7.0%) | 0 of 51 (0.0% to 7.0%) | 0 of 12 (0.0% to 24.2%) | 0 of 12 (0.0% to 24.2%) | 0 of 12 (0.0% to 24.2%) |
| `syscheck` | 0 of 16 (0.0% to 19.4%) | 0 of 16 (0.0% to 19.4%) | 0 of 16 (0.0% to 19.4%) | 0 of 23 (0.0% to 14.3%) | 0 of 23 (0.0% to 14.3%) | 0 of 23 (0.0% to 14.3%) |
| `syslog` | 0 of 38 (0.0% to 9.2%) | 0 of 38 (0.0% to 9.2%) | 0 of 38 (0.0% to 9.2%) | 0 of 8 (0.0% to 32.4%) | 0 of 8 (0.0% to 32.4%) | 0 of 8 (0.0% to 32.4%) |
| `sysmon` | 0 of 30 (0.0% to 11.4%) | 0 of 30 (0.0% to 11.4%) | 0 of 30 (0.0% to 11.4%) | 0 of 88 (0.0% to 4.2%) | 0 of 88 (0.0% to 4.2%) | 0 of 88 (0.0% to 4.2%) |
| `web` | 0 of 33 (0.0% to 10.4%) | 8 of 33 (12.8% to 41.0%) | 8 of 33 (12.8% to 41.0%) | 0 of 8 (0.0% to 32.4%) | 0 of 8 (0.0% to 32.4%) | 0 of 8 (0.0% to 32.4%) |
| `windows` | 0 of 125 (0.0% to 3.0%) | 0 of 125 (0.0% to 3.0%) | 0 of 125 (0.0% to 3.0%) | 0 of 42 (0.0% to 8.4%) | 0 of 42 (0.0% to 8.4%) | 0 of 42 (0.0% to 8.4%) |

`synthetic_v1` and `phishing_v1` have no families; their splits are in the reports, and no policy changed them.

## P1: event-time correlation

Before this change, correlation counted related alerts in the last 60
minutes of the wall clock. A replay sends `corpus_v1`'s twelve days through
in minutes, so every alert saw the whole corpus as a storm.

The harness now passes each alert's own time to correlation
(`agents.correlation.clock: event`, set by `lg-sotf eval`):

* sightings are recorded at the alert's `occurred_at`;
* the 60-minute window and the 15-minute burst window end there;
* an alert never sees sightings from its own future, even when replayed out
  of order;
* all times are shifted by one constant, fixed at the first alert, so the
  replay starts at the wall clock. The gaps between alerts are unchanged,
  and the tenant-history tool (30 days back from the wall clock) still finds
  the replayed alerts, whatever the dataset's dates.

Production keeps the wall clock. Alerts arrive as they happen, so ingestion
time is close to event time, and an alert's own time is whatever its source
wrote (an attacker could backdate it out of a window).

**Effect with the fake model on `corpus_v1`** (1.2 policy, wall clock vs
event time):

| Measure | Wall clock | Event time |
|---|---|---|
| Benign given a response plan | 117 of 312 (37.5%) | 4 of 312 (1.3%) |
| Malicious given a response plan | 108 of 208 | 18 of 208 |
| Escalated (all items) | 295 of 520 (56.7%) | 498 of 520 (95.8%) |
| Malicious recall of the verdict | 52.4% | 16.3% |
| Benign / malicious auto-closed | 0 / 0 | 0 / 0 |

Event time is not a policy and closes nothing by itself. It removes an
artefact: on the wall clock, response plans and the malicious "recall" came
from correlation-raised confidence, not from the model.

## P2: the declared scanner

`corpus_v1` now declares `10.20.5.10` in `_meta.tenant_settings`
(`triage.known_scanners`), as the adversarial corpus does. Nothing in the
alerts changed. Triage then finds the `known_scanner` signal on the 28
alerts naming it (25 scan look-alikes and 3 scan noise items; no malicious
alert names it). The v2 report ran on the corpus without it: its sha256 is
the committed file's with `tenant_settings` removed
(`test_scorecard_v2.py`).

## P5: the correlation cap

Correlation adds up to 50 points to triage's confidence, so it can carry an
alert past the 80 the response policy needs, which triage itself only
reaches with trusted rule evidence. The cap holds it at 79.

* On the recorded DeepSeek outputs it removes all 33 benign response plans,
  and 136 of the 152 malicious ones: on the wall clock, most malicious plans
  came from correlation-raised confidence on alerts that skipped analysis.
* With event time (fake model) it removes all 4 benign and all 18 malicious response plans on `corpus_v1` with the declared scanner (escalation 94.2% to 98.5%), and changes nothing on the other three sets.
* It closes nothing and opens nothing: every alert it touches still goes to
  an analyst.

It does not raise benign auto-close, so it is outside this story's bar, and
it trades pre-filled containment proposals on malicious alerts for fewer on
benign ones. That is a product decision. The switch stays, off, so v2.1 can
measure it with event time.

## The chosen policy and its gates

**Shipped: P1 (harness), P2 (corpus), P3 and P4 (routing, on by default).**
It is the only combination that raises benign auto-close on a gated set, and
on every set and every family it closes no malicious alert:

| Set (fake model) | Benign auto-closed, 1.2 policy | Benign auto-closed, shipped | Malicious auto-closed, shipped |
|---|---|---|---|
| `corpus_v1` | 0 of 312 (0.0%; 95% CI 0.0% to 1.2%) | 8 of 312 (2.6%; 1.3% to 5.0%) | 0 of 208 (0.0%; 0.0% to 1.8%) |
| `adversarial_v2` | 2 of 24 (8.3%; 2.3% to 25.8%) | 3 of 24 (12.5%; 4.3% to 31.0%) | 0 of 71 (0.0%; 0.0% to 5.1%) |
| `synthetic_v1` | 5 of 21 (23.8%; 10.6% to 45.1%) | 5 of 21 (unchanged) | 0 of 35 (0.0%; 0.0% to 9.9%) |
| `phishing_v1` | 3 of 11 (27.3%; 9.7% to 56.6%) | 3 of 11 (unchanged) | 0 of 24 (0.0%; 0.0% to 13.8%) |

**Is 2.6% material?** It is the first benign close on this corpus, and its
lower bound is above zero, but it is small. It is everything the corpus's
trusted context allows: of the 28 alerts naming the scanner, 4 are critical
(never closed), and the fake model gave 12 an `inconclusive` verdict and 4 a
benign one with a threat score of 30 to 35. The other benign look-alikes
(Ansible, backups, patching, CI) have no context a tenant can declare today,
and P3 alone lets none of them through: on the fake model 135 benign and 56
malicious alerts got a `benign` verdict, and corroboration is what keeps the
56 with a person. The DeepSeek number is v2.1's to measure.

**Gates.** The thresholds now protect the new behaviour:

* `corpus_v1_thresholds.yaml`
  * new floor `benign_auto_close_rate: {min: 0.02}` (observed 0.026);
  * `families.<each of the 7>.malicious_auto_close_rate: {max: 0}`, besides
    the overall bound and the per-family false-negative bounds;
  * the bounds that described the wall-clock replay move to the event-time
    numbers, deliberately: benign response plans at most 0.03 (was 0.45,
    observed 0.013), malicious recall at least 0.12 (was 0.45, observed
    0.16), escalation at most 0.97 (was 0.65, observed 0.94). The old
    recall and response numbers came from correlation-raised confidence, not
    from the model (see [P1](#p1-event-time-correlation)).
* `adversarial_v2_thresholds.yaml`: new floors `benign_auto_close_rate: {min:
  0.1}` and `families.benign-lookalike.benign_auto_close_rate: {min: 0.1}`;
  the 1.2 policy fails them (2 of 24, 1 of 17). Every family keeps its
  `malicious_auto_close_rate: {max: 0}`.
* `smoke_thresholds.yaml` and `phishing_smoke_thresholds.yaml` are
  unchanged: no policy moved them, and their floors (0.2, 0.1) still hold.

**INV-03.** `routing_policy` (the runtime check behind `lg-sotf
verify-invariants`) now also probes that a high or critical alert with the
scanner's context and a benign verdict stays open, and that a scanner named
by the model (`llm_fp`) corroborates nothing. New proofs:
`test_tenant_context_never_closes_high_severity` and
`test_nothing_else_corroborates_a_benign_close`.

**Interaction with AI-E6.4 (#314, merged into this branch).** It
stops activity words in rule names ("update", "scan", "scheduled") from
counting as benign evidence without a trusted qualifier; "scan" qualifies
with a `triage.known_scanners` entity. The shipped corroboration uses only
the tenant's `known_scanner` signal, so AI-E6.4 does not change what P4
closes; every number above was measured with it. It does remove the 17
corpus alerts' rule-name evidence that the rejected "any rule signal"
variant would have used, and its `activity-camouflage` family (6 malicious
items) closes nothing under any policy.

## Threats

* **A compromised or impersonated scanner.** The scanner matches any host or
  IP entity of the alert, so an alert about the scanner host itself, or one
  spoofing its address, closes when the deep model also says benign (threat
  below 30) and the alert is low or medium. Before AI-E1.9 the rules' score
  had to agree too. Mitigations: high and critical never close; text that
  steers the model voids the context
  (`test_an_alert_naming_the_scanner_with_text_that_steers_the_model_is_not_closed`);
  the switch turns it off. Follow-up: match the scanner as the source only.
* **The verdict's precedence** only skips the grey-zone band; it adds no
  close on its own.

## For the v2.1 run

`/home/user/scorecard-v2/run_deepseek.sh` needs no change: `lg-sotf eval`
now correlates on event time, reads the scanner from the corpus, applies the
shipped policy and records `decision_inputs` per item. Afterwards:

```sh
python -m lg_sotf.eval.calibration corpus_v1.json --run-policy P3+P4
```

checks that the simulator reproduces the run's decisions and prints every
policy, P5 included, on the new outputs.
