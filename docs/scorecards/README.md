# Evaluation scorecards

A scorecard is the one-page summary of how one model configuration handled
the evaluation sets: what it missed, what it closed on its own, how often it
asked an analyst, and what it cost. It is generated from the JSON reports of
`lg-sotf eval` (docs/evaluation.md), so every number traces back to a
per-item report committed next to it.

| Scorecard | Model | Data | Status |
|---|---|---|---|
| [v2, DeepSeek V4](v2/deepseek-v4/scorecard.md) ([RUN.md](v2/deepseek-v4/RUN.md)) | DeepSeek V4, open weights under MIT: `deepseek-flash` (fast) and `deepseek-v4-pro` (deep), measured through the hosted API | `corpus_v1`, 520 generated Wazuh alerts (synthetic) | **current** |
| [v1, qwen2.5 7B on Ollama](v1/qwen2.5-7b/scorecard.md) | `qwen2.5:7b` (local, Ollama) | synthetic and phishing sets (103 hand-written alerts) | history |

**v2 in one line.**
* **Misses.** 0 of 208 malicious alerts were closed without a human (95% CI
  0.0% to 1.8%).
* **Closes.** 0 of 312 benign alerts were closed by automation. Every benign
  alert went to an analyst or to an approval request: 33 (10.6%) got a
  response plan, and none of its actions ran.
* **Cost.** $1.47 for the run.

[RUN.md](v2/deepseek-v4/RUN.md) traces which routing gate held each benign
alert and lists the changes to test next.
[CALIBRATION.md](v2/deepseek-v4/CALIBRATION.md) (AI-E1.9) tests them offline
against the recorded decisions and the fake-model sets, and records the policy
chosen; it is a simulation, not a new model run. A self-hosted copy of the weights
is how a client runs this model; customer data never goes to the hosted API.

## Generating one

Run the evaluation once per dataset with the same settings, then:

```sh
lg-sotf eval-scorecard synthetic.json phishing.json \
    --output scorecard.md --json scorecard.json \
    --prompt-version "lg-sotf <commit>" \
    --note "Hardware: ..."
```

* All reports must come from the same provider and models; the command
  refuses to mix them.
* `--prompt-version` names the prompts when the reports do not record them.
  Once reports carry prompt hashes (AI-E1.2), the scorecard shows those.
* `--note` adds a limitation line (repeatable): the hardware, a subset, a
  known problem in the run.
* `--internal` marks the scorecard **internal only**. It is automatic for
  a DeepSeek model whenever any dataset is not marked synthetic, because the
  hosted API is in China and customer data must never go there. A DeepSeek
  run on synthetic data only is publishable: no customer data was sent,
  and the open weights can be self-hosted.

The command reads files only; it needs no database or model.

The nightly workflow generates one this way from the synthetic and phishing
sets, with a pinned EU or local model, and keeps it as the `eval-scorecard`
artifact of the run ([evaluation.md](../evaluation.md#evaluation-gate-in-ci)).
Those nightly scorecards are not committed.

## The template

Every scorecard has the same sections, in this order.

1. **Header.** Provider, fast and deep model IDs, prompt version (or "not
   recorded"), lg-sotf version, when the reports were generated.
2. **Headline: closure.** Two numbers per dataset: the *benign closure
   rate* (expected-benign items automation closed as benign, with `k` of `n`
   and a 95% Wilson interval) and *malicious auto-close* (expected-malicious
   items automation closed with any disposition, with `k` of `n` and the
   exact one-sided 95% upper bound). Then the closes per mechanism (rules,
   model, history, verdict cache, suppression, response) and the IDs of every
   malicious item closed ([evaluation.md](../evaluation.md#the-headline-closure)).
3. **Malicious false-negative rate.** Expected-malicious items
   automation closed as benign without a human, for each dataset and each
   split, as `k` missed of `n` with the rate and a 95% Wilson score interval,
   followed by the IDs of the missed items. An escalated malicious item is not
   a miss: a human sees it.
4. **Automation.**
   * *Auto-close precision*: of the items automation closed on its own, the
     share whose closing disposition matches the expected one.
   * *Auto-close rate*, *escalation rate* (analyst review requested),
     *approval requests* (response actions waiting for approval) and *errors*.
   Each with counts and a 95% Wilson interval.
5. **Per class.** Precision and recall (each with counts and a 95% Wilson
   interval), F1, support and predicted count for `malicious`, `benign` and
   `inconclusive`, plus macro F1. The predicted
   disposition of an escalated item is the analysis verdict (`inconclusive`
   without one), as in the eval report.
6. **Cost and latency per item.** Mean cost, total cost, tokens and LLM calls
   per item; latency mean, p50, p95 and max from ingestion to the run's stop.
   Local models are metered at $0: their cost is the hardware.
7. **Datasets.** Path, sha256 prefix, items, scored items, synthetic flag,
   splits.
8. **Limitations.** Generated from the reports (synthetic data, small
   samples, unreviewed escalations, subsets, errors, missing prompt versions)
   plus the `--note` lines.

## Reading the intervals

The hand-written sets are small (35 and 24 expected-malicious items). With
0 misses out of 35, the 95% interval still reaches 9.9%: the data cannot
show that the true miss rate is below 1 in 10. `corpus_v1` has 208
malicious items, so 0 misses bound the rate below 1.8%. Treat two scorecards as different
only when their intervals do not overlap, and gate releases on the per-item
results (`--thresholds`, `--baseline`), not on a scorecard.

## Reproducing a scorecard

`v2/deepseek-v4/` holds the eval report (`corpus_v1.json`), the scorecard,
its JSON form, [RUN.md](v2/deepseek-v4/RUN.md), the decision inputs
recovered from the alert timelines (`decision_inputs.json`) and
[CALIBRATION.md](v2/deepseek-v4/CALIBRATION.md).
`tests/unit/eval/test_scorecard_v2.py` regenerates the scorecard from the
committed report and fails if they disagree; `tests/unit/eval/test_calibration.py`
checks the simulator reproduces every recorded decision.

`v1/<model>/` holds the two eval reports, the scorecard and its JSON form.
`tests/unit/eval/test_scorecard_v1.py` regenerates the scorecard from the
committed reports and fails if they disagree. The run itself is described in
the scorecard's limitations and in [v1/qwen2.5-7b/RUN.md](v1/qwen2.5-7b/RUN.md).
