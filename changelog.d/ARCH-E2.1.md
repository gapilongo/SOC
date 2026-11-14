### Added

- A CI gate, `eval-gate`: every pull request runs the synthetic and phishing
  evaluation sets with the offline fake model and compares the result with a
  committed baseline (`tests/fixtures/eval/baselines/`). One more missed
  attack, or one fewer benign alert closed, than the baseline fails the
  build, and the log names every item that ended differently. The job calls
  no model and reads no secret. `make eval-gate` runs it locally;
  `make eval-baselines` records the baselines again after an intended change.
- A nightly evaluation with a real model: both sets run through one pinned
  model and the scorecard is kept as a workflow artifact for 90 days. The
  model is set with repository variables and one secret
  (`EVAL_LLM_PROVIDER`, `EVAL_LLM_BASE_URL`, `EVAL_LLM_FAST_MODEL`,
  `EVAL_LLM_DEEP_MODEL`, `EVAL_LLM_API_KEY`); the job is skipped until they
  are set. Only a model hosted in the EU or run locally is accepted, and
  only with exact model names. See "Evaluation gate in CI" in
  docs/evaluation.md.

### Changed

- The regression checks of `smoke_thresholds.yaml` and
  `phishing_smoke_thresholds.yaml` are exact for the benign auto-close rate
  (`max_decrease: 0`, was 0.05). They apply only when a run is compared with
  a baseline.
