### Added

- Scorecard v2 (`docs/scorecards/v2/deepseek-v4/`): DeepSeek V4, whose
  weights are released under MIT (`deepseek-flash` fast tier,
  `deepseek-v4-pro` deep tier), on the 520-alert attack-emulation corpus.
  It was measured through DeepSeek's hosted API on synthetic alerts only; a
  client self-hosts the same weights, and customer data never goes to the
  hosted API.
  - **Misses:** 0 of 208 malicious alerts closed without a human (95% CI 0.0%
    to 1.8%), in every log source and campaign.
  - **Closes:** 0 of 312 benign alerts closed by automation. 33 benign
    alerts were given a response plan, and none of their actions ran.
  - **Cost:** $1.47 for the run.
  - **RUN.md** traces which routing gate held each benign alert and lists the
    changes to test next.

### Changed

- `lg-sotf eval-scorecard` marks a DeepSeek scorecard internal-only only
  when one of its datasets is not synthetic. A run on synthetic data only is
  publishable. Real alerts must still never go to DeepSeek's hosted API.
