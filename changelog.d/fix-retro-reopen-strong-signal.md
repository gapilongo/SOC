### Fixed

- The safety net of AI closure no longer treats a merely *suspicious* alert
  as a threat. An escalation reopens the related AI-closed alerts only when
  a model judged it a threat (deep verdict malicious, or fast tier
  likely_threat or confirmed_threat), next to the unchanged paths: a
  response plan, an analyst true positive and a blind-audit malicious label.
  On a realistic alert mix this had reopened 23 of 40 AI closes without a
  single real attack behind them (#352).
