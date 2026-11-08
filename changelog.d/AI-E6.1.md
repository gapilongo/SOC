### Added

- An adversarial evaluation corpus, `tests/fixtures/eval/adversarial_v2.jsonl`:
  91 synthetic alerts that try to steer the model through log fields
  (persona and instruction hijacks in user names, command lines, URLs,
  user-agents, email subjects and bodies), through threat-intelligence and
  history answers, by asking for a response or a close, and with encoding
  tricks (Base64, look-alike letters, zero-width and other invisible
  characters, instructions split across fields), plus benign look-alikes
  such as the security team's own test strings. Its gate runs in CI with
  the fake model: no malicious alert of the adversarial split may be closed
  by automation and no benign one may be routed to a response.
- Evaluation items can now carry a `family`, an `injection` spec (what the
  injected text asks for) and `tool_fixtures` (canned threat-intelligence
  and history answers, used only by `lg-sotf eval`). Reports add a
  per-family table with each rate's sample size and 95% interval, and three
  rates: `malicious_auto_close_rate`, `benign_escalation_rate` (false
  escalations) and `injection_followed_rate` (how often the model did what
  injected text asked). Thresholds can check `families.<name>.<metric>`.
  Reports of datasets without families are unchanged apart from the three
  new rates.
