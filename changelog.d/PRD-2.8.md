### Added

- Investigation view: every alert now opens on a full page
  (`/alerts/<id>`, "Open full page" in the alert's side panel) that explains
  the AI's decision in the same order for every alert. First the outcome in
  one of four categories tied to what happens next (closed by AI; closed by
  AI, sampled for audit; needs your decision: likely malicious; needs your
  decision: unsure), the verdict as a sentence, and why the alert is with a
  person or why it was closed. Then the alert's description and its
  entities; the claims of the analysis, each beside what the lookup it names
  returned, with the provider's verdict highlighted; what is not established,
  in three kinds (checked and found nothing, not checked, could not check
  for this customer); the steps of the investigation in plain words; and the
  proposed response with the exact target of every action.
- The page keeps three voices apart: what a tool returned (monospace on a
  recessed surface, with its outcome), what the model wrote, and what a
  check, the policy or a person decided. A claim that names no lookup, or
  only a lookup that returned nothing, is marked **Unsupported**: nothing
  found is never counted as proof.
- A decision bar stays at the bottom of the page: `T`, `B` or `F` chooses the
  verdict, the bar says what that verdict sets in motion (which ticked
  actions run, how many wait for approval) before anything is recorded, and
  `Ctrl+Enter` records it and opens the next escalation. The rules are those
  of the decision page: a claim first, a note for a true positive, and your
  verdict and note are kept when someone else changed the escalation.
  Single-key shortcuts act only outside text fields and can be switched off
  in the bar.
- **Hide the verdict** (`V`) withholds the verdict, the claims and the
  model's assessment so you can judge from the evidence first; an alert in a
  blind-audit sample always opens this way.

Not shown yet, and said so on the page instead of being filled in: the
track record of each outcome (how often analysts confirmed it), the hash of
each observation, how many hosts or users an action reaches, and the
"needs more information" verdict in the decision bar.
