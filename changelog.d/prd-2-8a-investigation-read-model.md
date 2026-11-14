### Added

- `GET /api/v1/alerts/{id}/investigation` (beta): one read model that
  explains the AI's decision on an alert, for the console's new
  investigation view. It only reads stored data: it calls no model and
  writes nothing.
  - **Outcome:** one of four categories tied to what happens next (closed
    by the AI on evidence; closed on the model's word and sampled for
    audit; needs your decision, likely malicious; needs review, not proven
    either way), the reason in plain words, why the AI may not close the
    alert on its own, and who or what closed it (the AI, a suppression
    rule, a cached analyst verdict or an analyst).
  - **Summary, claims and observations:** the conclusion, marked as written
    by the model or by the rules; each claim with what it points to and
    the lookups it rests on; each lookup with a typed outcome (`success`,
    `empty`, `failed`), a bounded excerpt and, where the trace store has
    the call, its input and output hashes.
  - **What is not established:** checked and found nothing; not checked;
    could not be checked for this customer. An empty or failed lookup never
    backs a claim.
  - **Steps, track record and response:** what the investigation did in
    plain words; how often people confirmed this outcome category for the
    tenant over 90 days, as counts, with a rate only from 30 verdicts on;
    and the proposed actions with their exact targets.
  - `pending_harness` names the fields that stay empty until the
    investigation harness fills them (highlight ranges, the model's
    citations, the checker's verdicts), so the view can say so.
  - Text an attacker can shape (claim texts, targets, excerpt lines) is
    returned as data, cut to a stated length, and never put into a
    sentence. An alert that waits for its blind-audit label shows nothing
    of the AI's side.
