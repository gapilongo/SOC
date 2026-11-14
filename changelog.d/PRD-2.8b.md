### Changed

- Investigation view (`/alerts/<id>`): the page now reads the investigation
  read model (`GET /alerts/{id}/investigation`) instead of rebuilding it in
  the browser, so it shows what the API knows:
  - the **track record** of the alert's outcome, as counted squares ("Analysts
    confirmed 31 of 34 alerts sent to a person as likely malicious"), a bar
    above 60 alerts, and the words "too few for a rate" under 30. Never a
    percentage;
  - **why the AI may not close the alert on its own** (the closure policy's
    blockers), and for an alert the AI closed on evidence, the approved
    benign signals the rules found;
  - who or what closed an alert, with the rule's name, the analyst's
    decision, the earlier alert a cached verdict came from, and the time;
  - claims in the model's own words, and claims the rules derive from a
    lookup, marked as the rules';
  - each observation with its sources, its verdict and, where the trace
    store has the call, its hash;
  - the response as it stands: what a true positive would propose now, or
    the actions on the ledger with their status.
  "Not yet available" is now said only for what the read model lists as
  pending, in its own words. The "Reach" column is gone until the API
  returns a reach.
- An API that does not serve the read model yet (it answers 404) still
  gets the page: it is built from the alert, its escalation, its timeline
  and the response preview, as before.

### Added

- Decision bar: **Needs more** (`N`) records `needs_more_info`. The bar says
  what that does today before you record it: no verdict is recorded, the
  analysis runs again and reads your note (once per alert by default), then
  the alert comes back to an analyst as a new escalation, and no response
  action runs. The bar asks for the note.
- Investigation view: an entity chip (host, user, address, domain, hash)
  opens the alert list searched for that value. The search is the list's
  title search over the last 30 days; the API has no entity filter yet.
