### Added

- **The case page** (`/cases/<id>`): one case, its alerts, and who or what
  closed each one and why. A case is the escalation with its alerts, and its
  id is the escalation's id. The page answers "what did the AI close on this
  host while this case was open, and why" in one place.
  - **Alerts, oldest first,** each with its state and who closed it: the AI
    on approved evidence, the AI on the model's word, a suppression rule, an
    earlier analyst verdict, or an analyst. Beside it is the recorded
    reason: the rule of the decision policy and the closure tier for an AI
    close, the blind-audit result, the analyst's decision and note.
  - **Linked by the safety net:** alerts the AI closed that were linked to
    the case and left closed, with why; and alerts that were reopened, with
    who or what confirmed the threat.
  - **Response:** the actions on the ledger with their status (waiting for
    an approval, blocked by a guardrail with its reason, ran, failed, dry
    run). An action that waits is approved or rejected here, by the rules of
    the Approvals page.
  - **Timeline and entities:** the case's and its alerts' events in one
    list, in plain words, and what the alerts share (hosts, users, addresses).
  - **Decision:** the decision bar of the investigation view records the
    decision on the case (T, B, F, N, a note, Ctrl+Enter). J and K move
    through the alerts and Enter opens one; they follow the single-key
    switch.
- `GET /api/v1/cases/{id}` (beta): the read model behind the page. It only
  reads stored data. `not_available` names what the stored data cannot say
  yet (a readable case reference, a case summary, flagging an alert for
  audit, a reason on an approval), and those fields are absent, never
  estimated. An alert that waits for its blind-audit label shows what its
  source sent and nothing of the AI's side.

### Changed

- A row of the **Queue** opens the case page. The older decision page
  (`/escalations/<id>`) still opens from the Escalations list and from
  existing links.
- The investigation view names the alert's case in its breadcrumb, as a
  link to the case page, also for an alert the safety net linked to a case.
