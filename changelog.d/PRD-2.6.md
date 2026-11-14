### Fixed

- Decision page: every action in the expected response plan of a true
  positive now names its exact target (the process, host, user or address,
  as the API gives it), next to its risk and whether it can be undone, as
  the Approvals page does. Before, the list showed only the action's
  description, so two actions of one type ("Terminate a process through
  EDR") could not be told apart and an analyst could pre-approve an action
  without seeing what it acts on.
- An action the plan sends without a target can no longer be pre-approved
  from the decision page: its checkbox is disabled, it says why, and it is
  left for the Approvals page.

### Changed

- Decision page: the expected response plan is shown under the
  investigation instead of inside the decision form, so "Record decision"
  stays in view. The form says how many actions are pre-approved.
