# 0004. Declare each domain vocabulary once, as a `Literal`; migrations stay frozen

* Status: accepted
* Date: 2026-11-06
* Roadmap step: F2 ([refactor roadmap](../design/refactor-roadmap.md), Phase 1)

## Context and problem

The value sets of the domain (roles, scopes, severities, alert, action, run
and escalation statuses, dispositions, decisions, risk levels, autonomy
modes, verification states, source types, routes and the actor strings
`policy:auto` and `agent:workflow`) were declared 6 to 14 times each:
severity alone in about 12 places, across `db/repos`, `api`, `mcp`,
`services`, `core`, `queue`, `integrations` and `eval`. Derived subsets were
copied too (`BENIGN_DECISIONS` 4 times, `SEVERITY_RANK` 3 times,
`HIGH_SEVERITIES` 3 times; `ENDED_RUN_STATUSES` repeated
`TERMINAL_RUN_STATUSES`). Two copies of the push-only source types already
drifted once in production: the scheduler polled push-only `guardduty`
sources (`tests/unit/ingestion/test_push_source_types.py`). Role order
differed between copies: `users.ROLES` and the CLI listed
`admin, analyst, viewer`, the principal ranked `viewer, analyst, admin`.

## Decision

* **One declaration per vocabulary** in `lg_sotf.models.vocabulary`: a
  `Literal` type and the tuple of its values in canonical order, derived
  from it (`ALERT_STATUSES = get_args(AlertStatus)`), with the derived
  subsets beside it (`ROLE_RANK`, `REVIEWER_ROLES`, `SEVERITY_RANK`,
  `HIGH_SEVERITIES`, `BENIGN_DECISIONS`, the terminal and completed action
  statuses, `TERMINAL_RUN_STATUSES`, `PUSH_SOURCE_TYPES`, the execution
  owners and the actor constants). Only sets shared across packages go
  there; a value set private to one module stays in it.
* **Canonical order is lowest first**: roles `viewer, analyst, admin`,
  severities `info` to `critical`, escalation levels `L1` to `L3`. Ranks are
  derived from that order.
* **Every other module imports from it.** Existing public names (for
  example `lg_sotf.db.repos.alerts.SEVERITIES`, `api.schemas.Role`,
  `mcp.tools.LEVELS`) stay as re-exports bound to the vocabulary objects, so
  importers and tests keep working.
* **`Literal`, not `StrEnum`.** Workflow state is checkpointed by LangGraph,
  whose serializer records an `Enum` member by its import path: persisted
  checkpoints would then depend on module names and break on the next move.
  A `Literal` value is a plain `str` everywhere: in JSON, in the database, in
  checkpoints and in the OpenAPI schema (whose enums keep their order).
* **The module is a leaf**: standard library only, no `lg_sotf` import
  (import-linter contract `vocabulary-is-leaf`), and it is on the mypy strict
  list. Packages below `models` (`settings`, `security`, `observability`,
  `net`, `errors`) cannot import it; their copies (the OIDC role fields and
  `Autonomy` in `lg_sotf.settings`) stay and are pinned by the test below.
* **Migrations are frozen.** A migration records the schema at its revision
  and never imports the vocabulary: a later change to a vocabulary needs a
  new migration that widens or narrows the `CHECK` constraint, not an edit
  of an old one.

## Consequences

* `tests/unit/models/test_vocabulary.py` compares every remaining
  redeclaration and re-export with the vocabulary, as sets (`ROLE_RANK` and
  `SEVERITY_RANK` as orders). A new copy belongs in that list, or better is
  an import.
* `tests/integration/db/test_vocabulary_constraints.py` reads the live
  `CHECK` constraints (`pg_get_constraintdef`) on `alerts`,
  `response_actions`, `escalations`, `analyst_feedback`, `sources`, `users`,
  `api_keys`, `integrations` and `notification_outbox` and compares their
  value lists with the vocabulary: adding a value without a migration fails
  CI.
* `users.ROLES` and the `lg-sotf create-admin --role` choices now list roles
  in the canonical order, which changes the wording of the "role must be one
  of" error and of the CLI help (CHANGELOG).
* A list whose order is part of an output and differs from the canonical
  one (the evaluation dataset's `close, escalate, plan_response` routes,
  whose order shows in its validation errors) keeps its order; the test
  pins its values.

## Alternatives considered

* **`StrEnum`.** Typed members and exhaustiveness checks, but the
  checkpoint serializer stores members by import path (above), and every
  API, JSON and SQL boundary would need `.value` conversions.
* **Generate the vocabulary from the database `CHECK` constraints.** The
  database is not available to the unit tier, the import or the MCP client;
  comparing them in an integration test gives the same guarantee.
* **Keep the copies and only test them.** The test would catch drift, but
  every new value would still need edits in up to 14 places.
