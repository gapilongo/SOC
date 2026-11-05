# 0000. Record architecture decisions

* Status: accepted
* Date: 2026-11-05

## Context and problem

Decisions about structure lived in prose (`docs/architecture.md`), in PR
descriptions and in chat. The next engineer could not tell which constraints
are deliberate, which are accidents, and which are enforced.

## Decision

Architecture decisions are recorded as numbered MADR files in `docs/adr/`, in
the same PR as the change they govern. An accepted ADR is not rewritten; a new
ADR supersedes it. Rules an ADR states are enforced in CI wherever a tool can
check them (import-linter, ruff, the tests in `tests/unit/architecture/`).

## Consequences

Reviewers can point to a rule and its reason. Changing a rule means writing a
new ADR, which makes the change visible.
