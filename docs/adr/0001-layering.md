# 0001. Layering, the dependency rule and accepted exceptions

* Status: accepted
* Date: 2026-11-05
* Roadmap step: G2, G3 ([refactor roadmap](../design/refactor-roadmap.md), section 1.1)

## Context and problem

`docs/architecture.md` listed packages but no dependency direction. The import
graph had four package cycles (agents↔core, core↔db, core↔services,
integrations↔services) and about 70 function-local imports whose only job was
to dodge them. `ingestion` doubled as the shared network layer for `llm`,
`integrations`, `services` and `mcp`. Nothing stopped a new upward import.

## Decision

Packages of `lg_sotf` belong to layers. An import may point only **down**:

| Layer (top to bottom) | Packages | May import |
|---|---|---|
| Entrypoints | `__main__`, `cli` | everything below |
| Interfaces | `api` \| `mcp` \| `eval` (independent of each other) | runtime and below |
| Process roles, composition root | `runtime` | core and below |
| Workflow engine | `core` | application and below |
| Application | `services` \| `compliance` \| `onboarding` \| `agents` \| `ingestion` | adapters and below |
| Adapters | `integrations` \| `tools` \| `llm` \| `queue` | audit and below |
| Audit | `audit` | db and below |
| Persistence | `db` | domain and below |
| Domain policy and ports (no I/O) | `domain` (created in roadmap Phase 2) | models and below |
| Value types and vocabulary | `models` | net and below |
| Network kernel | `net` (created in F3) | kernel |
| Kernel | `errors` : `observability` : `security` : `settings` (may import each other) | stdlib and third-party only |

`|` marks siblings that must not import each other; `:` marks kernel modules
that may. Extra rules:

* `api` never imports the workflow (`core.workflow`, `core.nodes`,
  `core.graph`, `agents`, `langgraph`): the API enqueues work, workers run it.
* `mcp` is a thin REST client of the API: no `db`, `queue`, `services`,
  `core`, `agents`, `llm`, `integrations`, `api`, `asyncpg` or `redis`.
* Application, adapter, audit and model packages never import database or
  workflow drivers (`asyncpg`, `psycopg`, `psycopg_pool`, `langgraph`)
  directly; those stay behind `db`, `core` and `runtime`.
* API routers do not import each other; shared code goes to `api/deps.py` or
  `api/common.py`.
* A package `__init__` eagerly imports only its own modules.
* No function-local import may exist only to dodge a cycle.

All of this is enforced by import-linter (`pyproject.toml`
`[tool.importlinter]`, `make import-lint`, the CI Lint job).

## Consequences

Today's violations are listed in `ignore_imports` as exact
`importer -> imported` pairs (no wildcards), grouped under the roadmap step
that removes them. An ignore that stops matching fails the check, so the list
can only shrink: each step deletes its lines in the same PR.

Accepted exceptions that stay:

* `lg_sotf.settings -> lg_sotf.llm.endpoint`, imported lazily inside
  `Settings.production_problems`: the fail-closed production check validates
  the LLM endpoint policy, and splitting that check into a second module would
  create two half-gates.
* `TYPE_CHECKING`-only imports (for example the `ResponseAction` type
  reference) are excluded from analysis (`exclude_type_checking_imports`):
  they have no runtime effect.

## Alternatives considered

* Renaming packages to match layers (for example `core` → `workflow`): churns
  every import for a name; rejected in the roadmap's "Not doing".
* Deprecation shims for moved modules: every importer lives in this repo, so
  a move rewrites its importers in the same PR instead.
