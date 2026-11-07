# 0013. Read configuration only through `lg_sotf.settings`

* Status: accepted (recorded after the fact; the lint ban dates from roadmap G4)
* Date: 2026-11-06
* Roadmap step: Q5 ([refactor roadmap](../design/refactor-roadmap.md), Phase 8)

## Context and problem

The product runs as an API, workers, a scheduler, migrations and CLI
commands, from compose, Helm, VMs and a self-hosted PC. Each reads secrets
(database URLs, JWT secret, encryption keys, LLM keys) and limits. A module
that reads `os.environ` itself bypasses validation, the precedence rules and
the production safety checks; a module that calls `get_settings()` deep in
the call graph cannot be tested with explicit settings and hides a global
dependency.

## Decision

* **One reader.** `lg_sotf.settings.Settings` (pydantic) is the only code
  that reads the environment, `.env` and the optional YAML file
  (`LG_SOTF_CONFIG_FILE`). Variables are `LG_SOTF_<SECTION>__<KEY>`; the
  standard `DATABASE_URL`, `REDIS_URL` and provider API keys apply only when
  nothing else sets the value. Ruff `TID251` bans `os.environ`, `os.getenv`
  and `os.putenv` everywhere else (`pyproject.toml`).
* **Settings are passed, not fetched.** `get_settings()` is called only in
  the composition roots (`cli.py`, `api/app.py`, the `runtime/*.py`
  entrypoints and `settings.py`), checked by `test_data_access.py` against an
  empty shrink-only baseline (`tests/unit/architecture/get_settings_baseline.txt`).
  Components take a `Settings` (or their section) as a required parameter,
  in their constructor or call. The one other entrypoint, alembic's
  `db/migrations/env.py` when alembic is run by hand, builds its own
  `Settings()` and passes `.database` down.
* **Fail closed at startup.** Every process calls `settings.assert_safe()`;
  in `staging` and `production` it refuses missing secrets, the fake LLM,
  wildcard CORS, insecure cookies and the development database password.
* **Tests build settings explicitly**: `make_settings(**overrides)` (no
  `.env`, test environment, fake LLM) or `settings_env(...)`, and the cached
  settings are reset around every test (`tests/conftest.py`).

## Consequences

* One place documents every key (`docs/configuration.md`) and validates it.
* A new option is a field on `Settings`, never an ad hoc variable; a module
  that needs it receives it from its caller.
* Accepted exception: `settings -> llm.endpoint`, so that settings can
  validate LLM endpoints ([ADR-0001](0001-layering.md)).

## Alternatives considered

* **Each package reads its own variables.** Less plumbing, but no single
  validation, precedence or production check, and tests leak through the
  process environment.
* **A global settings object imported everywhere.** Equivalent to calling
  `get_settings()` everywhere: hidden dependencies and tests that need
  monkeypatching instead of arguments.
