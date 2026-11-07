# Testing

How the test suite is organised, how to run it, and the rules that keep it
fast, isolated and trustworthy. Architecture decisions behind the
integration setup: [ADR-0011](adr/0011-rls-per-tenant.md) (row-level
security and the runtime role), [ADR-0012](adr/0012-redis-streams-queue.md)
(the work queue) and [ADR-0013](adr/0013-configuration-through-settings.md)
(configuration).

## Quick start

```bash
make dev                 # pinned dev dependencies, the package in editable mode
make test-fast           # unit + deploy tiers: no database, no Redis (about two minutes)
make test-services       # PostgreSQL 16 on :55433 and Redis 7 on :56380, tmpfs, same role as CI
make test-integration    # the integration tier against those services
make test-services-down
```

`make test-integration PYTEST_ARGS="-n 4 --dist loadfile"` runs the
integration tier on four workers. `make test-serial` and `make test-parallel`
run the whole suite and read `LG_SOTF_TEST_DATABASE_URL` and
`LG_SOTF_TEST_REDIS_URL` from your environment; with neither variable set,
integration tests are skipped, never failed.

One test, one file, or a keyword:

```bash
python -m pytest tests/unit/api/test_ratelimit_oidc_settings.py::test_fixed_window_counts_and_resets -q
python -m pytest tests/integration/runtime -k lease -q      # needs the two variables
```

## Tiers

| Tier | Path | Needs | Rules |
|---|---|---|---|
| Unit | `tests/unit` | nothing | Hermetic. **Every warning is an error** (`tests/unit/conftest.py`), with no ignore list. A unit test that requests `db`, `repos`, `redis_client`, `redis_url`, `database_url` or `migrated_database_url` fails collection: the fast CI job has no services, so it would never run. |
| Deploy | `tests/deploy` | optional `helm`, `docker` | Packaging: Dockerfile, compose files, Helm chart, CI workflows, deploy scripts. Tests needing a missing binary skip. |
| Integration | `tests/integration` | PostgreSQL 16, Redis 7 | Real services, the real app, the real worker and workflow engine, the fake LLM. |

Suite-wide (`pyproject.toml`): `RuntimeWarning`, `ResourceWarning` and
`PytestUnraisableExceptionWarning` are errors everywhere; `--strict-markers`;
`asyncio_mode = "auto"`.

CI (`.github/workflows/ci.yml`) runs `lint` (ruff, mypy, import contracts),
`fast` (unit + deploy, no services), and `test` (the whole suite with
coverage, one process; the total floor and the per-package floors in
`scripts/ci/coverage_floors.py` only go up). `test-parallel` runs the suite on
four xdist workers and `parallel-parity` checks that both runs saw the same
tests with the same outcomes; both are non-blocking until about ten green
runs. `.github/workflows/nightly.yml` runs the suite in a random order
(pinned `pytest-randomly`).

`upgrade` runs `scripts/ci/upgrade_rehearsal.sh`: the previous release (the
latest `v*` tag) runs in a git worktree on its own venv, migrates a fresh
database and leaves alerts waiting for an analyst and an approval; this
checkout then migrates the same database as the schema owner and must resume
and close every waiting run through its API (no failed or dead-lettered run,
no `UnknownGraphVersion`), with the runtime role's privileges unchanged. It
starts its own PostgreSQL and Redis from `docker/docker-compose.test.yml`
(project `lgsotf-upgrade`, ports 55491 and 56391) and removes them afterwards.
Locally: `UPGRADE_NEW_PYTHON=.venv/bin/python scripts/ci/upgrade_rehearsal.sh`
(`--from <ref>` picks another N-1).

## The test services

The integration tier needs a **plain** PostgreSQL role: superusers and roles
with `BYPASSRLS` skip row-level security, and `tests/integration` refuses
them. `scripts/ci/create_test_role.sql` creates the role
(`NOSUPERUSER NOBYPASSRLS CREATEDB`) and its database; CI and
`docker/docker-compose.test.yml` both run that file (a deploy test checks it).

* The database is reset (schema dropped) and migrated **once per session**,
  then truncated before every test that uses `db` (`truncate_all`). The
  database name must contain `test`.
* The Redis database is flushed before and after every test that uses
  `redis_client`.
* Under `pytest -n N`, worker `gw<k>` uses the database `<name>_gw<k>`
  (created when missing, which is why the role has `CREATEDB`) and the Redis
  database `base + k`, refused above 15. With base 5 and four workers that is
  5 to 8.

## Fixtures and helpers

Fixtures live in conftests; **helpers live in `_support.py` modules**. A test
never imports a `conftest` or another `test_*` module
(`tests/unit/architecture/test_test_suite.py` enforces it): move the helper
into the nearest `_support.py` instead.

| Where | What |
|---|---|
| `tests/conftest.py` | `make_settings(**overrides)` (explicit `Settings`, test environment, fake LLM, no `.env`), `settings_env(...)`, `unique_prefix`, and the autouse reset of cached settings, chat models and usage. |
| `tests/integration/conftest.py` | `database_url`, `migrated_database_url`, `checkpointed_database_url` (plus LangGraph's checkpoint tables), `db`, `repos` (tenants `tenant-a` and `tenant-b` exist), `redis_url`, `redis_client`, the API harness (`api_settings`, `api_clock`, `make_api`, `api`) and `microsoft_env`. Its `make_settings` defaults `redis.key_prefix` to `unique_prefix` and fails any other prefix. |
| `tests/integration/_support.py` | Per-worker database and Redis URLs (xdist). |
| `tests/integration/db/_support.py` | `TENANT_A`, `TENANT_B`, `new_alert`, `make_alert`, `db_settings`, `ALL_TABLES`, `truncate_all`, `seed_everything` (a row in every tenant table). |
| `tests/integration/api/_support.py` | `ApiHarness` (`user`, `login_headers`, `auth`, `api_key`, `key_headers`), `ApiClock`, `PASSWORD`, MFA (`TotpClock`, `enroll`, `challenge`, `code_now`) and OIDC helpers (`IdP`, `jit_api`, `jit_token`). |
| `tests/integration/e2e/_support.py` | `Stack` (ingest, dispatch, engine, worker), `running(worker)`, `eventually(predicate)`, shared events. |
| `tests/integration/runtime/_support.py` | `FakeEngine`, `make_worker`, `dispatch_alert`, `running`, `eventually`, `ManualClock`. |
| `tests/integration/integrations/_support.py`, `.../microsoft/_support.py` | `Receiver` (scripted HTTP receiver), `add_integration`, `MicrosoftEnv`. |
| `tests/fixtures/` | Vendor payloads, `FakeMicrosoft`, the evaluation datasets. |

## The fake LLM

No test needs a network or a model. `make_settings()` selects
`llm.provider = "fake"`: `lg_sotf.llm.fake.FakeChatModel` scores the alert
text with keyword heuristics and returns schema-valid structured output,
deterministically. To script exact answers (refusals, invalid or truncated
output, an obedient model for prompt-injection tests) use
`ScriptedChatModel(script={"TriageAssessment": [...], "*": [Refuse(...)]})`
and pass it to the agents through a `model_factory`
(`tests/integration/e2e/test_llm_safety.py`, `tests/unit/agents/_support.py`).

## Time

Tests do not wait for the wall clock when they can move a clock instead.

* **API rate limits**: `ApiHarness.clock` (an `ApiClock`) is frozen one second
  into a 60 s window, so a burst never straddles a minute boundary;
  `api.clock.advance(60)` opens the next window.
* **Worker and scheduler**: `Worker(clock=...)`, `Scheduler(clock=...,
  wall_clock=...)` and `oldest_undelivered_age_s(clock=...)` take a
  `ManualClock` (liveness, tenant activity windows, job intervals, backlog
  age). Production uses `time.monotonic` and `time.time`.
* **Real waits stay real** where the clock is not ours: Redis idle times and
  key TTLs, PostgreSQL `now()` and leases. Wait for them with
  `eventually(...)`, never a bare `sleep`, and wait for the condition the test
  asserts afterwards (run status, not only alert status).

## Timeouts

Every test fails after 120 s (`pytest-timeout`, signal method); the
process-level e2e and evaluation modules allow 300 s
(`pytest.mark.timeout(300)`). Inside a test, `eventually(...)` and
`running(worker)` have their own bounds (20 s in e2e, 8 s in runtime). Raise a
bound only with evidence that the wait is legitimately longer, never to make a
flaky test pass.

## Isolation rules

* Every Redis user in a test is namespaced by `unique_prefix`: pub/sub
  channels are shared by all Redis databases, so another worker would see the
  events otherwise.
* Every table a test can write is truncated between tests: a new table goes
  into `ALL_TABLES` (`tests/integration/db/test_truncation.py` fails until it
  does).
* No fixed ports: bind port 0. No cluster-global state (roles, databases)
  created by a test.
* Process-wide caches (settings, chat models, usage) are reset around every
  test by `tests/conftest.py`; reset any new one there too.
* Tests must pass in any order and on any xdist worker (the nightly job and
  `test-parallel` check both).

## Flaky tests

A test that fails and then passes on a rerun is a bug, in the test or in the
product, not noise.

1. Never retry automatically, never raise a timeout to hide it, never mark it
   `skip` or `xfail` without an issue that names the root cause.
2. Reproduce it: run it in a loop and under load (for example while
   `pytest -n 14 tests/unit` runs), with `-p randomly --randomly-seed=N` when
   the nightly job found it, and with `-n 4 --dist loadfile` when only the
   parallel job fails.
3. Find what the test waits for. Most flakes are a wait on the wrong
   condition, a real clock where an injectable one exists, or a shared name
   (Redis prefix, tenant, port).
4. Fix the cause and say in the commit message what it was.
