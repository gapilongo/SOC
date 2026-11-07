# Contributing to LG-SOTF

Thank you for helping. This project handles security telemetry and can
trigger containment actions, so changes are held to a high bar: tested,
documented, and safe by default.

Security problems: do not open a public issue; follow [SECURITY.md](SECURITY.md).

## Development setup

Requirements: Python 3.11+, PostgreSQL 15+ (16 recommended) and Redis 7+ for
integration tests, Docker for the image and stack tests, Node 22 for the web
application.

```sh
git clone https://github.com/gapilongo/SOC.git && cd SOC
python3.11 -m venv .venv && . .venv/bin/activate
make dev          # hash-locked dependencies from requirements-dev.txt, editable install (make lock re-locks)
pre-commit install --hook-type pre-commit --hook-type pre-push
make check        # what CI's lint and fast jobs run: ruff, mypy, import contracts, unit + deploy tests

# Integration tests, one command each: throwaway PostgreSQL and Redis in Docker (tmpfs, CI's role)
make test-services && make test-integration && make test-services-down

# Or your own services: dedicated databases whose names contain "test" (they are reset)
export LG_SOTF_TEST_DATABASE_URL=postgresql://soc:<password>@127.0.0.1:5432/soc_test
export LG_SOTF_TEST_REDIS_URL=redis://127.0.0.1:6379/5
make test         # the whole suite, one process (make test-parallel: four xdist workers)
```

[docs/testing.md](docs/testing.md) covers the tiers, helpers, clocks,
isolation rules and the flaky-test policy.

`make help` lists every target (image build, compose stack, smoke test, Helm
lint). The web application in `src/lg_front` has its own `npm` scripts; see
its README.

## Ground rules

* **Read the contract first.** `docs/architecture.md` is the system contract;
  when code and that document disagree, fix one of them in the same change.
* **Tests assert behaviour.** Every bug fix and every guardrail gets a test.
  Integration tests use real PostgreSQL and Redis; LLM paths use the `fake`
  provider (`lg_sotf.llm.fake`), never the network.
* **Safety first.** Changes to routing, response planning, guardrails,
  redaction, prompt construction or tenant scoping need a test for the unsafe
  case (for example: an injected alert must not close, a protected asset must
  not be acted on, another tenant's row must not be visible). Run the
  evaluation harness (`lg-sotf eval`, docs/evaluation.md) when you change
  routing thresholds, prompts or agents, and include the before/after report
  summary in the pull request.
* **Configuration** is read only in `lg_sotf/settings.py`. When you add or
  change a setting, describe it in `docs/tools/settings_reference.py` and run
  `python docs/tools/settings_reference.py --write`; a test fails otherwise.
* **Database changes** are Alembic migrations, expand/contract only (the
  previous release must keep working during a rolling upgrade). Every
  tenant-owned table gets `tenant_id` and the row-level security policy.
* **No secrets, no real customer data** in commits, fixtures or test output.
  Fixtures use documentation address ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24), `example.com` names and are marked synthetic. CI runs
  Gitleaks.
* **Dependencies** are pinned in `requirements*.txt`; explain why a new one
  is needed. CI runs `pip-audit` and Bandit.

## Style

* Ruff (`make lint`) with the rules in `pyproject.toml`, line length 120.
* Type hints everywhere. `make typecheck` runs mypy over every file listed in
  `pyproject.toml` (`[tool.mypy] files`) with `disallow_untyped_defs` and
  `warn_return_any` on; a new leaf package also joins the strict override list.
* The architecture is enforced: see `docs/design/refactor-roadmap.md` for the
  layer rules, size budgets and data-access ratchets, and `docs/adr/` for the
  decisions behind them.
* Structured logging through `lg_sotf.observability.logging.get_logger` with
  event names (`component.event`) and keyword fields; never log secrets or
  raw alert bodies at INFO.
* Documentation in plain English, no marketing claims: describe what the
  code does today.

## Pull requests

1. Branch from `main`, keep the change focused, write clear commit messages.
2. Fill in the pull request template: what changed, why, how it was tested,
   and the security and operational impact.
3. CI must pass: lint and types, unit and integration tests (including the
   smoke evaluation), security scans, image build and Helm validation.
4. For user-visible changes, add a changelog fragment in `changelog.d/` (see
   `changelog.d/README.md`; don't edit `CHANGELOG.md` directly), and update the
   relevant document in `docs/`.

## Reporting bugs and requesting features

Use the issue templates. For bugs include the version (`lg-sotf version`),
deployment mode, the relevant settings (never secrets), logs with request
ids, and steps to reproduce.

## License

By contributing, you agree that your contributions are licensed under the
project's license (see [LICENSE](LICENSE)).
