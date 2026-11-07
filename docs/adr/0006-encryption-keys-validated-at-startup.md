# 0006. Validate the encryption keys at startup in every process role

* Status: accepted
* Date: 2026-11-07
* Roadmap step: D7 ([refactor roadmap](../design/refactor-roadmap.md), Phase 3)

## Context and problem

`security.encryption_keys` (Fernet) decrypts every stored credential: source
credentials, tenant webhook secrets, ticketing and Microsoft integration
secrets, tenant enrichment API keys and TOTP secrets.

The API built its `SecretBox` once at startup (`load_secret_box`, F11) and
refused to start when a key was set but invalid. The worker and the
scheduler did not: five components built their own box on first use
(`OutboxDelivery`, `TicketService`, the enrichment `CredentialResolver`,
`ResponseService.secret_box()` and `ConnectorRegistry`), each with its own
reaction to an invalid key (`None`, an error log, or a
`ConnectorConfigError` per action). A typo in the key therefore surfaced
hours later as failed response actions, undelivered notifications and
sources that could not poll, while the processes reported healthy.

## Decision

* The `SecretBox` is built once per process by its composition root and
  injected: `api/app.py` (`build_context`), `runtime/worker.py`
  (`run_worker` -> `WorkflowEngine.create`), `runtime/scheduler.py`
  (`run_scheduler` -> `Scheduler`), and `cli.py` for a command that needs
  one.
* `load_secret_box(settings)` returns `None` if and only if no key is set,
  and raises `SecurityConfigError` when a key is set but unusable. No root
  catches it: the API, the worker and the scheduler refuse to start on
  invalid keys, and the CLI reports the error and exits non-zero.
* Components never build a box themselves. Each keeps its documented
  contract for a missing box: `None` (the secret cannot be read, which the
  caller reports) or a configuration error.
* `SecretBox.from_settings` and `load_secret_box` are called only from
  `security/crypto.py`, `api/app.py`, `runtime/*.py` and `cli.py`; an
  architecture test (`tests/unit/architecture/test_composition_roots.py`)
  enforces it.

## Consequences

* An invalid key stops a rollout at the first pod instead of failing
  actions and deliveries later; a missing key still starts the process
  (development installs run without one), with encrypted values unreadable.
* Tests and tools that need decryption pass a box explicitly.
* Rotation is unchanged (`docs/operations.md`): every listed key must be a
  valid Fernet key in every role.

## Alternatives considered

* **Keep lazy loading, log loudly.** The first D7 step did this to find
  the remaining callers; it still lets a misconfigured worker take work it
  cannot finish.
* **Run without a box on invalid keys.** What the worker and scheduler did
  before; the failure is only visible per action, per tenant.
