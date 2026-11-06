# 0011. Isolate tenants with PostgreSQL row-level security and a runtime role that cannot bypass it

* Status: accepted (recorded after the fact; the design dates from 1.0)
* Date: 2026-11-06
* Roadmap step: Q5 ([refactor roadmap](../design/refactor-roadmap.md), Phase 8)

## Context and problem

Every tenant's alerts, users, credentials, escalations, actions and audit log
live in shared tables. One query that forgets `WHERE tenant_id = $1`, in any
of the hundreds of repository methods or in LangGraph's own checkpoint
queries (which we do not write), would show one customer another customer's
data. An MSSP install makes that a contractual failure, not a bug.
Application-level filtering alone cannot be reviewed exhaustively, and a role
that owns the tables, is a superuser or has `BYPASSRLS` ignores any
database-level rule.

## Decision

* **Every tenant-owned table** has `tenant_id TEXT NOT NULL` and a
  `tenant_isolation` policy, with `ENABLE` and `FORCE ROW LEVEL SECURITY`:
  a row is visible and writable only when `tenant_id =
  current_setting('app.tenant_id', true)`. The LangGraph checkpoint tables get
  the same policy, keyed on the tenant part of `thread_id`
  (`"{tenant_id}:{alert_id}"`), and the checkpointer sets `app.tenant_id`
  before each statement (`db/checkpointer.py`).
* **Code enters a tenant only through a scoped transaction**:
  `db.tenant_tx(tenant_id)` (`SET LOCAL app.tenant_id`). Cross-tenant work
  (partition DDL, retention, sweeps) uses `db.system_tx()`, which sets
  `app.bypass_rls`; `lgsotf_rls_bypass()` honours it only when the session
  user is a member of the schema owner, so a runtime session that sets it
  gains nothing.
* **Two roles.** The owner (`database.migration_url`) runs `lg-sotf migrate`
  and the scheduler. The runtime role (`database.url`,
  `database.runtime_role`) runs the API and the workers: it owns nothing, is
  not a superuser, has no `BYPASSRLS` and is not a member of the owner;
  `grant_runtime_privileges` refuses a role that is any of those. Credential
  lookups that must happen before the tenant is known (user by email,
  refresh token or API key by hash) go through `SECURITY DEFINER` functions.
* **Defence in depth**: repositories still filter by `tenant_id` explicitly,
  and Redis keys carry `:t:{tenant_id}:`.
* **Tests run as a plain role.** `scripts/ci/create_test_role.sql` creates
  `NOSUPERUSER NOBYPASSRLS CREATEDB`; `tests/integration` refuses a role that
  would bypass RLS (`assert_rls_applies`), so every integration test runs
  under the policies.

## Consequences

* A missing `WHERE tenant_id` returns nothing instead of another tenant's
  rows; `tests/integration/db/test_rls.py` seeds a row in every tenant table
  (`seed_everything`) and checks reads, writes, moves between tenants,
  partitions and checkpoints. `tests/integration/db/test_runtime_role.py` and
  `tests/integration/api/test_runtime_role.py` run the product as the runtime
  role.
* Every new tenant table needs the policy in its migration and an entry in
  `TENANT_TABLES` and `ALL_TABLES` (the truncation test fails otherwise).
* `SET LOCAL` costs one statement per transaction, and code that needs
  several tenants opens several transactions.
* Single-role installs (development) use the owner role everywhere and so do
  not get the second line of defence; production configures both roles.

## Alternatives considered

* **Filtering in the application only.** Cheaper, but one forgotten clause
  leaks data, and LangGraph's checkpoint queries are not ours to review.
* **A schema or a database per tenant.** Strong isolation, but migrations,
  connection pools and cross-tenant sweeps grow with the number of tenants,
  and the LangGraph checkpointer expects one set of tables.
* **One role with `BYPASSRLS` for the scheduler and the API.** Simpler
  grants, but a single injection in the API would read every tenant.
