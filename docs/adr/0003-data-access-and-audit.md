# 0003. Keep SQL in repositories, let services own transactions, audit in the same transaction

* Status: accepted
* Date: 2026-11-06
* Roadmap step: D1 (audit), D2 (provisioning); D4 and D5 finish the SQL and transaction rules ([refactor roadmap](../design/refactor-roadmap.md), Phase 3)

## Context and problem

`AuditLogger.record` promised that an action whose audit entry cannot be
written is not reported as done. 34 of its 54 calls passed no connection, so
the entry was written in a transaction of its own after the change had
committed: an audit failure answered 500 while the change stayed, with no
trace in the hash-chained log. The scheduler wrote SLA-breach entries with
`repos.audit.append` directly, skipping redaction and the log line. Tenant
provisioning ran up to seven transactions: a failure after the first left a
tenant without its admin, and a retry answered 409. About 35 queries lived
outside `db/`, and 14 router functions opened transactions.

## Decision

* **SQL lives in repositories** (`lg_sotf.db`). Code outside `db/` calls
  repository methods.
* **Services own transactions.** A use case that changes data opens one
  `db.tenant_tx` (or `system_tx`), passes the connection to every repository
  call and to the audit write, and returns plain results. Routers validate
  input, call the service and map results to HTTP; they open no
  transactions. Expensive work (argon2 hashing, secret encryption, outbound
  calls) happens before the transaction; cache invalidation and event
  publishing after it commits.
* **An audit entry commits with its change.** `AuditLogger.record(..., *,
  conn)` requires the change's connection. If the entry cannot be written the
  change rolls back and the error propagates (500, nothing changed, the
  request can be retried).
* **`AuditLogger.record_event`** is the only audit write without a
  connection. It is for entries that have no transaction to join: access
  events (sign-in, sign-out, exports, cross-tenant reads), refused or failed
  attempts, changes outside the database (Redis, external systems), and the
  start and end of an operation spread over many transactions (streaming
  tenant erasure). It is written before the action is reported as done.
* **Every audit row goes through `AuditLogger`**, never
  `repos.audit.append` directly, so details are redacted and logged.
* **Multi-tenant writes in one transaction** re-scope the connection with
  `db.tenancy.switch_tenant(conn, tenant_id)` between tenants; RLS then checks
  each write against the tenant it names.
* **Tenant provisioning** is one service, `services.tenancy.provision_tenant`,
  used by the API and the CLI: the tenant row, its settings, its first admin
  and every audit entry commit together.

## Consequences

* An audit failure now rolls back the change it records instead of leaving
  it committed (CHANGELOG, Fixed).
* A failed provisioning leaves no tenant behind, and a retry succeeds; two
  concurrent requests for one id give one 201 and one 409.
* CI enforces it with the data-access ratchets in
  `tests/unit/architecture/test_data_access.py`: the audit-without-conn
  baseline is empty, `.audit.append(` appears only in `audit/logger.py` and
  `db/`, `TenantsRepo.provision/create` is called only from
  `services/tenancy.py` and `db/`, and the shrink-only raw-SQL and
  router-transaction baselines reach their targets in D4 and D5.
* Streaming tenant erasure stays a series of batch transactions: its start
  and its result are `record_event` entries.

## Alternatives considered

* **A unit of work that buffers audit entries and writes them at commit.**
  Rejected: every entry's `ts` (`clock_timestamp()`) would move to commit
  time, and the explicit connection already gives the same atomicity.
* **Audit first, then change.** An entry for a change that then fails would
  claim something that did not happen.
* **Keep the transaction in the API layer** (for example in `MfaService`).
  It would grow the router-transaction ratchet; the use case belongs to the
  service layer.
