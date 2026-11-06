# Architecture decision records

Each significant architecture decision is recorded here as a short Markdown
file in the [MADR](https://adr.github.io/madr/) format (`template.md`). An ADR is
written when the decision is made, in the same PR as the change, and is never
edited afterwards except to mark it superseded by a newer one.

| No. | Title | Status |
|---|---|---|
| [0000](0000-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0001](0001-layering.md) | Layering, the dependency rule and accepted exceptions | Accepted |
| 0002 | Module boundaries, size and complexity budgets; move PRs separate from behaviour PRs | Reserved (roadmap G5) |
| [0003](0003-data-access-and-audit.md) | Data access: SQL only in repositories, services own transactions, audit in the same transaction | Accepted |
| [0004](0004-domain-vocabulary.md) | Domain vocabulary: `Literal` over `StrEnum`, frozen migrations | Accepted |
| 0005 | Exception text is never logged | Reserved (X1) |
| 0006 | Encryption keys are validated at startup in every role | Reserved (D7) |
| [0007](0007-egress-policy-in-net.md) | Egress policy lives in `lg_sotf.net`, with one strict and one lenient reader of the ingestion section | Accepted |
| 0008 | Tracing: instrument at choke points, or remove | Reserved (X5) |
| 0009 | API contract: committed OpenAPI snapshot, tolerant reader | Reserved (T2) |
| 0010 | Frontend structure and boundaries | Reserved (FE9) |
| [0011](0011-rls-per-tenant.md) | Postgres RLS per tenant and the non-BYPASSRLS runtime role | Accepted |
| [0012](0012-redis-streams-queue.md) | Redis Streams work queue with DLQ | Accepted |
| [0013](0013-configuration-through-settings.md) | Configuration only through `lg_sotf.settings` | Accepted |

Earlier design documents: [MCP architecture](../design/mcp-architecture.md)
(read, safe writes and proposals over MCP; decisions are human-only) and the
[refactor roadmap](../design/refactor-roadmap.md), which these ADRs implement.
