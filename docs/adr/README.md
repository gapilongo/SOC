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
| 0003 | Data access: SQL only in repositories, services own transactions, audit in the same transaction | Reserved (D1, D5) |
| 0004 | Domain vocabulary: `Literal` over `StrEnum`, frozen migrations | Reserved (F2) |
| 0005 | Exception text is never logged | Reserved (X1) |
| 0006 | Encryption keys are validated at startup in every role | Reserved (D7) |
| 0007 | Egress policy lives in `lg_sotf.net` | Reserved (F4) |
| 0008 | Tracing: instrument at choke points, or remove | Reserved (X5) |
| 0009 | API contract: committed OpenAPI snapshot, tolerant reader | Reserved (T2) |
| 0010 | Frontend structure and boundaries | Reserved (FE9) |
| 0011 | Postgres RLS per tenant and the non-BYPASSRLS runtime role | Reserved (Q5) |
| 0012 | Redis Streams work queue with DLQ | Reserved (Q5) |
| 0013 | Configuration only through `lg_sotf.settings` | Reserved (Q5) |

Earlier design documents: [MCP architecture](../design/mcp-architecture.md)
(read, safe writes and proposals over MCP; decisions are human-only) and the
[refactor roadmap](../design/refactor-roadmap.md), which these ADRs implement.
