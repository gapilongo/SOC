### Added

- MSSP organisation model, part 1 (schema): a tenant can be an MSSP
  *organisation* with named staff members, and a customer tenant can give an
  organisation (or one of its members) a role in it, with a reason and an
  expiry of at most a year. Grants belong to the customer: only the customer
  can create or revoke them, the organisation can only read its own, and no
  other tenant sees them (row-level security). Tenant exports include them
  (`tenant_grants.jsonl`, `organisations.jsonl`,
  `organisation_members.jsonl`).
- MSSP organisation model, part 2 (reading under grants): a member of an
  organisation acts in a customer tenant by sending `X-Tenant-ID` with their
  own sign-in, when the customer granted the organisation access. Every read
  route serves the customer's data under the grant's role (capped at the
  member's own role) and answers 403 without a live grant; revoking a grant
  takes effect on the next request, and each request is recorded in the
  customer's audit log (`grant.tenant_access`). New endpoints:
  `PUT /platform/organisations/{tenant_id}`, `/organisation/members`,
  `GET /organisation/grants`, and `GET`/`POST /tenant/grants` with
  `POST /tenant/grants/{id}/revoke` for the customer's admins. Giving and
  revoking a grant is audited in both the customer's and the organisation's
  chain. `GET /auth/me` returns `grant_id`. See docs/mssp.md.
- MSSP organisation model, part 3 (writing and deciding under grants): an
  MSSP analyst acting under a grant can now decide escalations (one at a
  time or with bulk close) and approve, reject, roll back, retry and verify
  actions, within the grant's role. Every audit entry written under a grant
  is recorded in both chains: the customer's, naming the organisation and
  grant, and the organisation's as `delegated.<action>` with the customer
  entry's id and hash. Claiming an escalation and creating or changing
  users, MFA, API keys and grants stay refused under a grant. A platform
  admin's tenant switch still cannot claim or decide.
- MSSP organisation model, part 4 (live updates, automation and MCP under
  grants): `/ws?tenant=<customer>` streams a granted customer's events and
  closes when the grant is revoked or expires; an organisation's API key
  acts under a grant to the whole organisation with its scopes capped by the
  grant's role (never `ingest`); `LG_SOTF_MCP__TENANT_ID` pins the MCP server
  to one customer tenant. A generated cross-tenant leak suite covers every
  API operation, MCP tool and the WebSocket channel.
