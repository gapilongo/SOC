# 0009. Publish the API contract as a committed OpenAPI snapshot; responses advertise enums and read tolerantly

* Status: accepted
* Date: 2026-11-07
* Roadmap step: T2 ([refactor roadmap](../design/refactor-roadmap.md), Phase 6); builds on G6 and G7

## Context and problem

The OpenAPI document is the API's published contract. G6 committed it as
`docs/openapi.json`, with a snapshot test, and #118 generates the frontend's
TypeScript types from it (`src/lg_front/src/api/schema.gen.ts`) and checks the
hand-written types against them (`contract.check.ts`). The contract still
said less than the code knew:

* About 50 response fields drawn from a vocabulary (roles, scopes,
  severities, alert, escalation and action statuses, dispositions,
  decisions, risk levels, source types and health, tenant statuses, actor
  types, integration kinds and events, the action catalog, among others)
  were published as plain `string`. A client could not learn the values
  without reading the server code.
* One response field, `ActionOut.verification`, used the strict vocabulary
  `Literal`: a value the model did not know raised a validation error, and
  the endpoint answered 500. During a rolling deploy, an older API process
  can read a row that a newer worker wrote with a new value.
* Four JSON responses that routers build as plain dicts or `Response`
  objects (the evidence pack, `GET /readyz`, `GET /tenant/response/routes`
  and `GET /integrations/microsoft/catalog`) were published as `{}` or as a
  bare `Dict[str, Any]`, and the tenant export advertised a JSON body although
  it streams a ZIP.

Making the response fields `Literal` would advertise the enums, but a value
added by a newer release would then break older API processes, and generated
clients that switch exhaustively would break on it too.

## Decision

* **The committed `docs/openapi.json` is the contract.** Every API change
  regenerates it (`python scripts/export_openapi.py`) and the frontend types
  (`npm run gen:api`) in the same commit; the snapshot test and the CI diff
  check fail otherwise. The diff of `docs/openapi.json` is the review
  artifact of an API change.
* **Responses advertise, requests validate (tolerant reader).** A response
  field drawn from a vocabulary is typed with an alias from
  `lg_sotf.api.schemas`, for example
  `AlertStatusStr = Annotated[str, WithJsonSchema(vocabulary_schema(ALERT_STATUSES))]`.
  The schema lists the values in canonical order; at runtime the field is a
  plain `str`, so an unknown value is returned unchanged. A request field
  uses the vocabulary `Literal` itself and refuses unknown values (422).
* **Aliases, not calls in annotations.** Each vocabulary has one module-level
  alias; a field never spells out `Annotated[...]` or calls a function inside
  its annotation. The aliases take their values from the single declaration
  of each vocabulary: `lg_sotf.models.vocabulary` (ADR-0004), a repository
  constant pinned to its `CHECK` constraint (`SOURCE_HEALTH`,
  `TENANT_STATUSES`, `AUDIT_ACTOR_TYPES`, `EVENT_ACTOR_TYPES`,
  `INTEGRATION_KINDS`, `TICKETING_KINDS`, the outbox status and operation),
  the integration event types, or the action catalog (`ACTION_CATALOG`,
  `TargetKind`). A model below the API layer (`services/reporting.py`)
  declares its own one-line alias from the same tuple; so does the
  compliance router for the NIS2 stages, to keep `api/schemas.py` from
  importing the NIS2 module.
* **Hand-built JSON is documented, not re-serialized.** A route that returns
  a dict or a `Response` documents its body with
  `responses={200: {"model": X}}`, never `response_model`, so the payload is
  serialized exactly as before. These models live in
  `lg_sotf.api.payload_schemas` and are never instantiated. A dict-returning
  handler passes `response_model=None`, so its inferred `Dict[str, Any]` does
  not compete with the documented model. A non-JSON body declares its media
  type and schema (the tenant export: `application/zip`, binary).
* **Clients read tolerantly.** The generated TypeScript types become string
  unions, but the frontend keeps its own `Open<T>` types (the known values or
  any other string) and narrows with `isOneOf` before indexing a lookup
  table. `contract.check.ts` requires each generated response type to be
  assignable to the hand-written one, which an enum union always is to its
  `Open<T>`.

## Consequences

* `tests/unit/api/test_openapi_enums.py` lists every advertised field with
  the tuple it must equal (in order), and checks that response models
  return unknown values unchanged, that request models refuse them, that the
  documented responses reference their models and that no 2xx JSON body is
  untyped. A new vocabulary field gets a line there.
* Adding a vocabulary value changes `docs/openapi.json` and `schema.gen.ts`.
  The frontend still compiles, because its response types are open; a
  closed hand-written union (a request type, or a value the UI must handle
  exhaustively) fails `tsc -b` until it is widened, which is the point.
* `ActionOut.verification` now returns an unknown value instead of a 500.
  The `CHECK` constraint already limits the stored values, so no response
  changes today.
* Some free-text or provider-defined fields stay plain strings on purpose:
  `AlertEventOut.event_type` and `DeliveryOut.event_type` (the delivery
  event also includes the integration test event), `FindingOut.status` and
  `verdict` (parsed from analysis JSON written by the model and by older
  releases), `RoutingOut.code`, guardrail and blocked-reason codes (open
  sets, documented in `GUARDRAIL_REASONS`), and model names.
* Count maps keyed by a vocabulary (`DashboardOut.by_status`,
  `AlertCountsOut.by_status`, `EscalationGroupOut.by_severity`, ...) keep
  `Dict[str, int]`: some carry sentinel keys such as `undecided`, and
  openapi-typescript ignores `propertyNames`, so an enum on the keys would
  inform no client.

## Alternatives considered

* **`Literal` on response fields.** Advertises the enums with no extra
  types, but rejects unknown values at runtime (500 during a rolling deploy)
  and invites exhaustive client switches.
* **`StrEnum`.** Ruled out for the vocabulary by ADR-0004 (checkpoint
  serialization); it would also turn every response field into a closed set.
* **`response_model` for the hand-built responses.** Publishes the schema
  too, but re-validates and re-serializes the payload: the evidence pack is
  sealed with a digest of its exact JSON, and any coercion would change it.
* **Generate the frontend's types and drop the hand-written ones.** The
  generated unions are closed; the UI would lose the tolerant reader and
  the readable names. The generated types are a check, not the source.
