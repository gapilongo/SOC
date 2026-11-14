# 0015. Frontend module model: one build, a thin shell, a manifest per service

* Status: accepted
* Date: 2026-11-14
* Story: ARCH-E10.1 (#376); the entitlement field is ARCH-E10.2 (#377)

## Context and problem

The console (`src/lg_front`) is a well-kept single product. Its discipline
is real: one route table, one lazy chunk per route, declared query keys and
invalidation policies, a compile-time API contract check, linted layers. But
it has no module boundary. A review at commit 1725a247 measured the cost:

* adding one page edited **13 existing files**, twice (the Blind audit page,
  commit 3310c58b, and the Setup wizard, commit 1c33b5cd);
* a second service, a Vulnerability Operations Center (VOC) with six pages
  and one cross-link each way, would edit **14 existing files at the minimum
  and about 25 when integrated**, across five closed registries: the route
  table with its closed union of navigation groups, the `can` object, the
  API quartet (types, endpoints, query keys, invalidation) with its contract
  check, the live-event switch, and the shell's count chips, which read only
  the SOC dashboard summary;
* the shell imported a feature (`pages/platform/TenantSwitcher`, twice), and
  15 imports crossed from one feature folder into another's internals.

The founder wants a platform to which services are added. Two services
developed in parallel would collide in the same seven central files.

## Decision

The console stays **one build and one image**. Inside it, a service is a
**module**: a folder with a typed manifest, registered in one list. The SOC
is the first and, today, the only module. Nothing changes for the user.

1. **One build, no micro-frontends, no Module Federation.** Modules are
   folders in one Vite application, each page its own lazy chunk.
2. **A thin shell.** `src/app/` owns the providers, sign-in, the layout, the
   sidebar, the header and the route guards. It names no service: everything
   service-specific reaches it through the registry.
3. **A typed manifest per service.** `src/modules/<id>/index.ts` exports one
   `ModuleManifest` (`src/core/module.ts`): id and title, the entitlement
   key, navigation groups and items, routes with their lazy pages and access
   rules, the module's permission functions, a map from live event types to
   the module's own query keys, and its contributions to extension points.
   The manifest is static data. It reaches page and widget code only through
   `lazy()`, so a module that is switched off is never downloaded. ESLint
   refuses a static import of a page from a manifest. What a manifest does
   import directly stays small: its query keys, the hook behind a navigation
   count, and a route that only redirects.
4. **One registry.** `src/app/modules.ts` holds `MODULES = [soc]`. Adding a
   service is its folder and one entry in that list. Routes, the sidebar,
   navigation counts, the live-event mapping, the extension points and the
   shell tests are derived from it (`src/app/registry.ts`). Navigation
   groups are open: a module declares a group or adds items to one another
   module declared. A navigation count is a hook the module supplies.
   A manifest that cannot work (duplicate id or path, an undeclared group, a
   live-event key outside the module's namespace) throws when the registry
   is built, which every shell test sees.
5. **An API slice per module on the shared client.** The kernel keeps the
   HTTP client, the generated schema (one file, one command), the identity
   types and `GET /auth/me`. Each module owns
   `modules/<id>/api/{types,endpoints,queryKeys,invalidate,contract.check,hooks}.ts`.
   Every query key of a module starts with its id (`['soc', 'alerts', ...]`),
   so a module's invalidation cannot reach another module's cache by
   accident; the kernel's keys start with `core`.
6. **Named extension points for cross-links.** The owner of a place defines
   a slot and the props it passes (`defineSlot`, `src/core/slots.ts`) and
   renders it with `SlotOutlet`; a module contributes a lazy component for
   it in its manifest, optionally with a `when` rule on the principal. A
   slot with no contribution renders nothing, so the owner's code does not
   change when a module arrives or is switched off. A contribution that
   crashes is contained and renders nothing. The first slots are the ones
   with a use today:
   * `shell.header.tenant` and `shell.banner`, owned by the shell: the tenant
     switcher and the acting-tenant banner, which the shell used to import
     from a feature folder;
   * `alert.entity`, owned by the SOC: rendered next to every entity of an
     alert, in the alert panel and on the decision page (one shared
     `EntityList`, so a contribution appears in both).

   `overview.needsYouNow`, `reports.tabs`, `tenantSettings.sections` and
   `platform.tenantColumns` are named in the review and are declared when
   their first contributor exists, not before.
7. **A module's public surface is `public.ts`.** Another module imports only
   that file. Links between services go through it (`alertsHref`), never
   through deep paths.
8. **Entitlements come from the server.** A manifest names its entitlement
   key. `moduleEnabled(manifest, principal)` is the one place that answers
   "does this tenant have the module"; the route guard and the sidebar both
   ask it. It answers yes for every registered module until `GET /auth/me`
   carries the tenant's entitlements (ARCH-E10.2), which also adds the
   distinct "not enabled for this tenant" state. The API remains the
   enforcement point; the UI only hides.
9. **The boundary is enforced by lint, not by review.** `eslint.config.js`:
   a module imports another module only through its `public.ts`; the shell
   imports a module only through the registry, which imports only the
   module's manifest; the kernel and `components/` never import a module; a
   manifest never imports its pages statically. Tests may compose layers, as
   before.
10. **Gates per module.** `coverage-floors.json` has a floor for
    `src/modules/soc/` and a stricter one for its API slice; a new module
    adds its own, so a thinly tested module cannot hide inside the overall
    figure.

Shared presentational primitives live in `components/ui`, where every module
finds them: one `Tabs` (and `TabLinks` for views that are links), one
`Timeline`, one `EntityChip` and `EntityList`. They replace four tab
implementations and two copies each of the timeline and the entity list.

### Which choices rest on evidence, and which are judgement

| Choice | Standing |
|---|---|
| One build with internal modules | **Evidence**: consistent expert guidance that micro-frontends serve many independently deploying teams (Mezzalira at QCon 2025; Jackson on martinfowler.com), and Zalando's move from mixed fragments to one stack and one repository. No source gives a measured team-size threshold. Air-gapped delivery adds a reason: a remote module would be baked into the image anyway |
| A static manifest, registration only, lazy code | **Evidence** for the pattern: Backstage moved wiring out of the app root into plugins after hand-wiring in one central file did not scale; Grafana requires every extension to be declared; Kibana separates setup from start; VS Code reads contributions without running extension code. The single typed object per module, lighter than Backstage's extension tree, is **judgement** |
| A small set of named slots | **Evidence** that few suffice (Falcon Foundry's six socket types, Grafana's eight core extension points). Which slots, and declaring each only with its first use, is **judgement** from the code review |
| Boundaries enforced by lint | **Evidence** of practice (Nx tag rules; the Red Hat console team's four custom rules). The effect on AI coding agents is one team's self-report |
| Server-supplied entitlements, with an unlicensed build behaving like the open one | **Evidence** from one fully read source (GitLab's EE guidelines) |
| A failed entitlement or a crashing contribution degrades the module, not the shell | **Judgement**, drawn from a counter-example (Backstage fails to start) |
| Query keys namespaced by module id | **Judgement**: it makes "a module invalidates only its own keys" checkable |
| Doing it before the second service | **Judgement** supported by the product's own file counts and by Backstage's migration history (hybrid mode, converters, "all routes from a single plugin must be migrated at once"). No source measures early against late cost |

## Consequences

* Adding a service touches its own folder and one line in
  `src/app/modules.ts`. `src/app/scaffold.test.tsx` proves it: it registers
  an example module with one page (`src/test/scaffold-module`, also the
  folder to copy when a service starts) and shows that the route, the
  sidebar group, the item and its count, the guard, the breadcrumb, the
  live-event mapping and an `alert.entity` contribution all follow, with no
  other file changed. `src/app/boundary.test.ts` holds the lint rule in
  place.
* The SOC module still carries the pages every service will share (tenant
  configuration, users, the MSSP console, account security), and its
  permission functions stay in `auth/roles.ts`, where the shell also uses
  them. Both move when a second service needs them; the model makes each a
  folder move and a manifest edit.
* Query keys changed shape (`['alerts', ...]` became `['soc', 'alerts', ...]`).
  The cache is in memory only, so nothing persisted is affected.
* The tenant switcher and the acting-tenant banner are now lazy chunks,
  loaded only for platform admins. The first load is smaller (initial
  JavaScript 434.1 kB, 137.5 kB gzip, against 438.8 kB and 138.7 kB before);
  a platform admin sees the plain tenant name for a moment before the
  switcher appears.
* Picking one look where the copies differed is visible in three places:
  the Reports and MSSP console tabs look like the Alerts view tabs and answer
  to Home and End; entity chips in the alert panel have the decision page's
  radius; the decision page's Entities tab uses the alert panel's labels.
* `LiveSocket` no longer holds a list of event types: the registry tells it
  which types the modules listen to.
* Not done here, by decision: a data-table primitive on the virtual table
  (it did not fall out of this refactor and deserves its own story); the
  axe page list derived from the registry (the e2e suite keeps its literal
  list: deriving it would add pages that axe has never checked, which is
  work for the accessibility-gates story); an `ee/` directory and build alias
  for licensed modules (ARCH-E10.2 and the packaging story decide it).
