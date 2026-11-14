### Changed

- The web console is now built from service modules (ARCH-E10.1,
  [ADR 0015](docs/adr/0015-frontend-module-model.md)). It is still one build
  and one image, and it works as before; the change is in how it is put
  together, so that a second service can be added without editing the first.
  - Each service is a folder under `src/lg_front/src/modules/` with a typed
    manifest (pages and their access rules, navigation, counts, live events,
    extension contributions). The security operations pages are the first
    module. Adding a service is its folder and one line in
    `src/app/modules.ts`; a test registers an example module that way and
    checks that the route, the sidebar, the access guard, live updates and a
    cross-link all follow.
  - Each module has its own API slice, and its cached data is kept under its
    own name, so one service cannot refresh or clear another's by accident.
  - Services link to each other through named extension points. The tenant
    switcher and the "acting on another tenant" banner use them, and are now
    loaded only for platform admins, which makes the first page load a little
    smaller for everyone else.
  - A lint rule keeps a module from reaching into another module's files and
    keeps the shell from naming a service.
  - Tabs, timelines and entity lists are one shared component each. What you
    may notice: the Reports and MSSP console tabs look like the Alerts view
    tabs and answer to Home and End; on the decision page the Entities tab
    says "IP addresses" where it said "Ips".
