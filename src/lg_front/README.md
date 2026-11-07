# LG-SOTF analyst web app

React 18 + TypeScript single-page app for triaging alerts, deciding
escalations, approving response actions and administering a tenant. It talks
only to the LG-SOTF API (`/api/v1`, see `docs/api.md`) and its `/ws` live
event stream.

## Development

```sh
npm ci
npm run dev          # http://localhost:5173, proxies /api (and /api/v1/ws) to 127.0.0.1:8000
npm run lint         # ESLint (TypeScript, React hooks, jsx-a11y), zero warnings allowed
npm run typecheck    # tsc -b
npm run test:ci      # Vitest + Testing Library
npm run build        # type-check and bundle into dist/
npm run audit:prod   # npm audit of production dependencies (high and critical fail)
```

Set `LG_SOTF_DEV_API` to proxy to another API address. The API's
`api.cors_origins` must contain the page origin for the WebSocket
(`configs/development.yaml` already lists `http://localhost:5173` and
`http://localhost:3000`).

Node 20.19+ or 22.12+ is required.

## End-to-end tests (Playwright)

`e2e/` drives the real UI in Chromium against a running deployment. The
usual way is `scripts/e2e_ui_stack.sh` from the repository root: it builds
the api and frontend images, starts the production-like compose stack with
the UI on `http://localhost:13000` (fake LLM, bootstrap admin), runs the
suite, checks the container logs for tokens and tears everything down (CI
job `e2e-ui`). Against a stack you already run:

```sh
npx playwright install chromium   # once
E2E_BASE_URL=http://localhost:3000 E2E_ADMIN_EMAIL=admin@example.com \
E2E_ADMIN_PASSWORD=... npm run e2e
```

The suite creates its own users, API key and alerts (named after the run),
so it can run against a stack that already holds data, but it does write
to that tenant: never point it at production. `E2E_SCREENSHOTS=<dir>` saves
a screenshot of each main page (the README images come from such a run);
`E2E_CHROMIUM_PATH` selects a Chromium binary.

## Runtime configuration

Nothing environment-specific is compiled in. `index.html` loads `/config.js`,
which the container writes at start-up from environment variables:

| Variable | Meaning |
|---|---|
| `LG_SOTF_API_BASE_URL` | Origin of the API when it is not on the UI's host (empty: same origin, the usual Ingress setup). |
| `LG_SOTF_WS_URL` | Full WebSocket URL of `/api/v1/ws` (empty: derived). |
| `LG_SOTF_API_UPSTREAM` | Reverse-proxy `/api` (REST and WebSocket) to this upstream, `http(s)://host[:port]` without a path, e.g. `http://api:8000` (compose). |
| `LG_SOTF_OIDC_ISSUER`, `LG_SOTF_OIDC_CLIENT_ID` | Enable single sign-on (authorization code + PKCE, public client). |
| `LG_SOTF_OIDC_SCOPE`, `LG_SOTF_OIDC_AUDIENCE`, `LG_SOTF_OIDC_TOKEN_TYPE` | Scope (default `openid profile email`), optional `audience` parameter, and which token the API receives (`access_token` default, or `id_token`). |
| `LG_SOTF_OIDC_REDIRECT_URI`, `LG_SOTF_OIDC_AUTHORIZATION_ENDPOINT`, `LG_SOTF_OIDC_TOKEN_ENDPOINT`, `LG_SOTF_OIDC_END_SESSION_ENDPOINT`, `LG_SOTF_OIDC_LABEL` | Overrides of the discovery document and the button label. The redirect URI defaults to `<origin>/auth/callback`. |
| `LG_SOTF_CSP_CONNECT_SRC` | Extra `connect-src` origins, space separated. |
| `LG_SOTF_HSTS_MAX_AGE` | Send `Strict-Transport-Security` with this max-age. |

Every value is validated (URL shape, character set) before it is written into
JavaScript or nginx configuration; an invalid value stops the container with
exit code 64. The same values feed the Content-Security-Policy:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self' <API, WebSocket and IdP origins>;
base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
```

The build emits no inline scripts or styles (the Dockerfile fails the build
if `index.html` gains one).

## Container

`Dockerfile` builds with `NODE_IMAGE` (default `node:22-alpine`) and serves
with `NGINX_IMAGE` (default `nginxinc/nginx-unprivileged:1.28-alpine`):
non-root, port 8080, read-only root filesystem (only `/tmp` is written),
SPA fallback, gzip, immutable caching for hashed `/assets/*`, `no-cache` for
`index.html`, `no-store` for `/config.js`, security headers on every static
response, and `/healthz` for probes. Behind a TLS-intercepting proxy pass the
CA as a build secret: `docker build --secret id=build_ca,src=ca.crt ...`.

Compose: `make up PROFILES=frontend` (UI on http://localhost:3000, `/api`
proxied to the api service). Helm: `frontend.enabled` (default `true`) with
runtime settings under `frontend.config`.

### Live updates need the page origin in `api.cors_origins`

Browsers always send `Origin` on a WebSocket handshake, and the API accepts
`/api/v1/ws` only from origins listed in `settings.api.cors_origins`, even
when the UI and the API share one host. Every deployment must list the URL
users open, for example:

* Helm: `settings.api.cors_origins: ["https://soc.example.com"]` (the chart's
  default is `[]`, which refuses the UI's own Ingress host);
* compose: `configs/development.yaml` lists `http://localhost:3000` and
  `http://localhost:5173`; opening `http://127.0.0.1:3000` or changing
  `FRONTEND_PORT` needs that origin added, and the production overlay needs
  the public URL.

Without it the rest of the UI works (pages poll), and after five failed
attempts the header shows "Live updates unavailable" instead of
"Reconnecting".

## Security model

* The access token is held in memory only (a private field of the auth
  store); it is never written to localStorage, sessionStorage or cookies.
  ESLint forbids `localStorage`, and `tests/deploy/test_frontend.py` checks
  the sources.
* One exception to "not in URLs": browsers cannot set headers on a
  WebSocket, and the API reads the token from the query string of
  `/api/v1/ws?token=...`. The nginx proxy never logs query strings in its
  access log and logs only critical errors for that location (its error log
  would otherwise print the request line), but an ingress controller or
  load balancer in front of the API may log full URLs: configure it to drop
  query strings for `/api/v1/ws`. Tokens are short-lived access tokens,
  never the refresh token.
* Sessions survive reloads through the API's HttpOnly, `SameSite=Strict`
  refresh cookie: the app calls `POST /auth/refresh` on load, shortly before
  the token expires, when the tab becomes visible and on a 401. Refreshes are
  single-flight within a tab and serialised across tabs with the Web Locks
  API, because the API treats a reused (already rotated) refresh token as
  theft and revokes every session of the user.
* OIDC sessions are refreshed with the IdP's refresh token (kept in memory)
  when one is issued; otherwise the user signs in again when the token
  expires. Only the transient PKCE verifier, `state` and `nonce` are kept in
  sessionStorage across the redirect and are deleted when the callback is
  handled. The post-login destination is restricted to same-app paths.
* Role checks in the UI mirror the API (viewer, analyst, admin, platform
  admin) to hide or disable what the API would refuse; the API remains the
  authority. A platform admin can act on another tenant (`X-Tenant-ID`);
  claiming, deciding and approving are then disabled, as the API refuses them.
* The React Query cache is dropped whenever the session ends or its
  identity changes (user, home tenant, acting tenant or role), so data of
  one session never renders for the next person in the same tab.
* CSV exports quote per RFC 4180 and prefix cells starting with `=`, `+`,
  `-`, `@`, tab or carriage return with `'` so spreadsheets do not execute
  them.

## Structure

Layers, from the top (each may import only the layers below it):

```
src/main.tsx      entry point: reads /config.js, builds the session and the query client
src/app/          the app shell: App (providers, public routes), routes.tsx (the route
                  table: path, page, role gate, nav entry), Layout and shell/ (sidebar,
                  header, account menu), queryClient
src/pages/        one folder or file per feature; each route is one lazily loaded chunk.
                  Data-fetching widgets live with their feature (pages/platform/TenantSwitcher,
                  pages/onboarding/, pages/settings/LlmTestCard, pages/actions/)
src/components/   presentational building blocks: ui/ primitives, dialogs (focus trap),
                  badges, virtualized table, error boundary, route guards
src/api/          shared kernel: HTTP client (error envelope, request ids, refresh on 401),
src/auth/         types, endpoints, query keys and hooks; auth store, OIDC (PKCE), role
src/live/         checks; WebSocket client (backoff with jitter, resync); CSV, JSON and
src/lib/          download helpers, formatting, keyset pagination, visibility-aware
src/theme/        polling; design tokens, theme and row density
docker/           nginx.conf and the start-up entrypoint
```

ESLint enforces the boundaries (`no-restricted-imports` in `eslint.config.js`):

* the shared kernel (`api`, `auth`, `live`, `lib`, `theme`) and `components`
  never import `pages` or `app`;
* the shared kernel never imports `components`;
* `components` never imports `api/endpoints` or `@tanstack/react-query`: a
  widget that fetches data belongs to its feature under `pages`.

Tests may cross the boundaries (a page rendered inside the shell, for
example). `src/main.tsx`, `src/auth/store.ts` and `src/auth/oidc.ts` must not
move: the deployment tests pin them.

## API types

`src/api/types.ts` holds the API types the app uses, written by hand: names
and vocabularies stay readable, and response vocabularies are open
(`Open<T>`: the known values or any other string, so a newer API in a rolling
deploy does not break the UI). They are held to the API contract:

* `npm run gen:api` turns the committed `docs/openapi.json` into
  `src/api/schema.gen.ts` (openapi-typescript, pinned). CI regenerates it and
  fails when the committed file differs, so a backend change to the OpenAPI
  document comes with the regenerated file.
* `src/api/contract.check.ts`, compiled by `tsc -b`, requires every response
  schema to be assignable to its hand-written type (as sent: FastAPI includes
  every field) and every hand-written request type to be assignable to its
  schema. A drift fails the type check and names the field. Give a new type
  a line there.
* Only `src/api` may import `schema.gen` (ESLint).
