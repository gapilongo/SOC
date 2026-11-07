#!/usr/bin/env bash
# Browser end-to-end test of the web UI against the production-like compose stack.
#
#   scripts/e2e_ui_stack.sh                 # build both images, run the Playwright suite, tear down
#   scripts/e2e_ui_stack.sh --no-build      # use the existing $APP_IMAGE and $FRONTEND_IMAGE
#   scripts/e2e_ui_stack.sh --keep          # leave the stack running afterwards (prints how to reach it)
#   scripts/e2e_ui_stack.sh --stack-only    # start the stack and print its URL; run no tests (implies --keep)
#
# What it does:
#   1. generates secrets into a private env file (scripts/generate_secrets.py);
#   2. starts postgres, redis, migrate, api, worker, scheduler and the frontend
#      (nginx serving the built app and proxying /api) with the production
#      overlay: two database roles, environment=staging, the fake LLM allowed
#      for the demo, a bootstrap admin from the env file;
#   3. runs the Playwright suite in src/lg_front/e2e against the UI origin
#      (http://localhost:$E2E_UI_PORT): sign-in, live Overview, alert filters
#      and pagination, timeline, escalation claim and decision, approval,
#      role gating for an analyst and a viewer, sign-out, token storage, the
#      Content-Security-Policy and screenshots of each main page.
#
# The browser opens http://localhost, which Chromium treats as a secure
# context, so the API's Secure refresh cookie (auth.cookie_secure=true in the
# overlay) works without TLS. Everywhere else put TLS in front of the stack.
#
# Needs docker with compose v2, python3 and Node.js 20.19+/22.12+ with the
# frontend's dev dependencies installed (npm ci in src/lg_front) and a
# Chromium for Playwright (`npx playwright install chromium`, or set
# PLAYWRIGHT_BROWSERS_PATH to an existing browser directory).
#
# Environment overrides:
#   APP_IMAGE, FRONTEND_IMAGE    images to test (default lg-sotf:dev, lg-sotf-frontend:dev)
#   PYTHON_BASE_IMAGE            base image for the backend build
#   NODE_IMAGE, NGINX_IMAGE      base images for the frontend build
#   POSTGRES_IMAGE, REDIS_IMAGE  service images
#   BUILD_CA_FILE                CA bundle for builds behind a TLS-intercepting proxy
#   E2E_PROJECT                  compose project name (default lgsotf-e2e)
#   E2E_UI_PORT, E2E_API_PORT    host ports (default 13000 / 18100)
#   E2E_SCREENSHOTS              directory for page screenshots (default: none taken)
#   PLAYWRIGHT_ARGS              extra arguments for `playwright test`

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUILD=1
KEEP=0
RUN_TESTS=1
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --keep) KEEP=1 ;;
    --stack-only) KEEP=1; RUN_TESTS=0 ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

export APP_IMAGE="${APP_IMAGE:-lg-sotf:dev}"
export FRONTEND_IMAGE="${FRONTEND_IMAGE:-lg-sotf-frontend:dev}"
PROJECT="${E2E_PROJECT:-lgsotf-e2e}"
UI_PORT="${E2E_UI_PORT:-13000}"
API_PORT="${E2E_API_PORT:-18100}"
UI_URL="http://localhost:${UI_PORT}"
ADMIN_EMAIL="admin@e2e.example.com"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lgsotf-e2e.XXXXXX")"
chmod 700 "$WORK"
ENV_FILE="$WORK/stack.env"

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

COMPOSE=(docker compose -p "$PROJECT" -f docker/docker-compose.yml -f docker/docker-compose.prod.yml
  --env-file "$ENV_FILE" --profile frontend)

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -f "$ENV_FILE" ]; then
    echo "--- last service logs (rc=$rc) ---" >&2
    "${COMPOSE[@]}" ps -a >&2 || true
    "${COMPOSE[@]}" logs --no-color --tail 40 api worker frontend >&2 || true
  fi
  if [ "$KEEP" -eq 1 ] && [ -f "$ENV_FILE" ]; then
    echo
    echo "stack left running at $UI_URL"
    echo "  admin: $ADMIN_EMAIL, password: LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD in $ENV_FILE"
    echo "  stop:  ${COMPOSE[*]} down -v"
    return
  fi
  if [ -f "$ENV_FILE" ]; then
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

value() { grep -m1 "^$1=" "$ENV_FILE" | cut -d= -f2-; }

# ------------------------------------------------------------------ env file
step "generating secrets into a private env file"
install -m 600 /dev/null "$ENV_FILE"
python3 scripts/generate_secrets.py --append "$ENV_FILE" >/dev/null
{
  echo "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL=$ADMIN_EMAIL"
  # The drivers sign the bootstrap platform admin in with a password only. MFA for platform
  # admins is on by default in staging; the MFA flows are covered by tests/integration/api/test_mfa.py
  # and the frontend tests, so this stack opts out explicitly (never do this in a deployment).
  echo "LG_SOTF_AUTH__REQUIRE_MFA_FOR_PLATFORM_ADMINS=false"
  # The browser's origin: CORS and the WebSocket origin check.
  echo "LG_SOTF_API__CORS_ORIGINS=[\"$UI_URL\"]"
  echo "LG_SOTF_API__PUBLIC_URL=$UI_URL"
  echo "API_PORT=$API_PORT"
  echo "WORKER_HEALTH_PORT=$((API_PORT + 1))"
  echo "SCHEDULER_HEALTH_PORT=$((API_PORT + 2))"
  echo "FRONTEND_PORT=$UI_PORT"
  echo "APP_IMAGE=$APP_IMAGE"
  echo "FRONTEND_IMAGE=$FRONTEND_IMAGE"
  [ -n "${POSTGRES_IMAGE:-}" ] && echo "POSTGRES_IMAGE=$POSTGRES_IMAGE"
  [ -n "${REDIS_IMAGE:-}" ] && echo "REDIS_IMAGE=$REDIS_IMAGE"
  true
} >>"$ENV_FILE"
[ -n "$(value LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD)" ] || fail "generate_secrets.py did not produce the admin password"

# --------------------------------------------------------------------- images
if [ "$BUILD" -eq 1 ]; then
  step "building $APP_IMAGE"
  make image IMAGE="$APP_IMAGE" ${PYTHON_BASE_IMAGE:+PYTHON_BASE_IMAGE="$PYTHON_BASE_IMAGE"} \
    ${BUILD_CA_FILE:+BUILD_CA_FILE="$BUILD_CA_FILE"} >"$WORK/build-api.log" 2>&1 \
    || { tail -40 "$WORK/build-api.log" >&2; fail "backend image build failed"; }
  step "building $FRONTEND_IMAGE"
  docker build -t "$FRONTEND_IMAGE" \
    ${NODE_IMAGE:+--build-arg NODE_IMAGE="$NODE_IMAGE"} \
    ${NGINX_IMAGE:+--build-arg NGINX_IMAGE="$NGINX_IMAGE"} \
    ${BUILD_CA_FILE:+--secret id=build_ca,src="$BUILD_CA_FILE"} \
    src/lg_front >"$WORK/build-frontend.log" 2>&1 \
    || { tail -40 "$WORK/build-frontend.log" >&2; fail "frontend image build failed"; }
fi
for image in "$APP_IMAGE" "$FRONTEND_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || fail "image $image not found (drop --no-build)"
done

# ---------------------------------------------------------------------- stack
step "starting the stack ($PROJECT) with the web UI on $UI_URL"
"${COMPOSE[@]}" up -d --no-build --wait --wait-timeout 180 \
  postgres redis migrate api worker scheduler frontend
"${COMPOSE[@]}" ps -a --format '{{.Service}}: {{.State}} {{.Status}}'
code="$(curl -s -o /dev/null -w '%{http_code}' "$UI_URL/")"
[ "$code" = "200" ] || fail "the UI answered $code at $UI_URL/"

[ "$RUN_TESTS" -eq 1 ] || exit 0

# ------------------------------------------------------------------ playwright
step "Playwright suite (src/lg_front/e2e)"
read -r -a EXTRA_ARGS <<<"${PLAYWRIGHT_ARGS:-}"
E2E_BASE_URL="$UI_URL" \
E2E_ADMIN_EMAIL="$ADMIN_EMAIL" \
E2E_ADMIN_PASSWORD="$(value LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD)" \
E2E_SCREENSHOTS="${E2E_SCREENSHOTS:-}" \
  npm --prefix src/lg_front run --silent e2e -- "${EXTRA_ARGS[@]}"

step "container logs carry no access tokens"
# The UI sends the access token in the /api/v1/ws query string (browsers cannot
# set WebSocket headers): nginx must not log it and the API must redact it.
logs="$("${COMPOSE[@]}" logs --no-color frontend api worker scheduler 2>&1)"
if printf '%s' "$logs" | grep -Eq 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'; then
  fail "a JWT appears in the container logs"
fi
echo "ok    no JWT in the frontend, api, worker or scheduler logs"

echo
echo "E2E UI PASSED"
