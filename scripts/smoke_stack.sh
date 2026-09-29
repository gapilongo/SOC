#!/usr/bin/env bash
# End-to-end smoke test of the docker compose stack, as a customer runs it.
#
#   scripts/smoke_stack.sh                 # build the image, run every check, tear down
#   scripts/smoke_stack.sh --no-build      # use the existing $APP_IMAGE (default lg-sotf:dev)
#   scripts/smoke_stack.sh --keep          # leave the stack running afterwards
#
# What it does (production-like override: two database roles, environment=staging,
# fake LLM allowed for the demo, secrets generated into a private temp dir):
#   1. start postgres, redis, migrate, api, worker, scheduler (compose --wait);
#      the bootstrap admin comes from the env file;
#   2. create a second tenant and its admin inside a container
#      (`lg-sotf create-tenant --admin-email ... --password-stdin`);
#   3. scripts/smoke_stack.py flow: the whole customer path over HTTP only
#      (login, API key, ingest, webhook source, WebSocket, escalation claim and
#      decision, dry-run approvals, closure, dashboard, LLM usage, audit log,
#      metrics, tenant isolation, refresh rotation and logout);
#   4. queue durability: a burst of alerts, then the worker is killed with
#      SIGKILL mid-processing and started again; later a second burst across a
#      graceful restart. Every alert must settle, none lost or failed;
#   5. Redis outage: redis is stopped, the api/worker/scheduler /readyz must
#      turn 503, redis is started, /readyz must recover and a new alert must be
#      processed end to end.
#
# Needs docker with compose v2 and python3. The HTTP driver runs on the host when
# python3 has httpx and websockets, otherwise inside the application image.
#
# Environment overrides:
#   APP_IMAGE            image to test (default lg-sotf:dev)
#   PYTHON_BASE_IMAGE    base image for the build (e.g. mirror.gcr.io/library/python:3.11-slim)
#   POSTGRES_IMAGE, REDIS_IMAGE   service images (e.g. mirror.gcr.io/library/postgres:16-alpine)
#   BUILD_CA_FILE        CA bundle for builds behind a TLS-intercepting proxy
#   SMOKE_PROJECT        compose project name (default lgsotf-smoke)
#   SMOKE_API_PORT, SMOKE_WORKER_PORT, SMOKE_SCHEDULER_PORT   host ports (18000/19101/19102)
#   SMOKE_BURST          alerts per durability burst (default 150)
#   SMOKE_PYTHON         interpreter for the driver (default: python3 if it has httpx+websockets)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUILD=1
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

export APP_IMAGE="${APP_IMAGE:-lg-sotf:dev}"
PROJECT="${SMOKE_PROJECT:-lgsotf-smoke}"
API_PORT="${SMOKE_API_PORT:-18000}"
WORKER_PORT="${SMOKE_WORKER_PORT:-19101}"
SCHEDULER_PORT="${SMOKE_SCHEDULER_PORT:-19102}"
BURST="${SMOKE_BURST:-150}"
BASE_URL="http://127.0.0.1:${API_PORT}"
TENANT_B="smoke-b"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lgsotf-smoke.XXXXXX")"
chmod 700 "$WORK"
ENV_FILE="$WORK/stack.env"
STATE="$WORK/state.json"

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

COMPOSE=(docker compose -p "$PROJECT" -f docker/docker-compose.yml -f docker/docker-compose.prod.yml --env-file "$ENV_FILE")

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -f "$ENV_FILE" ]; then
    echo "--- last service logs (rc=$rc) ---" >&2
    "${COMPOSE[@]}" ps -a >&2 || true
    "${COMPOSE[@]}" logs --no-color --tail 60 api worker scheduler >&2 || true
  fi
  if [ "$KEEP" -eq 0 ] && [ -f "$ENV_FILE" ]; then
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  elif [ "$KEEP" -eq 1 ]; then
    echo "stack left running: ${COMPOSE[*]}"
    echo "env file (secrets): $ENV_FILE"
    return
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

value() { grep -m1 "^$1=" "$ENV_FILE" | cut -d= -f2-; }
random_secret() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }

# ------------------------------------------------------------------ env file
step "generating secrets into a private env file"
install -m 600 /dev/null "$ENV_FILE"
python3 scripts/generate_secrets.py --append "$ENV_FILE" >/dev/null
{
  echo "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL=admin@smoke.example.com"
  echo "API_PORT=$API_PORT"
  echo "WORKER_HEALTH_PORT=$WORKER_PORT"
  echo "SCHEDULER_HEALTH_PORT=$SCHEDULER_PORT"
  echo "APP_IMAGE=$APP_IMAGE"
  [ -n "${POSTGRES_IMAGE:-}" ] && echo "POSTGRES_IMAGE=$POSTGRES_IMAGE"
  [ -n "${REDIS_IMAGE:-}" ] && echo "REDIS_IMAGE=$REDIS_IMAGE"
  true
} >>"$ENV_FILE"
for key in LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD LG_SOTF_API__METRICS_TOKEN LGSOTF_APP_PASSWORD; do
  [ -n "$(value "$key")" ] || fail "generate_secrets.py did not produce $key"
done

# --------------------------------------------------------------------- image
if [ "$BUILD" -eq 1 ]; then
  step "building $APP_IMAGE"
  make image IMAGE="$APP_IMAGE" ${PYTHON_BASE_IMAGE:+PYTHON_BASE_IMAGE="$PYTHON_BASE_IMAGE"} \
    ${BUILD_CA_FILE:+BUILD_CA_FILE="$BUILD_CA_FILE"} >"$WORK/build.log" 2>&1 \
    || { tail -40 "$WORK/build.log" >&2; fail "image build failed"; }
fi
docker image inspect "$APP_IMAGE" >/dev/null 2>&1 || fail "image $APP_IMAGE not found (drop --no-build)"

# --------------------------------------------------------------------- stack
step "starting the stack ($PROJECT)"
"${COMPOSE[@]}" up -d --no-build --wait --wait-timeout 180 postgres redis migrate api worker scheduler
"${COMPOSE[@]}" ps -a --format '{{.Service}}: {{.State}} {{.Status}}'
[ "$(docker inspect -f '{{.State.ExitCode}}' "$("${COMPOSE[@]}" ps -a -q migrate)")" = "0" ] || fail "migrate did not exit 0"

step "creating tenant $TENANT_B and its admin with the lg-sotf CLI in a container"
B_PASSWORD="$(random_secret)"
printf '%s\n' "$B_PASSWORD" | "${COMPOSE[@]}" run --rm --no-deps -T migrate \
  create-tenant --id "$TENANT_B" --name "Smoke B" --admin-email "admin@$TENANT_B.example.com" --password-stdin \
  2>/dev/null | grep -v '^{'

# -------------------------------------------------------------------- driver
export SMOKE_BASE_URL="$BASE_URL" SMOKE_STATE="$STATE"
export SMOKE_ADMIN_EMAIL="admin@smoke.example.com"
SMOKE_ADMIN_PASSWORD="$(value LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD)"
SMOKE_METRICS_TOKEN="$(value LG_SOTF_API__METRICS_TOKEN)"
export SMOKE_ADMIN_PASSWORD SMOKE_METRICS_TOKEN
export SMOKE_TENANT_B="$TENANT_B" SMOKE_TENANT_B_EMAIL="admin@$TENANT_B.example.com" SMOKE_TENANT_B_PASSWORD="$B_PASSWORD"

PY="${SMOKE_PYTHON:-python3}"
if "$PY" -c 'import httpx, websockets' 2>/dev/null; then
  drive() { "$PY" scripts/smoke_stack.py "$@"; }
else
  echo "(driver runs inside $APP_IMAGE: host python3 lacks httpx/websockets)"
  drive() {
    # Runs as the invoking user so it can write the state file in the private work dir.
    docker run --rm --network host --read-only --tmpfs /tmp --user "$(id -u):$(id -g)" \
      -v "$ROOT:/src:ro" -v "$WORK:$WORK" -w /src \
      -e SMOKE_BASE_URL -e SMOKE_STATE -e SMOKE_ADMIN_EMAIL -e SMOKE_ADMIN_PASSWORD -e SMOKE_METRICS_TOKEN \
      -e SMOKE_TENANT_B -e SMOKE_TENANT_B_EMAIL -e SMOKE_TENANT_B_PASSWORD \
      --entrypoint python "$APP_IMAGE" scripts/smoke_stack.py "$@"
  }
fi

readyz() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/readyz" || true; }

# Entries still in the work streams (not yet acked and deleted) = alerts in flight or not started.
queue_depth() {
  local total=0 n stream
  for stream in lgsotf:q:alerts:high lgsotf:q:alerts:normal; do
    n="$("${COMPOSE[@]}" exec -T redis redis-cli XLEN "$stream" | tr -dc '0-9')"
    total=$((total + ${n:-0}))
  done
  echo "$total"
}

interrupt_worker() {  # $1: description, rest: compose command
  local what="$1" depth
  shift
  depth="$(queue_depth)"
  [ "$depth" -gt 0 ] || fail "queue already drained before the $what; raise SMOKE_BURST"
  echo "ok    $depth queue entries in flight at the $what"
  "${COMPOSE[@]}" "$@"
}

step "customer flow over the HTTP API"
drive flow --timeout 180

step "worker killed (SIGKILL) mid-processing: no alert may be lost"
drive burst --count "$BURST"
sleep 1  # let the worker start some runs, so the kill lands mid-run rather than before any work
interrupt_worker "worker kill" kill -s SIGKILL worker
"${COMPOSE[@]}" start worker
drive settled --timeout 360

step "worker restarted gracefully (SIGTERM drain) mid-processing"
drive burst --count "$BURST"
interrupt_worker "graceful restart" restart worker
drive settled --timeout 360

step "redis outage: readiness must fail and recover"
"${COMPOSE[@]}" stop redis
drive unready --timeout 60
for port in "$WORKER_PORT" "$SCHEDULER_PORT"; do
  code="$(readyz "$port")"
  [ "$code" = "503" ] || fail "readyz on :$port answered $code during the redis outage (want 503)"
  echo "ok    :$port/readyz -> 503 while redis is down"
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/healthz")" = "200" ] || fail "api liveness failed during the outage"
echo "ok    api /healthz stays 200 (liveness has no dependencies)"
"${COMPOSE[@]}" start redis
drive ready --timeout 120
for port in "$WORKER_PORT" "$SCHEDULER_PORT"; do
  for _ in $(seq 1 60); do [ "$(readyz "$port")" = "200" ] && break; sleep 1; done
  [ "$(readyz "$port")" = "200" ] || fail "readyz on :$port did not recover"
  echo "ok    :$port/readyz -> 200 after redis is back"
done
drive burst --count 3
drive settled --timeout 180

step "final state"
"${COMPOSE[@]}" ps -a --format '{{.Service}}: {{.State}} {{.Status}}'
echo
echo "SMOKE PASSED"
