#!/usr/bin/env bash
# LG-SOTF quickstart: from a clone to triaged alerts in the web UI, with the time measured.
#
#   scripts/quickstart.sh                     # offline fake model (deterministic, no key, no GPU)
#   scripts/quickstart.sh --ollama qwen3:8b   # a local model served by Ollama inside the stack
#   scripts/quickstart.sh --down              # stop the stack and delete its data and secrets
#   make quickstart [OLLAMA=qwen3:8b]         # the same through make
#
# Steps (each prints its elapsed time):
#   1. secrets: scripts/generate_secrets.py writes a private env file
#      ($QS_DIR/stack.env, mode 0600, directory 0700); re-runs keep existing
#      secrets;
#   2. images: builds lg-sotf:dev and lg-sotf-frontend:dev when they are
#      missing (--build rebuilds, --no-build never builds);
#   3. model (--ollama only): pulls the model into the ollama-models volume
#      through the one-shot ollama-pull service (docker/docker-compose.ollama.yml);
#   4. stack: docker compose up of postgres, redis, migrate, api, worker,
#      scheduler and the web UI with the production-like overlay
#      (docker/docker-compose.prod.yml: two database roles, secrets required),
#      waiting until every service is healthy;
#   5. tenant: creates tenant "demo" and its admin with the lg-sotf CLI; the
#      password is generated and written to $QS_DIR/admin-credentials.txt
#      (0600), never printed;
#   6. demo: scripts/demo/seed_demo.py creates an ingest API key
#      ($QS_DIR/ingest-api-key), posts scripts/demo/alerts.json and waits
#      until every alert is triaged, then prints the measured time to the first
#      verdict (from the start of this script and from ingest). The times are
#      also written to $QS_DIR/timing.json.
#
# The UI is served on http://localhost:$QS_UI_PORT; browsers treat localhost as
# a secure context, so the Secure session cookie works without TLS. Anywhere
# else, put TLS in front (docs/deployment.md).
#
# Needs docker with compose v2 and python3. Environment overrides:
#   QS_DIR               state directory (default .quickstart in the repository)
#   QS_PROJECT           compose project name (default lgsotf-quickstart)
#   QS_UI_PORT, QS_API_PORT, QS_WORKER_PORT, QS_SCHEDULER_PORT   host ports (3000/8000/9101/9102)
#   QS_TRIAGE_TIMEOUT    seconds to wait for triage (default 900)
#   APP_IMAGE, FRONTEND_IMAGE   images (default lg-sotf:dev, lg-sotf-frontend:dev)
#   POSTGRES_IMAGE, REDIS_IMAGE, OLLAMA_IMAGE, PYTHON_BASE_IMAGE, NODE_IMAGE, NGINX_IMAGE, BUILD_CA_FILE
#   EDGE_SUBNET, EDGE_FRONTEND_IP, EDGE_API_IP   the UI network, when 172.31.250.0/29 is taken

set -euo pipefail

STARTED_AT="$(date +%s)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODEL=""
BUILD="auto"
DOWN=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --ollama)
      [ "$#" -ge 2 ] || { echo "--ollama needs a model name, e.g. --ollama qwen3:8b" >&2; exit 2; }
      MODEL="$2"
      shift
      ;;
    --build) BUILD="always" ;;
    --no-build) BUILD="never" ;;
    --down) DOWN=1 ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ -n "$MODEL" ] && ! [[ "$MODEL" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$ ]]; then
  echo "invalid model name: $MODEL" >&2
  exit 2
fi

QS_DIR="${QS_DIR:-$ROOT/.quickstart}"
PROJECT="${QS_PROJECT:-lgsotf-quickstart}"
UI_PORT="${QS_UI_PORT:-3000}"
API_PORT="${QS_API_PORT:-8000}"
WORKER_PORT="${QS_WORKER_PORT:-9101}"
SCHEDULER_PORT="${QS_SCHEDULER_PORT:-9102}"
TRIAGE_TIMEOUT="${QS_TRIAGE_TIMEOUT:-900}"
APP_IMAGE="${APP_IMAGE:-lg-sotf:dev}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-lg-sotf-frontend:dev}"
UI_URL="http://localhost:${UI_PORT}"
TENANT="demo"
ADMIN_EMAIL="admin@demo.example.com"

ENV_FILE="$QS_DIR/stack.env"
CREDS="$QS_DIR/admin-credentials.txt"
KEY_FILE="$QS_DIR/ingest-api-key"
TIMING="$QS_DIR/timing.json"

elapsed() { printf '%ss' "$(($(date +%s) - STARTED_AT))"; }
step() { printf '\n==> [%s] %s\n' "$(elapsed)" "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "docker compose v2 is not available"
command -v python3 >/dev/null || fail "python3 is not installed"

COMPOSE_FILES=(-f docker/docker-compose.yml -f docker/docker-compose.prod.yml)
if [ -n "$MODEL" ] || [ "$DOWN" -eq 1 ]; then
  COMPOSE_FILES+=(-f docker/docker-compose.ollama.yml)
fi
COMPOSE=(docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" --env-file "$ENV_FILE" --profile frontend)

# ---------------------------------------------------------------------- down
if [ "$DOWN" -eq 1 ]; then
  if [ -f "$ENV_FILE" ]; then
    "${COMPOSE[@]}" --profile ollama-pull down -v --remove-orphans
  fi
  rm -rf "$QS_DIR"
  echo "quickstart stack ($PROJECT) stopped; its volumes and $QS_DIR were deleted"
  exit 0
fi

on_error() {
  local rc=$?
  [ "$rc" -eq 0 ] && return
  if [ -f "$ENV_FILE" ]; then
    echo "--- stack status (rc=$rc) ---" >&2
    "${COMPOSE[@]}" ps -a >&2 || true
    "${COMPOSE[@]}" logs --no-color --tail 30 migrate api worker >&2 || true
  fi
  echo "The stack was left as it is. Re-run this script, or remove everything with: $0 --down" >&2
}
trap on_error EXIT

# ------------------------------------------------------------------- secrets
step "secrets and settings in $ENV_FILE"
mkdir -p "$QS_DIR"
chmod 700 "$QS_DIR"
[ -f "$ENV_FILE" ] || install -m 600 /dev/null "$ENV_FILE"
chmod 600 "$ENV_FILE"
python3 scripts/generate_secrets.py --append "$ENV_FILE" >/dev/null

# Replace (or add) a non-secret KEY=value line; secrets above are never rewritten.
set_value() {
  local tmp
  tmp="$(mktemp "$QS_DIR/.env.XXXXXX")"
  grep -v "^$1=" "$ENV_FILE" >"$tmp" || true
  printf '%s=%s\n' "$1" "$2" >>"$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}
unset_value() {
  local tmp
  tmp="$(mktemp "$QS_DIR/.env.XXXXXX")"
  grep -v "^$1=" "$ENV_FILE" >"$tmp" || true
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

set_value LG_SOTF_API__CORS_ORIGINS "[\"$UI_URL\"]"
set_value LG_SOTF_API__PUBLIC_URL "$UI_URL"
set_value API_PORT "$API_PORT"
set_value FRONTEND_PORT "$UI_PORT"
set_value WORKER_HEALTH_PORT "$WORKER_PORT"
set_value SCHEDULER_HEALTH_PORT "$SCHEDULER_PORT"
set_value APP_IMAGE "$APP_IMAGE"
set_value FRONTEND_IMAGE "$FRONTEND_IMAGE"
for var in POSTGRES_IMAGE REDIS_IMAGE OLLAMA_IMAGE EDGE_SUBNET EDGE_FRONTEND_IP EDGE_API_IP; do
  if [ -n "${!var:-}" ]; then set_value "$var" "${!var}"; fi
done
if [ -n "$MODEL" ]; then
  set_value OLLAMA_MODEL "$MODEL"
  PROVIDER="ollama"
else
  unset_value OLLAMA_MODEL
  PROVIDER="fake"
fi

# -------------------------------------------------------------------- images
# The same build as `make image`, without needing make.
build_app() {
  local version revision
  version="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/lg_sotf/__init__.py)"
  revision="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  docker build -f docker/Dockerfile -t "$APP_IMAGE" \
    --build-arg BASE_IMAGE="${PYTHON_BASE_IMAGE:-}" \
    --build-arg VERSION="$version" \
    --build-arg REVISION="$revision" \
    --build-arg CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    ${BUILD_CA_FILE:+--secret id=build_ca,src="$BUILD_CA_FILE"} \
    . >"$QS_DIR/build-app.log" 2>&1 \
    || { tail -40 "$QS_DIR/build-app.log" >&2; fail "backend image build failed (log: $QS_DIR/build-app.log)"; }
}
build_frontend() {
  docker build -t "$FRONTEND_IMAGE" \
    ${NODE_IMAGE:+--build-arg NODE_IMAGE="$NODE_IMAGE"} \
    ${NGINX_IMAGE:+--build-arg NGINX_IMAGE="$NGINX_IMAGE"} \
    ${BUILD_CA_FILE:+--secret id=build_ca,src="$BUILD_CA_FILE"} \
    src/lg_front >"$QS_DIR/build-frontend.log" 2>&1 \
    || { tail -40 "$QS_DIR/build-frontend.log" >&2; fail "frontend image build failed (log: $QS_DIR/build-frontend.log)"; }
}
for pair in "app:$APP_IMAGE" "frontend:$FRONTEND_IMAGE"; do
  kind="${pair%%:*}"
  image="${pair#*:}"
  if [ "$BUILD" = "always" ] || { [ "$BUILD" = "auto" ] && ! docker image inspect "$image" >/dev/null 2>&1; }; then
    step "building $image (first run only; takes a few minutes)"
    "build_$kind"
  fi
  docker image inspect "$image" >/dev/null 2>&1 || fail "image $image not found (drop --no-build)"
done

# --------------------------------------------------------------------- model
if [ -n "$MODEL" ]; then
  step "pulling $MODEL into the ollama-models volume (log: $QS_DIR/ollama-pull.log)"
  "${COMPOSE[@]}" --profile ollama-pull run --rm ollama-pull >"$QS_DIR/ollama-pull.log" 2>&1 \
    || { tail -20 "$QS_DIR/ollama-pull.log" >&2; fail "could not pull $MODEL"; }
fi

# --------------------------------------------------------------------- stack
SERVICES=(postgres redis migrate api worker scheduler frontend)
[ -z "$MODEL" ] || SERVICES+=(ollama)
if [ -z "$("${COMPOSE[@]}" ps -q api 2>/dev/null)" ]; then
  for port in "$UI_PORT" "$API_PORT" "$WORKER_PORT" "$SCHEDULER_PORT"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      fail "port $port is already in use (set QS_UI_PORT/QS_API_PORT/QS_WORKER_PORT/QS_SCHEDULER_PORT)"
    fi
  done
fi
step "starting the stack ($PROJECT, model: ${MODEL:-fake})"
"${COMPOSE[@]}" up -d --no-build --remove-orphans --wait --wait-timeout 300 "${SERVICES[@]}"
"${COMPOSE[@]}" ps --format '{{.Service}}: {{.Status}}'

# -------------------------------------------------------------------- tenant
if [ ! -f "$CREDS" ]; then
  step "creating tenant \"$TENANT\" and its admin"
  ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  printf '%s\n' "$ADMIN_PASSWORD" | "${COMPOSE[@]}" run --rm --no-deps -T migrate \
    create-tenant --id "$TENANT" --name "Demo SOC" --admin-email "$ADMIN_EMAIL" --password-stdin \
    >"$QS_DIR/create-tenant.log" 2>&1 \
    || { tail -5 "$QS_DIR/create-tenant.log" >&2; fail "could not create the demo tenant (start over with: $0 --down)"; }
  install -m 600 /dev/null "$CREDS"
  {
    echo "# LG-SOTF quickstart admin. Keep this file private; change the password after signing in."
    echo "URL=$UI_URL"
    echo "TENANT=$TENANT"
    echo "EMAIL=$ADMIN_EMAIL"
    echo "PASSWORD=$ADMIN_PASSWORD"
  } >"$CREDS"
  unset ADMIN_PASSWORD
fi

# ---------------------------------------------------------------------- demo
step "posting the demo alerts and waiting for triage"
python3 scripts/demo/seed_demo.py \
  --base-url "http://127.0.0.1:$API_PORT" \
  --credentials "$CREDS" \
  --api-key-file "$KEY_FILE" \
  --started-at "$STARTED_AT" \
  --timeout "$TRIAGE_TIMEOUT" \
  --timing-out "$TIMING" \
  --provider "$PROVIDER"

trap - EXIT
cat <<EOF

LG-SOTF is running ($(elapsed) in total).
  Web UI:          $UI_URL   (tenant "$TENANT")
  Admin sign-in:   $CREDS   (email and password; not shown here)
  Ingest API key:  $KEY_FILE
  Model:           ${MODEL:-fake (offline keyword heuristic, not a detection model)}
  Measured times:  $TIMING
  Stop and delete: $0 --down
EOF
