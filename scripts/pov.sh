#!/usr/bin/env bash
# LG-SOTF proof-of-value (PoV) install: a prospect evaluates LG-SOTF on its own alerts.
#
#   scripts/pov.sh --siem-host wazuh.prospect.example              # local model (Ollama, qwen3:8b)
#   scripts/pov.sh --siem-host siem.example --ollama qwen3:14b       # another local model
#   POV_LLM_API_KEY=... scripts/pov.sh --siem-host siem.example \
#       --llm-url https://api.mistral.ai/v1 --llm-model mistral-small-latest   # an EU endpoint
#   scripts/pov.sh --allow-host misp.prospect.example                # add a host to the allow-list
#   scripts/pov.sh --backtest 90                                     # backtest the last 90 days
#   scripts/pov.sh --down                                            # stop and delete everything
#   make pov SIEM=wazuh.prospect.example [OLLAMA=qwen3:8b]           # the same through make
#
# What the profile enforces (docker/docker-compose.pov.yml, docs/pov.md):
#   * response: the install kill switch records every action as dry_run, the
#     default autonomy is "disabled" for every risk, no response connector is
#     configured, notifications and ticketing are off;
#   * sources: read-only (sources that mark or move mailbox messages are refused);
#   * egress: an allow-list of the SIEM host(s) given here plus the model
#     endpoint; sources, integrations, webhooks, enrichment and the LLM client
#     refuse every other host;
#   * model: local (Ollama) by default, or an OpenAI-compatible EU endpoint;
#     DeepSeek endpoints are refused.
#
# Hosts accumulate across runs: re-run with --siem-host/--allow-host to add one;
# remove one by editing POV_HOSTS in $POV_DIR/stack.env, then re-run.
#
# Steps: secrets ($POV_DIR/stack.env, 0600), images (built when missing), model
# (Ollama only), stack (postgres, redis, migrate, api, worker, scheduler, web UI,
# production-like overlay), tenant and admin ($POV_DIR/admin-credentials.txt,
# 0600, never printed), then the next steps.
#
# Environment overrides:
#   POV_DIR              state directory (default .pov in the repository)
#   POV_PROJECT          compose project name (default lgsotf-pov)
#   POV_UI_PORT, POV_API_PORT, POV_WORKER_PORT, POV_SCHEDULER_PORT   host ports (3000/8000/9101/9102)
#   POV_LLM_API_KEY      API key of the --llm-url endpoint (never on the command line)
#   APP_IMAGE, FRONTEND_IMAGE, POSTGRES_IMAGE, REDIS_IMAGE, OLLAMA_IMAGE, PYTHON_BASE_IMAGE, BUILD_CA_FILE
#   EDGE_SUBNET, EDGE_FRONTEND_IP, EDGE_API_IP   the UI network, when 172.31.250.0/29 is taken

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOSTS_ARG=()
OLLAMA_ARG=""
LLM_URL=""
LLM_MODEL=""
ALLOW_PRIVATE=""
TENANT_ARG=""
ADMIN_EMAIL_ARG=""
BUILD="auto"
DOWN=0
BACKTEST_DAYS=""
need() { [ "$2" -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; }; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --siem-host|--allow-host) need "$1" "$#"; IFS=', ' read -r -a more <<<"$2"; HOSTS_ARG+=("${more[@]}"); shift ;;
    --ollama) need "$1" "$#"; OLLAMA_ARG="$2"; shift ;;
    --llm-url) need "$1" "$#"; LLM_URL="$2"; shift ;;
    --llm-model) need "$1" "$#"; LLM_MODEL="$2"; shift ;;
    --allow-private) ALLOW_PRIVATE="true" ;;
    --tenant) need "$1" "$#"; TENANT_ARG="$2"; shift ;;
    --admin-email) need "$1" "$#"; ADMIN_EMAIL_ARG="$2"; shift ;;
    --backtest) need "$1" "$#"; BACKTEST_DAYS="$2"; shift ;;
    --build) BUILD="always" ;;
    --no-build) BUILD="never" ;;
    --down) DOWN=1 ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

POV_DIR="${POV_DIR:-$ROOT/.pov}"
PROJECT="${POV_PROJECT:-lgsotf-pov}"
UI_PORT="${POV_UI_PORT:-3000}"
API_PORT="${POV_API_PORT:-8000}"
WORKER_PORT="${POV_WORKER_PORT:-9101}"
SCHEDULER_PORT="${POV_SCHEDULER_PORT:-9102}"
APP_IMAGE="${APP_IMAGE:-lg-sotf:dev}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-lg-sotf-frontend:dev}"
UI_URL="http://localhost:${UI_PORT}"
ENV_FILE="$POV_DIR/stack.env"
CREDS="$POV_DIR/admin-credentials.txt"

saved() { if [ -f "$ENV_FILE" ]; then sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; fi; }

command -v docker >/dev/null || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "docker compose v2 is not available"
command -v python3 >/dev/null || fail "python3 is not installed"

compose_cmd() {
  local files=(-f docker/docker-compose.yml -f docker/docker-compose.prod.yml)
  if [ "$1" = "ollama" ]; then files+=(-f docker/docker-compose.ollama.yml); fi
  files+=(-f docker/docker-compose.pov.yml)
  COMPOSE=(docker compose -p "$PROJECT" "${files[@]}" --env-file "$ENV_FILE" --profile frontend)
}

# ---------------------------------------------------------------------- down
if [ "$DOWN" -eq 1 ]; then
  if [ -f "$ENV_FILE" ]; then
    compose_cmd ollama
    "${COMPOSE[@]}" --profile ollama-pull down -v --remove-orphans
  fi
  rm -rf "$POV_DIR"
  echo "PoV stack ($PROJECT) stopped; its volumes and $POV_DIR were deleted"
  exit 0
fi

# ------------------------------------------------------------------ backtest
if [ -n "$BACKTEST_DAYS" ]; then
  [[ "$BACKTEST_DAYS" =~ ^[0-9]{1,3}$ ]] || fail "--backtest takes a number of days (1-366)"
  [ -f "$ENV_FILE" ] || fail "no PoV stack here; install it first"
  compose_cmd "$(saved POV_LLM_MODE)"
  mkdir -p "$POV_DIR/reports"
  report="/reports/backtest-$(date -u +%Y%m%dT%H%M%SZ).json"
  step "backtest of tenant $(saved POV_TENANT) over the last $BACKTEST_DAYS days (read-only)"
  "${COMPOSE[@]}" run --rm --no-deps -T --user "$(id -u):$(id -g)" -v "$POV_DIR/reports:/reports" worker \
    eval --from-history --tenant "$(saved POV_TENANT)" --days "$BACKTEST_DAYS" --report "$report"
  echo "Report: $POV_DIR/reports/$(basename "$report") (and the .md next to it)"
  exit 0
fi

# ------------------------------------------------------------- model choice
if [ -n "$LLM_URL" ] && [ -n "$OLLAMA_ARG" ]; then fail "choose --ollama or --llm-url, not both"; fi
if [ -n "$LLM_URL" ]; then
  MODE="url"
elif [ -n "$OLLAMA_ARG" ]; then
  MODE="ollama"
else
  MODE="$(saved POV_LLM_MODE)"
  MODE="${MODE:-ollama}"
fi
if [ "$MODE" = "url" ]; then
  LLM_URL="${LLM_URL:-$(saved LG_SOTF_LLM__BASE_URL)}"
  LLM_MODEL="${LLM_MODEL:-$(saved LG_SOTF_LLM__FAST__MODEL)}"
  [ -n "$LLM_MODEL" ] || fail "--llm-url needs --llm-model"
  [[ "$LLM_URL" =~ ^https://([A-Za-z0-9.-]+)(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] \
    || fail "--llm-url must be an https URL without credentials, e.g. https://api.mistral.ai/v1"
  LLM_HOST="${BASH_REMATCH[1],,}"
  case "$LLM_HOST" in
    *deepseek*) fail "DeepSeek endpoints are never used for a PoV: choose an EU-hosted or local model" ;;
  esac
else
  OLLAMA_MODEL="${OLLAMA_ARG:-$(saved OLLAMA_MODEL)}"
  OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:8b}"
  LLM_HOST="ollama"
fi
for value in "$LLM_MODEL" "${OLLAMA_MODEL:-}"; do
  if [ -n "$value" ] && ! [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$ ]]; then fail "invalid model name: $value"; fi
done

# ------------------------------------------------------------------- hosts
HOSTS=()
read -r -a HOSTS <<<"$(saved POV_HOSTS | tr ',' ' ')"
for host in "${HOSTS_ARG[@]}"; do
  host="${host,,}"
  [ -n "$host" ] || continue
  [[ "$host" =~ ^(\*\.)?[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9])?$|^[0-9a-f:.]{2,45}$ ]] \
    || fail "not a host name or address: $host (no scheme, port or path)"
  case " ${HOSTS[*]} " in *" $host "*) ;; *) HOSTS+=("$host") ;; esac
done
[ "${#HOSTS[@]}" -gt 0 ] || fail "give the prospect's SIEM host with --siem-host (repeatable)"
EGRESS="$(printf '%s,' "${HOSTS[@]}" "$LLM_HOST")"
EGRESS="${EGRESS%,}"
TENANT="${TENANT_ARG:-$(saved POV_TENANT)}"
TENANT="${TENANT:-pov}"
ADMIN_EMAIL="${ADMIN_EMAIL_ARG:-admin@${TENANT}.example.com}"
[[ "$TENANT" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || fail "invalid tenant id: $TENANT"

# ------------------------------------------------------------------- secrets
step "secrets and settings in $ENV_FILE"
mkdir -p "$POV_DIR"
chmod 700 "$POV_DIR"
[ -f "$ENV_FILE" ] || install -m 600 /dev/null "$ENV_FILE"
chmod 600 "$ENV_FILE"
python3 scripts/generate_secrets.py --append "$ENV_FILE" >/dev/null

# Replace (or add, or with no value remove) a non-secret KEY=value line.
set_value() {
  local tmp
  tmp="$(mktemp "$POV_DIR/.env.XXXXXX")"
  grep -v "^$1=" "$ENV_FILE" >"$tmp" || true
  if [ "$#" -ge 2 ]; then printf '%s=%s\n' "$1" "$2" >>"$tmp"; fi
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

set_value POV_HOSTS "$(IFS=,; echo "${HOSTS[*]}")"
set_value POV_EGRESS_HOSTS "$EGRESS"
set_value POV_TENANT "$TENANT"
set_value POV_LLM_MODE "$MODE"
if [ -n "$ALLOW_PRIVATE" ]; then set_value POV_ALLOW_PRIVATE true; fi
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
# No response connector: the install webhook stays unset whatever the shell holds.
set_value LG_SOTF_RESPONSE__WEBHOOK_URL
set_value LG_SOTF_RESPONSE__WEBHOOK_SECRET
unset LG_SOTF_RESPONSE__WEBHOOK_URL LG_SOTF_RESPONSE__WEBHOOK_SECRET
if [ "$MODE" = "url" ]; then
  set_value LG_SOTF_LLM__PROVIDER openai_compatible
  set_value LG_SOTF_LLM__BASE_URL "$LLM_URL"
  set_value LG_SOTF_LLM__FAST__MODEL "$LLM_MODEL"
  set_value LG_SOTF_LLM__DEEP__MODEL "$LLM_MODEL"
  if [ -n "${POV_LLM_API_KEY:-}" ]; then set_value LG_SOTF_LLM__API_KEY "$POV_LLM_API_KEY"; fi
  set_value OLLAMA_MODEL
else
  set_value LG_SOTF_LLM__PROVIDER ollama
  set_value LG_SOTF_LLM__BASE_URL http://ollama:11434/v1
  set_value LG_SOTF_LLM__FAST__MODEL "$OLLAMA_MODEL"
  set_value LG_SOTF_LLM__DEEP__MODEL "$OLLAMA_MODEL"
  set_value LG_SOTF_LLM__API_KEY
  set_value OLLAMA_MODEL "$OLLAMA_MODEL"
fi
compose_cmd "$MODE"

on_error() {
  local rc=$?
  [ "$rc" -eq 0 ] && return
  echo "--- stack status (rc=$rc) ---" >&2
  "${COMPOSE[@]}" ps -a >&2 || true
  "${COMPOSE[@]}" logs --no-color --tail 30 migrate api worker >&2 || true
  echo "The stack was left as it is. Re-run this script, or remove everything with: $0 --down" >&2
}
trap on_error EXIT

# -------------------------------------------------------------------- images
build_image() {
  local image="$1" log="$POV_DIR/build-$2.log"
  shift 2
  docker build -t "$image" ${BUILD_CA_FILE:+--secret id=build_ca,src="$BUILD_CA_FILE"} "$@" >"$log" 2>&1 \
    || { tail -40 "$log" >&2; fail "image build failed (log: $log)"; }
}
for image in "$APP_IMAGE" "$FRONTEND_IMAGE"; do
  if [ "$BUILD" = "always" ] || { [ "$BUILD" = "auto" ] && ! docker image inspect "$image" >/dev/null 2>&1; }; then
    step "building $image (first run only; takes a few minutes)"
    if [ "$image" = "$APP_IMAGE" ]; then
      build_image "$image" app -f docker/Dockerfile --build-arg BASE_IMAGE="${PYTHON_BASE_IMAGE:-python:3.11-slim}" \
        --build-arg VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/lg_sotf/__init__.py)" \
        --build-arg REVISION="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" .
    else
      build_image "$image" frontend src/lg_front
    fi
  fi
  docker image inspect "$image" >/dev/null 2>&1 || fail "image $image not found (drop --no-build)"
done

# --------------------------------------------------------------------- model
SERVICES=(postgres redis migrate api worker scheduler frontend)
if [ "$MODE" = "ollama" ]; then
  step "pulling $OLLAMA_MODEL into the ollama-models volume (log: $POV_DIR/ollama-pull.log)"
  "${COMPOSE[@]}" --profile ollama-pull run --rm ollama-pull >"$POV_DIR/ollama-pull.log" 2>&1 \
    || { tail -20 "$POV_DIR/ollama-pull.log" >&2; fail "could not pull $OLLAMA_MODEL"; }
  SERVICES+=(ollama)
fi

# --------------------------------------------------------------------- stack
if [ -z "$("${COMPOSE[@]}" ps -q api 2>/dev/null)" ]; then
  for port in "$UI_PORT" "$API_PORT" "$WORKER_PORT" "$SCHEDULER_PORT"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      fail "port $port is already in use (set POV_UI_PORT/POV_API_PORT/POV_WORKER_PORT/POV_SCHEDULER_PORT)"
    fi
  done
fi
step "starting the PoV stack ($PROJECT; egress allow-list: $EGRESS)"
"${COMPOSE[@]}" up -d --no-build --remove-orphans --wait --wait-timeout 300 "${SERVICES[@]}"

# -------------------------------------------------------------------- tenant
if [ ! -f "$CREDS" ]; then
  step "creating tenant \"$TENANT\" and its admin"
  ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  printf '%s\n' "$ADMIN_PASSWORD" | "${COMPOSE[@]}" run --rm --no-deps -T migrate \
    create-tenant --id "$TENANT" --name "Proof of value" --admin-email "$ADMIN_EMAIL" --password-stdin \
    >"$POV_DIR/create-tenant.log" 2>&1 \
    || { tail -5 "$POV_DIR/create-tenant.log" >&2; fail "could not create tenant $TENANT (start over with: $0 --down)"; }
  install -m 600 /dev/null "$CREDS"
  {
    echo "# LG-SOTF PoV admin. Keep this file private; change the password after signing in."
    echo "URL=$UI_URL"
    echo "TENANT=$TENANT"
    echo "EMAIL=$ADMIN_EMAIL"
    echo "PASSWORD=$ADMIN_PASSWORD"
  } >"$CREDS"
  unset ADMIN_PASSWORD
fi

trap - EXIT
if [ "$MODE" = "url" ]; then MODEL_DESC="$LLM_MODEL at $LLM_HOST"; else MODEL_DESC="$OLLAMA_MODEL (local, Ollama)"; fi
cat <<EOF

LG-SOTF PoV profile is running.
  Web UI:            $UI_URL   (tenant "$TENANT")
  Admin sign-in:     $CREDS   (not shown here)
  Model:             $MODEL_DESC
  Egress allow-list: $EGRESS
  Response:          dry-run only (install kill switch); autonomy disabled for every risk

Next steps
  1. Connect a source: sign in, open Settings > Sources and add the SIEM
     (read-only credentials; its host must be on the allow-list above, add
     one with: $0 --allow-host HOST). Wait for the first poll.
  2. Run the backtest (lg-sotf eval --from-history) once analysts' decisions
     are in the history:
       $0 --backtest 90
  3. Stop and delete everything at the end of the PoV: $0 --down
EOF
