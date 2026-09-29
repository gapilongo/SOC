#!/usr/bin/env bash
# Deploy (or roll back) one LG-SOTF environment on this VM. Runs as the
# non-root deploy user (member of the docker group); see docs/cicd.md.
#
#   deploy.sh --env dev --domain soc-dev.example.org \
#             --app-image ghcr.io/gapilongo/lg-sotf@sha256:... \
#             --frontend-image ghcr.io/gapilongo/lg-sotf-frontend@sha256:... \
#             --version sha-1a2b3c4 --secrets-stdin < values
#   deploy.sh --env dev --domain soc-dev.example.org --rollback   # back to the previous version
#   deploy.sh --env dev --status
#
# The GitHub "Deploy" workflow uploads the bundle (this directory plus the
# compose files) to <root>/env/<env>/releases/<commit>/ and runs this script
# from there with the secrets as KEY=value lines on stdin.
#
# What a deploy does:
#   1. stores the values from stdin in <root>/env/<env>/secrets.env (0600) and
#      renders the compose env file <root>/env/<env>/.env (0600); nothing is
#      printed;
#   2. makes sure the shared `lgsotf-proxy` network and the Caddy edge
#      (<root>/edge) run, and installs this environment's site;
#   3. pulls the images (a GHCR read token, when given, is used for this pull
#      only and never stored), runs `lg-sotf migrate`, then
#      `docker compose up -d --wait`;
#   4. checks https://<domain>/healthz, /readyz, /api (401), / and /config.js
#      through Caddy;
#   5. on success records the version (current + previous), prunes old images
#      and release directories; on failure redeploys the previous version
#      automatically, checks it the same way and exits non-zero.
#
# Several environments can share one VM: each gets its own compose project
# (lgsotf-<env>), directory, volumes and internal networks, and its own
# hostname on the single Caddy that owns ports 80/443.
#
# Options:
#   --env NAME             environment (dev, uat, prod or another short name)
#   --domain HOST          public hostname (DNS A record -> this VM)
#   --root DIR             state directory (default /opt/lg-sotf)
#   --app-image REF        backend image, ideally repo@sha256:digest
#   --frontend-image REF   frontend image
#   --version LABEL        human-readable version (image tag), for records
#   --secrets-stdin        read KEY=value lines from stdin (see ALLOWED_KEYS)
#   --tls acme|internal    acme: Let's Encrypt (default); internal: Caddy's own
#                          CA, for local tests without a public hostname
#   --http-port N / --https-port N   host ports of the edge (default 80/443)
#   --slot N               address slot of the environment's internal network
#                          (1-30; default dev=1, uat=2, prod=3)
#   --health-timeout S     seconds to wait for the health checks (default 300)
#   --rollback             redeploy the previous version (no image arguments)
#   --status               print the current and previous versions
#
# Environment (optional): LGSOTF_PROXY_SUBNET (172.31.251.0/24),
# LGSOTF_CADDY_IP (172.31.251.2), LGSOTF_KEEP_RELEASES (5).

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENV_NAME=""
DOMAIN=""
ROOT="/opt/lg-sotf"
NEW_APP_IMAGE=""
NEW_FRONTEND_IMAGE=""
VERSION=""
SECRETS_STDIN=0
TLS_MODE="acme"
HTTP_PORT=80
HTTPS_PORT=443
SLOT=""
HEALTH_TIMEOUT=300
ACTION="deploy"
PROXY_NETWORK="lgsotf-proxy"
PROXY_SUBNET="${LGSOTF_PROXY_SUBNET:-172.31.251.0/24}"
CADDY_IP="${LGSOTF_CADDY_IP:-172.31.251.2}"
KEEP_RELEASES="${LGSOTF_KEEP_RELEASES:-5}"

# Keys accepted on stdin. Anything else is refused, so the caller cannot
# override computed settings (images, networks, trusted proxies).
ALLOWED_KEYS=(
  POSTGRES_SUPERUSER_PASSWORD LGSOTF_OWNER_PASSWORD LGSOTF_APP_PASSWORD
  LG_SOTF_AUTH__JWT_SECRET LG_SOTF_SECURITY__ENCRYPTION_KEYS LG_SOTF_SECURITY__INDICATOR_HMAC_KEY
  LG_SOTF_API__METRICS_TOKEN LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD
  ANTHROPIC_API_KEY LG_SOTF_LLM__PROVIDER LG_SOTF_WORKER__CONCURRENCY LG_SOTF_OBSERVABILITY__LOG_LEVEL
  ACME_EMAIL POSTGRES_IMAGE REDIS_IMAGE CADDY_IMAGE
  POSTGRES_MEM POSTGRES_CPUS REDIS_MEM REDIS_CPUS API_MEM API_CPUS WORKER_MEM WORKER_CPUS
  SCHEDULER_MEM SCHEDULER_CPUS FRONTEND_MEM FRONTEND_CPUS
)
# Used for this run only, never written to disk.
TRANSIENT_KEYS=(GHCR_USER GHCR_TOKEN)
REQUIRED_KEYS=(
  POSTGRES_SUPERUSER_PASSWORD LGSOTF_OWNER_PASSWORD LGSOTF_APP_PASSWORD
  LG_SOTF_AUTH__JWT_SECRET LG_SOTF_SECURITY__ENCRYPTION_KEYS LG_SOTF_SECURITY__INDICATOR_HMAC_KEY
  LG_SOTF_API__METRICS_TOKEN LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD
)

log() { printf '%s [%s] %s\n' "$(date -u +%H:%M:%S)" "${ENV_NAME:-?}" "$*"; }
die() { printf 'ERROR [%s] %s\n' "${ENV_NAME:-?}" "$*" >&2; exit 2; }
usage() { sed -n '2,53p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --env) ENV_NAME="${2:-}"; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --root) ROOT="${2:-}"; shift 2 ;;
    --app-image) NEW_APP_IMAGE="${2:-}"; shift 2 ;;
    --frontend-image) NEW_FRONTEND_IMAGE="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --secrets-stdin) SECRETS_STDIN=1; shift ;;
    --tls) TLS_MODE="${2:-}"; shift 2 ;;
    --http-port) HTTP_PORT="${2:-}"; shift 2 ;;
    --https-port) HTTPS_PORT="${2:-}"; shift 2 ;;
    --slot) SLOT="${2:-}"; shift 2 ;;
    --health-timeout) HEALTH_TIMEOUT="${2:-}"; shift 2 ;;
    --rollback) ACTION="rollback"; shift ;;
    --status) ACTION="status"; shift ;;
    -h|--help) usage 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage 64 ;;
  esac
done

# ------------------------------------------------------------------ validation
[[ "$ENV_NAME" =~ ^[a-z][a-z0-9]{0,11}$ ]] || die "--env must be a short lowercase name (e.g. dev, uat)"
[ "$ENV_NAME" != "edge" ] || die "--env edge is reserved"
[[ "$ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--root must be an absolute path"
if [ -z "$SLOT" ]; then
  case "$ENV_NAME" in dev) SLOT=1 ;; uat) SLOT=2 ;; prod) SLOT=3 ;; *) die "--slot is required for environment $ENV_NAME" ;; esac
fi
[[ "$SLOT" =~ ^[0-9]+$ ]] && [ "$SLOT" -ge 1 ] && [ "$SLOT" -le 30 ] || die "--slot must be 1-30"
[[ "$TLS_MODE" =~ ^(acme|internal)$ ]] || die "--tls must be acme or internal"
[[ "$HTTP_PORT" =~ ^[0-9]{1,5}$ && "$HTTPS_PORT" =~ ^[0-9]{1,5}$ ]] || die "bad port"
[[ "$HEALTH_TIMEOUT" =~ ^[0-9]{1,4}$ ]] || die "bad --health-timeout"
[[ "$KEEP_RELEASES" =~ ^[0-9]{1,3}$ ]] || die "bad LGSOTF_KEEP_RELEASES"
[[ "$PROXY_SUBNET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "bad LGSOTF_PROXY_SUBNET"
[[ "$CADDY_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "bad LGSOTF_CADDY_IP"
if [ "$ACTION" != "status" ]; then
  [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "--domain must be a hostname"
  DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
fi
IMAGE_RE='^[a-z0-9][a-z0-9._/:-]{0,250}(@sha256:[0-9a-f]{64})?$'
if [ "$ACTION" = "deploy" ]; then
  [[ "$NEW_APP_IMAGE" =~ $IMAGE_RE ]] || die "--app-image must be an image reference"
  [[ "$NEW_FRONTEND_IMAGE" =~ $IMAGE_RE ]] || die "--frontend-image must be an image reference"
  [ -n "$VERSION" ] || VERSION="$(printf '%s' "$NEW_APP_IMAGE" | sed -E 's/.*[:@]//' | cut -c1-19)"
  [[ "$VERSION" =~ ^[A-Za-z0-9._+-]{1,64}$ ]] || die "--version must be a short label"
fi

for tool in docker curl flock sed; do
  command -v "$tool" >/dev/null || die "$tool is not installed (run deploy/vm/bootstrap.sh)"
done
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed"

ENV_DIR="$ROOT/env/$ENV_NAME"
EDGE_DIR="$ROOT/edge"
STATE_DIR="$ENV_DIR/state"
SECRETS_FILE="$ENV_DIR/secrets.env"
ENV_FILE="$ENV_DIR/.env"
PROJECT="lgsotf-$ENV_NAME"
EDGE_PROJECT="lgsotf-edge"
PUBLIC_ORIGIN="https://$DOMAIN"
[ "$HTTPS_PORT" = "443" ] || PUBLIC_ORIGIN="https://$DOMAIN:$HTTPS_PORT"

# Per-environment /29 for the frontend <-> api network (fixed addresses so the
# api can trust exactly its frontend's X-Forwarded-For).
EDGE_BASE=$((SLOT * 8))
EDGE_SUBNET="172.31.250.$EDGE_BASE/29"
EDGE_FRONTEND_IP="172.31.250.$((EDGE_BASE + 2))"
EDGE_API_IP="172.31.250.$((EDGE_BASE + 3))"

mkdir -p "$ROOT" "$ENV_DIR" "$STATE_DIR"
chmod 0750 "$ROOT" 2>/dev/null || true

# One deploy per VM at a time (dev and uat may share the edge and the images).
exec 9>"$ROOT/.deploy.lock"
flock -w 900 9 || die "another deploy is still running on this VM"

# ------------------------------------------------------------------ key/value files
# Values are stored single-quoted: compose reads them literally (no ${...}
# interpolation), so a value must not contain a single quote or a line break.
declare -A VALUES=()
declare -A TRANSIENT=()

is_allowed() {
  local k
  for k in "${ALLOWED_KEYS[@]}"; do [ "$k" = "$1" ] && return 0; done
  return 1
}
is_transient() {
  local k
  for k in "${TRANSIENT_KEYS[@]}"; do [ "$k" = "$1" ] && return 0; done
  return 1
}

read_values_from_stdin() {
  local line key value count=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    [[ "$line" == *=* ]] || die "stdin: expected KEY=value lines"
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "stdin: bad key name"
    [[ "$value" != *"'"* ]] || die "stdin: the value of $key contains a single quote (not supported)"
    [ -n "$value" ] || continue
    if is_transient "$key"; then
      TRANSIENT[$key]="$value"
    elif is_allowed "$key"; then
      VALUES[$key]="$value"
    else
      die "stdin: $key is not an accepted key"
    fi
    count=$((count + 1))
  done
  [ "$count" -gt 0 ] || die "--secrets-stdin given but no KEY=value lines were received"
}

load_values_file() {  # $1: file written by write_values_file
  local line key value
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"
    value="${line#*=}"
    value="${value#\'}"
    value="${value%\'}"
    VALUES[$key]="$value"
  done < "$1"
}

atomic_write() {  # $1: target, $2: mode; content on stdin
  local tmp
  tmp="$(mktemp "$1.XXXXXX")"
  cat > "$tmp"
  chmod "$2" "$tmp"
  mv -f "$tmp" "$1"
}

write_values_file() {
  local k
  {
    echo "# LG-SOTF $ENV_NAME: values received from the deploy workflow. Private (0600)."
    for k in "${!VALUES[@]}"; do printf "%s='%s'\n" "$k" "${VALUES[$k]}"; done | sort
  } | atomic_write "$SECRETS_FILE" 0600
}

validate_values() {
  local k
  for k in "${REQUIRED_KEYS[@]}"; do
    [ -n "${VALUES[$k]:-}" ] || die "missing value: $k"
  done
  # Embedded unescaped in postgresql:// URLs by the compose files.
  for k in POSTGRES_SUPERUSER_PASSWORD LGSOTF_OWNER_PASSWORD LGSOTF_APP_PASSWORD; do
    [[ "${VALUES[$k]}" =~ ^[A-Za-z0-9._~-]{16,}$ ]] \
      || die "$k must be at least 16 URL-safe characters (use scripts/generate_secrets.py)"
  done
  [[ "${VALUES[LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL]}" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] \
    || die "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL is not an email address"
  [ -z "${VALUES[ACME_EMAIL]:-}" ] || [[ "${VALUES[ACME_EMAIL]}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] \
    || die "ACME_EMAIL is not an email address"
  local provider="${VALUES[LG_SOTF_LLM__PROVIDER]:-}"
  [ -z "$provider" ] || [[ "$provider" =~ ^(anthropic|openai|gemini|fake)$ ]] \
    || die "LG_SOTF_LLM__PROVIDER must be anthropic, openai, gemini or fake"
  for k in POSTGRES_IMAGE REDIS_IMAGE CADDY_IMAGE; do
    [ -z "${VALUES[$k]:-}" ] || [[ "${VALUES[$k]}" =~ $IMAGE_RE ]] || die "$k must be an image reference"
  done
}

# ------------------------------------------------------------------ rendering
# Compose env file for one version: stored values plus computed settings.
render_env_file() {  # $1 app image, $2 frontend image
  local provider allow_fake k
  provider="${VALUES[LG_SOTF_LLM__PROVIDER]:-}"
  if [ -z "$provider" ]; then
    if [ -n "${VALUES[ANTHROPIC_API_KEY]:-}" ]; then provider=anthropic; else provider=fake; fi
  fi
  if [ "$provider" = "fake" ]; then allow_fake=true; else allow_fake=false; fi
  {
    echo "# Rendered by deploy/vm/deploy.sh for $PROJECT. Private (0600); do not edit."
    for k in "${!VALUES[@]}"; do
      case "$k" in ACME_EMAIL|CADDY_IMAGE|LG_SOTF_LLM__PROVIDER) continue ;; esac
      printf "%s='%s'\n" "$k" "${VALUES[$k]}"
    done | sort
    printf "%s='%s'\n" \
      LGSOTF_ENV "$ENV_NAME" \
      LGSOTF_ENV_DIR "$ENV_DIR" \
      APP_IMAGE "$1" \
      FRONTEND_IMAGE "$2" \
      PROXY_NETWORK "$PROXY_NETWORK" \
      EDGE_SUBNET "$EDGE_SUBNET" \
      EDGE_FRONTEND_IP "$EDGE_FRONTEND_IP" \
      EDGE_API_IP "$EDGE_API_IP" \
      LG_SOTF_API__FORWARDED_ALLOW_IPS "$EDGE_FRONTEND_IP,$CADDY_IP" \
      FRONTEND_TRUSTED_PROXIES "$CADDY_IP" \
      LG_SOTF_API__PUBLIC_URL "$PUBLIC_ORIGIN" \
      LG_SOTF_API__CORS_ORIGINS "[\"$PUBLIC_ORIGIN\"]" \
      LG_SOTF_LLM__PROVIDER "$provider" \
      LG_SOTF_LLM__ALLOW_FAKE "$allow_fake"
  } | atomic_write "$ENV_FILE" 0600
}

render_edge() {
  local global="" tls="" conf="$EDGE_DIR/conf"
  mkdir -p "$conf/sites"
  chmod 0755 "$EDGE_DIR" "$conf" "$conf/sites"
  if [ "$TLS_MODE" = "internal" ]; then
    global="skip_install_trust"
    tls="tls internal"
  elif [ -n "${VALUES[ACME_EMAIL]:-}" ]; then
    global="email ${VALUES[ACME_EMAIL]}"
  fi
  sed -e "s|@@GLOBAL_OPTIONS@@|$global|" "$RELEASE_DIR/deploy/vm/caddy/Caddyfile.tmpl" \
    | atomic_write "$conf/Caddyfile" 0644
  sed -e "s|@@ENV@@|$ENV_NAME|g" -e "s|@@DOMAIN@@|$DOMAIN|g" -e "s|@@TLS@@|$tls|" \
    "$RELEASE_DIR/deploy/vm/caddy/site.caddy.tmpl" | atomic_write "$conf/sites/$ENV_NAME.caddy" 0644
  atomic_write "$EDGE_DIR/compose.yml" 0644 < "$RELEASE_DIR/deploy/vm/docker-compose.edge.yml"
  printf '%s=%s\n' \
    CADDY_IMAGE "${VALUES[CADDY_IMAGE]:-caddy:2.11-alpine}" \
    CADDY_IP "$CADDY_IP" \
    PROXY_NETWORK "$PROXY_NETWORK" \
    EDGE_HTTP_PORT "$HTTP_PORT" \
    EDGE_HTTPS_PORT "$HTTPS_PORT" | atomic_write "$EDGE_DIR/.env" 0600
}

edge() { docker compose -p "$EDGE_PROJECT" -f "$EDGE_DIR/compose.yml" --env-file "$EDGE_DIR/.env" "$@"; }

stack() {  # $1: release dir, rest: compose arguments
  local rel="$1"
  shift
  docker compose -p "$PROJECT" \
    -f "$rel/docker/docker-compose.yml" \
    -f "$rel/docker/docker-compose.prod.yml" \
    -f "$rel/deploy/vm/docker-compose.vm.yml" \
    --env-file "$ENV_FILE" "$@"
}

ensure_edge() {
  if ! docker network inspect "$PROXY_NETWORK" >/dev/null 2>&1; then
    log "creating network $PROXY_NETWORK ($PROXY_SUBNET)"
    docker network create --driver bridge --subnet "$PROXY_SUBNET" "$PROXY_NETWORK" >/dev/null
  fi
  render_edge
  log "starting the edge (Caddy)"
  edge up -d --wait --wait-timeout 120 --quiet-pull || return 1
  edge exec -T caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    || { edge exec -T caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >&2 || true; return 1; }
  edge exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force >/dev/null 2>&1
}

# ------------------------------------------------------------------ images
pull_images() {  # $1 app, $2 frontend, $3 release dir
  local cfg="" rc=0
  if [ -n "${TRANSIENT[GHCR_TOKEN]:-}" ]; then
    # A throwaway client config: the token is not left on the VM.
    cfg="$(mktemp -d)"
    printf '%s' "${TRANSIENT[GHCR_TOKEN]}" \
      | docker --config "$cfg" login ghcr.io -u "${TRANSIENT[GHCR_USER]:-lgsotf}" --password-stdin >/dev/null \
      || { rm -rf "$cfg"; log "GHCR login failed"; return 1; }
  fi
  local image
  for image in "$1" "$2"; do
    log "pulling $image"
    if [ -n "$cfg" ]; then
      docker --config "$cfg" pull -q "$image" >/dev/null || rc=1
    else
      docker pull -q "$image" >/dev/null || rc=1
    fi
  done
  [ -z "$cfg" ] || rm -rf "$cfg"
  [ "$rc" -eq 0 ] || return 1
  stack "$3" pull --quiet postgres redis
}

# ------------------------------------------------------------------ health
CURL_CA=()
health_checks() {  # $1 expected app image
  local deadline=$((SECONDS + HEALTH_TIMEOUT)) body code path want pending
  local base="https://$DOMAIN:$HTTPS_PORT"
  body="$(mktemp)"
  CURL_CA=()
  while :; do
    if [ "$TLS_MODE" = "internal" ] && [ "${#CURL_CA[@]}" -eq 0 ]; then
      if edge exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$STATE_DIR/edge-local-ca.crt" 2>/dev/null \
         && [ -s "$STATE_DIR/edge-local-ca.crt" ]; then
        CURL_CA=(--cacert "$STATE_DIR/edge-local-ca.crt")
      fi
    fi
    pending=""
    # path|expected status|text the body must contain
    for check in \
      "/healthz|200|\"status\":\"ok\"" \
      "/readyz|200|\"status\":\"ok\"" \
      "/api/v1/alerts|401|" \
      "/|200|<div id=\"root\">" \
      "/config.js|200|__LG_SOTF_CONFIG__"; do
      path="${check%%|*}"
      want="${check#*|}"
      code="$(curl -sS --noproxy '*' -o "$body" -w '%{http_code}' --max-time 10 \
        --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" "${CURL_CA[@]}" "$base$path" 2>/dev/null || true)"
      if [ "$code" != "${want%%|*}" ] || ! grep -qF -- "${want#*|}" "$body"; then
        pending="$pending $path($code)"
      fi
    done
    if [ -z "$pending" ]; then
      rm -f "$body"
      break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      rm -f "$body"
      log "health checks failed after ${HEALTH_TIMEOUT}s:$pending"
      return 1
    fi
    sleep 5
  done
  # The api that answered must be the version we deployed.
  local running
  running="$(docker inspect --format '{{.Config.Image}}' "$(stack "$CURRENT_RELEASE" ps -q api)" 2>/dev/null || true)"
  [ "$running" = "$1" ] || { log "api runs $running, expected $1"; return 1; }
  log "healthy: $PUBLIC_ORIGIN (/healthz, /readyz, /api, /, /config.js)"
}

show_failure() {
  log "--- stack state ---"
  stack "$CURRENT_RELEASE" ps -a --format '{{.Service}}: {{.State}} {{.Status}}' || true
  log "--- last log lines (migrate, api, frontend) ---"
  stack "$CURRENT_RELEASE" logs --no-color --tail 40 migrate api frontend 2>&1 \
    | grep -v -e '"route": "/healthz"' -e '"uri":"/healthz"' | tail -n 60 || true
}

# ------------------------------------------------------------------ one attempt
CURRENT_RELEASE=""
attempt() {  # $1 app, $2 frontend, $3 release dir
  CURRENT_RELEASE="$3"
  [ -f "$3/deploy/vm/docker-compose.vm.yml" ] || { log "release $3 is missing"; return 1; }
  render_env_file "$1" "$2"
  install -d -m 0700 "$ENV_DIR/postgres"
  install -m 0755 "$3/docker/postgres/init-roles.sh" "$ENV_DIR/postgres/init-roles.sh"
  stack "$3" config -q || { log "compose configuration is invalid"; return 1; }
  pull_images "$1" "$2" "$3" || { log "pulling images failed"; return 1; }
  log "starting postgres and redis"
  stack "$3" up -d --wait --wait-timeout 180 postgres redis || return 1
  log "running migrations (lg-sotf migrate)"
  stack "$3" run --rm -T migrate || { log "migration failed"; return 1; }
  log "starting api, worker, scheduler, frontend"
  stack "$3" up -d --wait --wait-timeout 300 --remove-orphans || { log "containers did not become healthy"; return 1; }
  health_checks "$1"
}

# ------------------------------------------------------------------ state
state_get() {  # $1 file, $2 key
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | head -n 1
}

record_success() {  # $1 app, $2 frontend, $3 release, $4 version
  if [ -f "$STATE_DIR/current.env" ] && [ "$(state_get "$STATE_DIR/current.env" APP_IMAGE)" != "$1" ]; then
    mv -f "$STATE_DIR/current.env" "$STATE_DIR/previous.env"
  fi
  printf '%s=%s\n' APP_IMAGE "$1" FRONTEND_IMAGE "$2" RELEASE_DIR "$3" VERSION "$4" \
    DEPLOYED_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | atomic_write "$STATE_DIR/current.env" 0600
  printf '%s deployed %s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$4" "$1" "$2" >> "$STATE_DIR/history.log"
}

prune() {
  local keep_ids=() f ref id repo line
  # Images any environment on this VM may still run or roll back to.
  for f in "$ROOT"/env/*/state/current.env "$ROOT"/env/*/state/previous.env; do
    [ -f "$f" ] || continue
    for ref in "$(state_get "$f" APP_IMAGE)" "$(state_get "$f" FRONTEND_IMAGE)"; do
      id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
      [ -z "$id" ] || keep_ids+=("$id")
    done
  done
  for repo in "${NEW_APP_IMAGE%%[@]*}" "${NEW_FRONTEND_IMAGE%%[@]*}"; do
    repo="$(printf '%s' "$repo" | sed -E 's#:[^/:]+$##')"
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      case " ${keep_ids[*]} " in *" $line "*) continue ;; esac
      docker image rm "$line" >/dev/null 2>&1 && log "removed old image $line" || true
    done < <(docker image ls --no-trunc --format '{{.ID}}' "$repo" | sort -u)
  done
  docker image prune -f >/dev/null 2>&1 || true
  # Release directories: keep those in use plus the newest few.
  local in_use
  in_use=" $(state_get "$STATE_DIR/current.env" RELEASE_DIR) $(state_get "$STATE_DIR/previous.env" RELEASE_DIR) "
  if [ -d "$ENV_DIR/releases" ]; then
    # shellcheck disable=SC2012  # release names are hex commit ids
    ls -1t "$ENV_DIR/releases" | tail -n +"$((KEEP_RELEASES + 1))" | while IFS= read -r line; do
      case "$in_use" in *" $ENV_DIR/releases/$line "*) continue ;; esac
      rm -rf "${ENV_DIR:?}/releases/$line"
    done
  fi
}

install_tools() {
  install -d -m 0755 "$ROOT/bin"
  install -m 0755 "$RELEASE_DIR/deploy/vm/backup.sh" "$ROOT/bin/backup.sh"
}

# ------------------------------------------------------------------ actions
if [ "$ACTION" = "status" ]; then
  for which in current previous; do
    f="$STATE_DIR/$which.env"
    if [ -f "$f" ]; then
      printf '%-8s %s  %s  (deployed %s)\n' "$which" "$(state_get "$f" VERSION)" \
        "$(state_get "$f" APP_IMAGE)" "$(state_get "$f" DEPLOYED_AT)"
    else
      printf '%-8s none\n' "$which"
    fi
  done
  exit 0
fi

if [ "$SECRETS_STDIN" -eq 1 ]; then
  read_values_from_stdin
  validate_values
  write_values_file
else
  [ -f "$SECRETS_FILE" ] || die "no stored values in $SECRETS_FILE; run once with --secrets-stdin"
  load_values_file "$SECRETS_FILE"
  validate_values
fi

PREV_APP="$(state_get "$STATE_DIR/current.env" APP_IMAGE)"
PREV_FRONTEND="$(state_get "$STATE_DIR/current.env" FRONTEND_IMAGE)"
PREV_RELEASE="$(state_get "$STATE_DIR/current.env" RELEASE_DIR)"
PREV_VERSION="$(state_get "$STATE_DIR/current.env" VERSION)"

if [ "$ACTION" = "rollback" ]; then
  f="$STATE_DIR/previous.env"
  [ -f "$f" ] || die "no previous version recorded"
  NEW_APP_IMAGE="$(state_get "$f" APP_IMAGE)"
  NEW_FRONTEND_IMAGE="$(state_get "$f" FRONTEND_IMAGE)"
  VERSION="$(state_get "$f" VERSION)"
  RELEASE_DIR="$(state_get "$f" RELEASE_DIR)"
  log "rolling back from ${PREV_VERSION:-?} to $VERSION"
fi

log "deploying $VERSION to $PUBLIC_ORIGIN (project $PROJECT)"
ensure_edge || die "the edge (Caddy) did not start; see: docker compose -p $EDGE_PROJECT logs caddy"

if attempt "$NEW_APP_IMAGE" "$NEW_FRONTEND_IMAGE" "$RELEASE_DIR"; then
  record_success "$NEW_APP_IMAGE" "$NEW_FRONTEND_IMAGE" "$RELEASE_DIR" "$VERSION"
  install_tools
  prune
  log "DEPLOYED $VERSION at $PUBLIC_ORIGIN"
  exit 0
fi

show_failure
if [ -z "$PREV_APP" ] || { [ "$PREV_APP" = "$NEW_APP_IMAGE" ] && [ "$PREV_FRONTEND" = "$NEW_FRONTEND_IMAGE" ]; }; then
  log "FAILED: $VERSION is not healthy and there is no other version to roll back to"
  exit 1
fi
log "FAILED: $VERSION is not healthy; rolling back to ${PREV_VERSION:-previous version}"
if attempt "$PREV_APP" "$PREV_FRONTEND" "$PREV_RELEASE"; then
  printf '%s rolled back from %s to %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$VERSION" "$PREV_VERSION" \
    >> "$STATE_DIR/history.log"
  log "ROLLED BACK to $PREV_VERSION; $VERSION was not deployed"
  exit 1
fi
show_failure
log "ROLLBACK FAILED: neither $VERSION nor $PREV_VERSION is healthy; see docs/cicd.md (Troubleshooting)"
exit 3
