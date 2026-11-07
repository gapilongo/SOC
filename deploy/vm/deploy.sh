#!/usr/bin/env bash
# Deploy (or roll back) one LG-SOTF environment on this host. Runs as the
# non-root deploy user (member of the docker group); see docs/cicd.md and,
# for a self-hosted PC behind Tailscale Funnel, docs/self-hosting-pc.md.
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
#   2. prepares the ingress:
#      caddy  (default) makes sure the shared `lgsotf-proxy` network and the
#             Caddy edge (<root>/edge) run, and installs this environment's
#             site;
#      funnel copies the Tailscale serve config to <root>/env/<env>/tailscale/
#             and creates the node's state volume (TS_AUTHKEY needed then);
#   3. pulls the images (a GHCR read token, when given, is used for this pull
#      only and never stored), runs `lg-sotf migrate`, then
#      `docker compose up -d --wait`;
#   4. checks the application:
#      caddy  https://<domain>/healthz, /readyz, /api (401), / and /config.js
#             through Caddy on this host;
#      funnel the same through the frontend's nginx inside the stack
#             (http://<frontend edge address>:8080 from the api container:
#             /healthz, /api/v1/healthz, /api/v1/readyz, /api (401), /,
#             /config.js); nginx answers /healthz itself and serves the app
#             for /readyz, so the api's probes are checked under /api/v1;
#      and that the api runs the image that was deployed;
#   5. on success records the version (current + previous), prunes old images
#      and release directories; on failure redeploys the previous version
#      automatically, checks it the same way and exits non-zero;
#   6. funnel only, after a successful deploy: checks that the Tailscale node
#      is logged in as <domain> and that Funnel serves it (exit 4 with the
#      likely cause if not; the application stays deployed, since the previous
#      version would not fix it), then requests https://<domain>/healthz from
#      this host for up to two minutes (a warning only: public DNS for a new
#      Funnel name can take about ten minutes).
#
# Several environments can share one host: each gets its own compose project
# (lgsotf-<env>), directory, volumes and internal networks, and its own
# hostname (on the single Caddy that owns ports 80/443, or its own Tailscale
# node, e.g. soc-dev and soc-uat).
#
# Options:
#   --env NAME             environment (dev, uat, prod or another short name)
#   --domain HOST          public hostname: a DNS A record -> this host (caddy),
#                          or <machine name>.<tailnet>.ts.net (funnel)
#   --ingress caddy|funnel how the public HTTPS traffic arrives (default: the
#                          environment's last deployed mode, else caddy)
#   --root DIR             state directory (default /opt/lg-sotf)
#   --app-image REF        backend image, ideally repo@sha256:digest
#   --frontend-image REF   frontend image
#   --version LABEL        human-readable version (image tag), for records
#   --secrets-stdin        read KEY=value lines from stdin (see ALLOWED_KEYS)
#   --tls acme|internal    caddy only. acme: Let's Encrypt (default); internal:
#                          Caddy's own CA, for local tests without a public name
#   --http-port N / --https-port N   caddy only: host ports of the edge (80/443)
#   --slot N               address slot of the environment's internal network
#                          (1-30; default dev=1, uat=2, prod=3)
#   --health-timeout S     seconds to wait for the health checks (default 300)
#   --rollback             redeploy the previous version (no image arguments)
#   --status               print the current and previous versions (and, with
#                          funnel, the Tailscale node's state)
#
# Exit status: 0 deployed; 1 not deployed (rolled back, or nothing to roll
# back to); 2 bad arguments or missing prerequisites; 3 the rollback failed
# too; 4 (funnel) deployed and healthy inside the host but not published by
# Tailscale Funnel.
#
# Environment (optional): LGSOTF_PROXY_SUBNET (172.31.251.0/24),
# LGSOTF_CADDY_IP (172.31.251.2), LGSOTF_KEEP_RELEASES (5); funnel:
# LGSOTF_INGRESS_TIMEOUT (seconds for the Tailscale checks, 120) and
# LGSOTF_EXTERNAL_TIMEOUT (seconds for the public check, 120; 0 skips it).

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENV_NAME=""
DOMAIN=""
INGRESS=""
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
INGRESS_TIMEOUT="${LGSOTF_INGRESS_TIMEOUT:-120}"
EXTERNAL_TIMEOUT="${LGSOTF_EXTERNAL_TIMEOUT:-120}"
ACTION="deploy"
PROXY_NETWORK="lgsotf-proxy"
PROXY_SUBNET="${LGSOTF_PROXY_SUBNET:-172.31.251.0/24}"
CADDY_IP="${LGSOTF_CADDY_IP:-172.31.251.2}"
KEEP_RELEASES="${LGSOTF_KEEP_RELEASES:-5}"
# The tailscaled socket inside the ts container (TS_SOCKET in docker-compose.funnel.yml).
TS_SOCKET="/tmp/tailscaled.sock"

# Keys accepted on stdin. Anything else is refused, so the caller cannot
# override computed settings (images, networks, trusted proxies).
ALLOWED_KEYS=(
  POSTGRES_SUPERUSER_PASSWORD LGSOTF_OWNER_PASSWORD LGSOTF_APP_PASSWORD
  LG_SOTF_AUTH__JWT_SECRET LG_SOTF_SECURITY__ENCRYPTION_KEYS LG_SOTF_SECURITY__INDICATOR_HMAC_KEY
  LG_SOTF_API__METRICS_TOKEN LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD
  ANTHROPIC_API_KEY LG_SOTF_LLM__PROVIDER LG_SOTF_WORKER__CONCURRENCY LG_SOTF_OBSERVABILITY__LOG_LEVEL
  GOOGLE_API_KEY OPENAI_API_KEY LG_SOTF_LLM__BASE_URL LG_SOTF_LLM__FAST__MODEL LG_SOTF_LLM__DEEP__MODEL
  LG_SOTF_LLM__STRUCTURED_OUTPUT LG_SOTF_LLM__FAST__MAX_CONCURRENCY LG_SOTF_LLM__DEEP__MAX_CONCURRENCY
  ACME_EMAIL POSTGRES_IMAGE REDIS_IMAGE CADDY_IMAGE TS_AUTHKEY TS_IMAGE
  POSTGRES_MEM POSTGRES_CPUS REDIS_MEM REDIS_CPUS API_MEM API_CPUS WORKER_MEM WORKER_CPUS
  SCHEDULER_MEM SCHEDULER_CPUS FRONTEND_MEM FRONTEND_CPUS TS_MEM TS_CPUS
)
# Used for this run only, never written to disk.
TRANSIENT_KEYS=(GHCR_USER GHCR_TOKEN)
REQUIRED_KEYS=(
  POSTGRES_SUPERUSER_PASSWORD LGSOTF_OWNER_PASSWORD LGSOTF_APP_PASSWORD
  LG_SOTF_AUTH__JWT_SECRET LG_SOTF_SECURITY__ENCRYPTION_KEYS LG_SOTF_SECURITY__INDICATOR_HMAC_KEY
  LG_SOTF_API__METRICS_TOKEN LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD
)
# Stored values the stack's compose files use only with --ingress funnel.
FUNNEL_ONLY_KEYS=" TS_AUTHKEY TS_IMAGE TS_MEM TS_CPUS "

log() { printf '%s [%s] %s\n' "$(date -u +%H:%M:%S)" "${ENV_NAME:-?}" "$*"; }
die() { printf 'ERROR [%s] %s\n' "${ENV_NAME:-?}" "$*" >&2; exit 2; }
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }

TLS_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --env) ENV_NAME="${2:-}"; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --ingress) INGRESS="${2:-}"; [ -n "$INGRESS" ] || INGRESS="(empty)"; shift 2 ;;
    --root) ROOT="${2:-}"; shift 2 ;;
    --app-image) NEW_APP_IMAGE="${2:-}"; shift 2 ;;
    --frontend-image) NEW_FRONTEND_IMAGE="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --secrets-stdin) SECRETS_STDIN=1; shift ;;
    --tls) TLS_MODE="${2:-}"; TLS_SET=1; shift 2 ;;
    --http-port) HTTP_PORT="${2:-}"; TLS_SET=1; shift 2 ;;
    --https-port) HTTPS_PORT="${2:-}"; TLS_SET=1; shift 2 ;;
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
if ! [[ "$SLOT" =~ ^[0-9]+$ ]] || [ "$SLOT" -lt 1 ] || [ "$SLOT" -gt 30 ]; then die "--slot must be 1-30"; fi
[[ "$TLS_MODE" =~ ^(acme|internal)$ ]] || die "--tls must be acme or internal"
[[ "$HTTP_PORT" =~ ^[0-9]{1,5}$ && "$HTTPS_PORT" =~ ^[0-9]{1,5}$ ]] || die "bad port"
[[ "$HEALTH_TIMEOUT" =~ ^[0-9]{1,4}$ ]] || die "bad --health-timeout"
[[ "$KEEP_RELEASES" =~ ^[0-9]{1,3}$ ]] || die "bad LGSOTF_KEEP_RELEASES"
[[ "$INGRESS_TIMEOUT" =~ ^[0-9]{1,4}$ ]] || die "bad LGSOTF_INGRESS_TIMEOUT"
[[ "$EXTERNAL_TIMEOUT" =~ ^[0-9]{1,4}$ ]] || die "bad LGSOTF_EXTERNAL_TIMEOUT"
[[ "$PROXY_SUBNET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "bad LGSOTF_PROXY_SUBNET"
[[ "$CADDY_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "bad LGSOTF_CADDY_IP"

ENV_DIR="$ROOT/env/$ENV_NAME"
STATE_DIR="$ENV_DIR/state"

state_get() {  # $1 file, $2 key
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | head -n 1
}

RECORDED_INGRESS="$(state_get "$STATE_DIR/current.env" INGRESS)"
[ -n "$INGRESS" ] || INGRESS="${RECORDED_INGRESS:-caddy}"
[[ "$INGRESS" =~ ^(caddy|funnel)$ ]] || die "--ingress must be caddy or funnel"
if [ "$INGRESS" = "funnel" ] && [ "$TLS_SET" -eq 1 ]; then
  die "--tls, --http-port and --https-port apply to --ingress caddy only (Funnel serves https://<domain> on 443)"
fi

if [ "$ACTION" != "status" ]; then
  [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "--domain must be a hostname"
  DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
  if [ "$INGRESS" = "funnel" ]; then
    [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9]([a-z0-9-]*[a-z0-9])?\.ts\.net$ ]] \
      || die "--ingress funnel needs --domain <machine name>.<tailnet>.ts.net (e.g. soc-dev.tail1234.ts.net)"
  elif [[ "$DOMAIN" =~ (^|\.)ts\.net$ ]]; then
    # Let's Encrypt cannot issue for a *.ts.net name, and a Funnel environment
    # deployed as caddy would be stopped as an ingress switch.
    die "--domain $DOMAIN is a Tailscale name: only --ingress funnel can serve *.ts.net"
  fi
fi
IMAGE_RE='^[a-z0-9][a-z0-9._/:-]{0,250}(@sha256:[0-9a-f]{64})?$'
if [ "$ACTION" = "deploy" ]; then
  [[ "$NEW_APP_IMAGE" =~ $IMAGE_RE ]] || die "--app-image must be an image reference"
  [[ "$NEW_FRONTEND_IMAGE" =~ $IMAGE_RE ]] || die "--frontend-image must be an image reference"
  [ -n "$VERSION" ] || VERSION="$(printf '%s' "$NEW_APP_IMAGE" | sed -E 's/.*[:@]//' | cut -c1-19)"
  [[ "$VERSION" =~ ^[A-Za-z0-9._+-]{1,64}$ ]] || die "--version must be a short label"
fi

for tool in docker curl flock sed awk; do
  command -v "$tool" >/dev/null || die "$tool is not installed (run deploy/vm/bootstrap.sh)"
done
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed"

EDGE_DIR="$ROOT/edge"
SECRETS_FILE="$ENV_DIR/secrets.env"
ENV_FILE="$ENV_DIR/.env"
PROJECT="lgsotf-$ENV_NAME"
EDGE_PROJECT="lgsotf-edge"
TS_HOSTNAME="${DOMAIN%%.*}"
TS_STATE_VOLUME="lgsotf-$ENV_NAME-tailscale"
PUBLIC_ORIGIN="https://$DOMAIN"
if [ "$INGRESS" = "caddy" ] && [ "$HTTPS_PORT" != "443" ]; then PUBLIC_ORIGIN="https://$DOMAIN:$HTTPS_PORT"; fi

# Per-environment /29 for the frontend <-> api network (fixed addresses so the
# api can trust exactly its frontend's X-Forwarded-For). With Funnel the host
# is typically a PC under WSL2, whose NAT network moves around 172.16.0.0/12
# and whose LAN is a 192.168.x network, so that mode uses 10.202.<slot>.0/29
# (next to the daemon pools of deploy/pc/install-docker.sh, 10.200-10.201).
if [ "$INGRESS" = "funnel" ]; then
  EDGE_SUBNET="10.202.$SLOT.0/29"
  EDGE_FRONTEND_IP="10.202.$SLOT.2"
  EDGE_API_IP="10.202.$SLOT.3"
else
  EDGE_BASE=$((SLOT * 8))
  EDGE_SUBNET="172.31.250.$EDGE_BASE/29"
  EDGE_FRONTEND_IP="172.31.250.$((EDGE_BASE + 2))"
  EDGE_API_IP="172.31.250.$((EDGE_BASE + 3))"
fi

mkdir -p "$ROOT" "$ENV_DIR" "$STATE_DIR"
chmod 0750 "$ROOT" 2>/dev/null || true

# One deploy per host at a time (dev and uat may share the edge and the images).
exec 9>"$ROOT/.deploy.lock"
flock -w 900 9 || die "another deploy is still running on this host"

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
  for k in LG_SOTF_LLM__FAST__MODEL LG_SOTF_LLM__DEEP__MODEL; do
    [ -z "${VALUES[$k]:-}" ] || [[ "${VALUES[$k]}" =~ ^[A-Za-z0-9._:/-]{1,100}$ ]] || die "$k is not a model name"
  done
  for k in LG_SOTF_LLM__FAST__MAX_CONCURRENCY LG_SOTF_LLM__DEEP__MAX_CONCURRENCY LG_SOTF_WORKER__CONCURRENCY; do
    [ -z "${VALUES[$k]:-}" ] || [[ "${VALUES[$k]}" =~ ^([1-9]|[1-5][0-9]|6[0-4])$ ]] || die "$k must be 1-64"
  done
  [ -z "${VALUES[LG_SOTF_LLM__BASE_URL]:-}" ] || [[ "${VALUES[LG_SOTF_LLM__BASE_URL]}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] \
    || die "LG_SOTF_LLM__BASE_URL must be an https:// URL"
  for k in POSTGRES_IMAGE REDIS_IMAGE CADDY_IMAGE TS_IMAGE; do
    [ -z "${VALUES[$k]:-}" ] || [[ "${VALUES[$k]}" =~ $IMAGE_RE ]] || die "$k must be an image reference"
  done
  # Catches a truncated or mis-pasted key without printing it.
  [ -z "${VALUES[TS_AUTHKEY]:-}" ] || [[ "${VALUES[TS_AUTHKEY]}" =~ ^tskey-[A-Za-z0-9_-]{8,}$ ]] \
    || die "TS_AUTHKEY does not look like a Tailscale auth key (tskey-auth-...)"
}

# ------------------------------------------------------------------ rendering
# Compose env file for one version: stored values plus computed settings.
render_env_file() {  # $1 app image, $2 frontend image
  local provider allow_fake k
  provider="${VALUES[LG_SOTF_LLM__PROVIDER]:-}"
  if [ -z "$provider" ]; then
    if [ -n "${VALUES[ANTHROPIC_API_KEY]:-}" ]; then
      provider=anthropic
    elif [ -n "${VALUES[GOOGLE_API_KEY]:-}" ]; then
      provider=gemini
    elif [ -n "${VALUES[OPENAI_API_KEY]:-}" ]; then
      provider=openai
    else
      provider=fake
    fi
  fi
  if [ "$provider" = "fake" ]; then allow_fake=true; else allow_fake=false; fi
  {
    echo "# Rendered by deploy/vm/deploy.sh for $PROJECT ($INGRESS ingress). Private (0600); do not edit."
    for k in "${!VALUES[@]}"; do
      case "$k" in ACME_EMAIL|CADDY_IMAGE|LG_SOTF_LLM__PROVIDER) continue ;; esac
      if [ "$INGRESS" != "funnel" ]; then
        case "$FUNNEL_ONLY_KEYS" in *" $k "*) continue ;; esac
      fi
      printf "%s='%s'\n" "$k" "${VALUES[$k]}"
    done | sort
    printf "%s='%s'\n" \
      LGSOTF_ENV "$ENV_NAME" \
      LGSOTF_ENV_DIR "$ENV_DIR" \
      APP_IMAGE "$1" \
      FRONTEND_IMAGE "$2" \
      EDGE_SUBNET "$EDGE_SUBNET" \
      EDGE_FRONTEND_IP "$EDGE_FRONTEND_IP" \
      EDGE_API_IP "$EDGE_API_IP" \
      LG_SOTF_API__PUBLIC_URL "$PUBLIC_ORIGIN" \
      LG_SOTF_API__CORS_ORIGINS "[\"$PUBLIC_ORIGIN\"]" \
      LG_SOTF_LLM__PROVIDER "$provider" \
      LG_SOTF_LLM__ALLOW_FAKE "$allow_fake"
    if [ "$INGRESS" = "funnel" ]; then
      # Funnel's proxy reaches nginx over 127.0.0.1 inside the ts namespace; the
      # api sees the frontend's (ts's) edge address.
      printf "%s='%s'\n" \
        TS_HOSTNAME "$TS_HOSTNAME" \
        TS_STATE_VOLUME "$TS_STATE_VOLUME" \
        LG_SOTF_API__FORWARDED_ALLOW_IPS "$EDGE_FRONTEND_IP" \
        FRONTEND_TRUSTED_PROXIES "127.0.0.1"
    else
      printf "%s='%s'\n" \
        PROXY_NETWORK "$PROXY_NETWORK" \
        LG_SOTF_API__FORWARDED_ALLOW_IPS "$EDGE_FRONTEND_IP,$CADDY_IP" \
        FRONTEND_TRUSTED_PROXIES "$CADDY_IP"
    fi
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
  # An empty CADDY_IMAGE keeps the digest pin in docker-compose.edge.yml (one place to bump).
  printf '%s=%s\n' \
    CADDY_IMAGE "${VALUES[CADDY_IMAGE]:-}" \
    CADDY_IP "$CADDY_IP" \
    PROXY_NETWORK "$PROXY_NETWORK" \
    EDGE_HTTP_PORT "$HTTP_PORT" \
    EDGE_HTTPS_PORT "$HTTPS_PORT" | atomic_write "$EDGE_DIR/.env" 0600
}

edge() { docker compose -p "$EDGE_PROJECT" -f "$EDGE_DIR/compose.yml" --env-file "$EDGE_DIR/.env" "$@"; }

stack() {  # $1: release dir, rest: compose arguments
  local rel="$1"
  shift
  local files=(
    -f "$rel/docker/docker-compose.yml"
    -f "$rel/docker/docker-compose.prod.yml"
    -f "$rel/deploy/vm/docker-compose.vm.yml"
  )
  if [ "$INGRESS" = "funnel" ]; then
    files+=(-f "$rel/deploy/vm/docker-compose.funnel.yml")
  elif [ -f "$rel/deploy/vm/docker-compose.caddy.yml" ]; then
    # Releases from before the ingress split carry the proxy network in docker-compose.vm.yml.
    files+=(-f "$rel/deploy/vm/docker-compose.caddy.yml")
  fi
  docker compose -p "$PROJECT" "${files[@]}" --env-file "$ENV_FILE" "$@"
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

# The node's identity lives in an external volume: deploys, rollbacks and
# `docker compose down -v` never delete it.
ts_state_exists() { docker volume inspect "$TS_STATE_VOLUME" >/dev/null 2>&1; }

ensure_funnel() {
  local conf="$ENV_DIR/tailscale" site="$EDGE_DIR/conf/sites/$ENV_NAME.caddy"
  # Read by tailscaled (root without capabilities, so through the "other" bits).
  install -d -m 0755 "$conf"
  atomic_write "$conf/serve.json" 0644 < "$RELEASE_DIR/deploy/vm/tailscale/serve.json"
  if ! ts_state_exists; then
    log "creating volume $TS_STATE_VOLUME (Tailscale node state; kept across deploys)"
    docker volume create --label "org.lg-sotf.env=$ENV_NAME" "$TS_STATE_VOLUME" >/dev/null || return 1
  fi
  # This environment was served by the shared Caddy before: stop routing it there.
  if [ -f "$site" ]; then
    rm -f "$site"
    log "removed the Caddy site of $ENV_NAME (now published through Tailscale Funnel)"
    if [ -f "$EDGE_DIR/compose.yml" ] && [ -n "$(edge ps -q caddy 2>/dev/null)" ]; then
      edge exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force >/dev/null 2>&1 \
        || log "warning: reloading Caddy without the $ENV_NAME site failed"
    fi
  fi
}

ensure_ingress() {
  if [ "$INGRESS" = "funnel" ]; then
    ensure_funnel || die "preparing the Tailscale Funnel ingress failed"
  else
    ensure_edge || die "the edge (Caddy) did not start; see: docker compose -p $EDGE_PROJECT logs caddy"
  fi
}

# ------------------------------------------------------------------ images
pull_images() {  # $1 app, $2 frontend, $3 release dir
  local cfg="" rc=0
  if [ -n "${TRANSIENT[GHCR_TOKEN]:-}" ]; then
    # A throwaway client config: the token is not left on the host.
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
  if [ "$INGRESS" = "funnel" ]; then
    stack "$3" pull --quiet postgres redis ts
  else
    stack "$3" pull --quiet postgres redis
  fi
}

# ------------------------------------------------------------------ health
CURL_CA=()
caddy_pending() {  # prints the failing paths of one round through Caddy
  local body code path want pending="" base="https://$DOMAIN:$HTTPS_PORT"
  if [ "$TLS_MODE" = "internal" ] && [ "${#CURL_CA[@]}" -eq 0 ]; then
    if edge exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$STATE_DIR/edge-local-ca.crt" 2>/dev/null \
       && [ -s "$STATE_DIR/edge-local-ca.crt" ]; then
      CURL_CA=(--cacert "$STATE_DIR/edge-local-ca.crt")
    fi
  fi
  body="$(mktemp)"
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
  rm -f "$body"
  printf '%s' "$pending"
}

# The same checks through the frontend's nginx, from inside the stack (the
# api container's Python; nothing is published on the host in this mode).
# nginx answers /healthz itself and serves the app for /readyz, so the api's
# own probes are requested under /api/v1, which nginx proxies to the api.
FUNNEL_PROBE='
import sys, urllib.error, urllib.request
base, host, checks = sys.argv[1], sys.argv[2], sys.argv[3:]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
pending = []
for check in checks:
    path, code, text = check.split("|", 2)
    request = urllib.request.Request(base + path, headers={"Host": host})
    try:
        with opener.open(request, timeout=10) as response:
            status, body = response.status, response.read(262144)
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read(262144)
    except Exception:
        status, body = 0, b""
    if str(status) != code or text.encode() not in body:
        pending.append("%s(%s)" % (path, status))
print(" ".join(pending))
'
funnel_pending() {  # prints the failing paths of one round through nginx
  local out
  out="$(stack "$CURRENT_RELEASE" exec -T api python -c "$FUNNEL_PROBE" \
    "http://$EDGE_FRONTEND_IP:8080" "$DOMAIN" \
    "/healthz|200|ok" \
    "/api/v1/healthz|200|\"status\":\"ok\"" \
    "/api/v1/readyz|200|\"status\":\"ok\"" \
    "/api/v1/alerts|401|" \
    "/|200|<div id=\"root\">" \
    "/config.js|200|__LG_SOTF_CONFIG__" 2>/dev/null)" || out=" (api container not reachable)"
  printf '%s' "$out"
}

health_checks() {  # $1 expected app image
  local deadline=$((SECONDS + HEALTH_TIMEOUT)) pending
  CURL_CA=()
  while :; do
    if [ "$INGRESS" = "funnel" ]; then pending="$(funnel_pending)"; else pending="$(caddy_pending)"; fi
    [ -n "${pending// /}" ] || break
    if [ "$SECONDS" -ge "$deadline" ]; then
      log "health checks failed after ${HEALTH_TIMEOUT}s: ${pending# }"
      return 1
    fi
    sleep 5
  done
  # The api that answered must be the version we deployed.
  local running
  running="$(docker inspect --format '{{.Config.Image}}' "$(stack "$CURRENT_RELEASE" ps -q api)" 2>/dev/null || true)"
  [ "$running" = "$1" ] || { log "api runs $running, expected $1"; return 1; }
  if [ "$INGRESS" = "funnel" ]; then
    log "healthy inside the stack: http://$EDGE_FRONTEND_IP:8080 as $DOMAIN (/healthz, /api/v1/healthz, /api/v1/readyz, /api, /, /config.js)"
  else
    log "healthy: $PUBLIC_ORIGIN (/healthz, /readyz, /api, /, /config.js)"
  fi
}

# The browser's WebSocket sends its access token as ?token= and uvicorn logs
# the handshake with the query string; OIDC callbacks carry ?code=. The
# Deploy workflow's log is public, so such values are masked in anything
# copied from container logs, whatever the image's own log redaction does.
redact_query_secrets() {
  sed -E "s/([?&]([a-z_]*token|code)=)[^&\"'[:space:]\\\\]*/\\1[redacted]/g"
}

show_failure() {
  local ts_error
  log "--- stack state ---"
  stack "$CURRENT_RELEASE" ps -a --format '{{.Service}}: {{.State}} {{.Status}}' || true
  # Not ts: while logged out its log carries a login URL.
  log "--- last log lines (migrate, api, frontend) ---"
  stack "$CURRENT_RELEASE" logs --no-color --tail 40 migrate api frontend 2>&1 | redact_query_secrets \
    | grep -v -e '"route": "/healthz"' -e '"uri":"/healthz"' | tail -n 60 || true
  if [ "$INGRESS" = "funnel" ]; then
    # A sidecar that cannot log in exits and is restarted; each restart leaves
    # the frontend without a network until its health check restarts it.
    ts_error="$(ts_login_error)"
    if [ -n "$ts_error" ]; then
      log "Tailscale: the ts sidecar cannot log in ($ts_error), so it keeps restarting and the frontend keeps losing its network."
      log "fix: $TS_AUTHKEY_FIX"
    fi
  fi
}

# ------------------------------------------------------------------ Tailscale Funnel
ts_container() {
  docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=ts" 2>/dev/null | head -n 1
}

ts_cli() {
  local id
  id="$(ts_container)"
  [ -n "$id" ] || return 1
  docker exec "$id" tailscale --socket="$TS_SOCKET" "$@"
}

# `tailscale status --json` without peers: the only DNSName is this node's.
# The document also holds the pending login URL, so it is parsed, never logged.
ts_status_json() { ts_cli status --json --peers=false 2>/dev/null; }

TS_AUTHKEY_FIX="create an auth key (admin console > Settings > Keys: tags tag:soc, not ephemeral, pre-approved), set it as the TS_AUTHKEY secret of the environment and deploy again."

# The last login error in the ts container's log (every run of it, stopped or
# not), cut down to the error text: that log can also hold a login URL, so no
# line of it is ever copied whole.
ts_login_error() {
  local id logs err
  # Called on the way to a rollback: nothing here may stop the script.
  id="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=ts" 2>/dev/null | head -n 1 || true)"
  [ -n "$id" ] || return 0
  logs="$(docker logs --tail 500 "$id" 2>&1 || true)"
  err="$(grep -oE 'invalid key: [A-Za-z0-9 ,.:_-]{1,120}' <<<"$logs" | tail -n 1 || true)"
  [ -n "$err" ] || err="$(grep -oE 'failed to auth tailscale: [A-Za-z0-9 ,.:_-]{1,120}' <<<"$logs" | tail -n 1 || true)"
  printf '%s' "$err" | sed -E -e 's/tskey-[A-Za-z0-9_-]*/tskey-[redacted]/g' -e 's/[ ,.:]+$//'
}

json_string() {  # $1 key; first "key": "value" in the JSON on stdin
  sed -n "s/^[[:space:]]*\"$1\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

has_capability() {  # $1 capability; JSON on stdin (Capabilities list or CapMap key)
  grep -Eq "^[[:space:]]*\"$1\"([,:]|\$)"
}

explain_ingress_failure() {  # $1 backend state, $2 node DNS name, $3 status JSON, $4 funnel status
  local state="$1" dns="$2" st="$3" funnel="$4" login_error
  log "INGRESS FAILED: $VERSION is deployed and healthy on this host, but Tailscale Funnel does not publish $PUBLIC_ORIGIN"
  case "$state" in
    "")
      log "cause: the ts container is not running or tailscaled does not answer."
      log "fix: on this host, 'docker ps -a --filter label=com.docker.compose.project=$PROJECT' and 'docker logs <ts container>'." ;;
    NeedsLogin)
      log "cause: the node is not logged in: TS_AUTHKEY is missing, invalid, expired or single-use and already used, or this machine was deleted from the tailnet."
      login_error="$(ts_login_error)"
      [ -z "$login_error" ] || log "last login error: $login_error"
      log "fix: $TS_AUTHKEY_FIX" ;;
    NeedsMachineAuth)
      log "cause: the node waits for device approval."
      log "fix: approve '$TS_HOSTNAME' in the admin console (Machines), or use pre-approved auth keys." ;;
    Running)
      if [ "$dns" != "$DOMAIN." ]; then
        log "cause: the node is registered as '${dns%.}', not '$DOMAIN'."
        log "fix: if the tailnet part differs, set --domain/APP_DOMAIN to <machine>.<your tailnet>.ts.net; if the name got a suffix (e.g. $TS_HOSTNAME-1), delete the stale '$TS_HOSTNAME' machine in the admin console and rename this one to '$TS_HOSTNAME'."
      elif ! has_capability https <<<"$st"; then
        log "cause: HTTPS certificates are not enabled for the tailnet, so the serve config is not applied."
        log "fix: admin console > DNS: enable MagicDNS and HTTPS Certificates, then deploy again."
      elif ! has_capability funnel <<<"$st"; then
        log "cause: the tailnet policy does not grant Funnel to this node."
        log "fix: add {\"target\": [\"tag:soc\"], \"attr\": [\"funnel\"]} to nodeAttrs and make sure the auth key carries tag:soc, then deploy again."
      elif ! grep -qF "https://$DOMAIN (Funnel on)" <<<"$funnel"; then
        log "cause: the serve config (<env dir>/tailscale/serve.json) is not active."
        log "fix: on this host, look for 'serve proxy' in 'docker logs <ts container>'."
      fi ;;
    *)
      log "cause: tailscaled is in state '$state': it cannot reach the Tailscale control plane."
      log "fix: check this host's outbound internet access (HTTPS and UDP 3478/41641), then deploy again." ;;
  esac
}

ingress_checks() {
  local deadline=$((SECONDS + INGRESS_TIMEOUT)) st="" state="" dns="" funnel=""
  while :; do
    st="$(ts_status_json || true)"
    state="$(json_string BackendState <<<"$st")"
    dns="$(json_string DNSName <<<"$st")"
    funnel=""
    if [ "$state" = "Running" ] && [ "$dns" = "$DOMAIN." ]; then
      funnel="$(ts_cli funnel status 2>/dev/null || true)"
      if grep -qF "https://$DOMAIN (Funnel on)" <<<"$funnel" && has_capability funnel <<<"$st"; then
        log "ingress: Tailscale node ${dns%.} is Running and Funnel publishes https://$DOMAIN"
        return 0
      fi
    fi
    [ "$SECONDS" -lt "$deadline" ] || break
    sleep 5
  done
  explain_ingress_failure "$state" "$dns" "$st" "$funnel"
  return 1
}

external_check() {  # warning only
  local deadline=$((SECONDS + EXTERNAL_TIMEOUT)) nginx api
  [ "$EXTERNAL_TIMEOUT" -gt 0 ] || return 0
  while :; do
    nginx="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$DOMAIN/healthz" 2>/dev/null || true)"
    api="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$DOMAIN/api/v1/healthz" 2>/dev/null || true)"
    if [ "$nginx" = "200" ] && [ "$api" = "200" ]; then
      log "reachable from this host: https://$DOMAIN/healthz and /api/v1/healthz"
      return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || break
    sleep 10
  done
  log "warning: https://$DOMAIN is not reachable from this host yet (/healthz: ${nginx:-none}, /api/v1/healthz: ${api:-none})."
  log "warning: public DNS for a new Funnel name can take about ten minutes; the deploy itself succeeded."
}

# ------------------------------------------------------------------ one attempt
CURRENT_RELEASE=""
attempt() {  # $1 app, $2 frontend, $3 release dir
  CURRENT_RELEASE="$3"
  [ -f "$3/deploy/vm/docker-compose.vm.yml" ] || { log "release $3 is missing"; return 1; }
  if [ "$INGRESS" = "funnel" ] && [ ! -f "$3/deploy/vm/docker-compose.funnel.yml" ]; then
    log "release $3 predates the Tailscale Funnel ingress"
    return 1
  fi
  render_env_file "$1" "$2"
  install -d -m 0700 "$ENV_DIR/postgres"
  install -m 0755 "$3/docker/postgres/init-roles.sh" "$ENV_DIR/postgres/init-roles.sh"
  stack "$3" config -q || { log "compose configuration is invalid"; return 1; }
  pull_images "$1" "$2" "$3" || { log "pulling images failed"; return 1; }
  log "starting postgres and redis"
  stack "$3" up -d --wait --wait-timeout 180 postgres redis || return 1
  log "running migrations (lg-sotf migrate)"
  stack "$3" run --rm -T migrate || { log "migration failed"; return 1; }
  if [ "$INGRESS" = "funnel" ]; then
    log "starting api, worker, scheduler, ts (Tailscale), frontend"
  else
    log "starting api, worker, scheduler, frontend"
  fi
  stack "$3" up -d --wait --wait-timeout 300 --remove-orphans || { log "containers did not become healthy"; return 1; }
  health_checks "$1"
}

# ------------------------------------------------------------------ state
record_success() {  # $1 app, $2 frontend, $3 release, $4 version
  if [ -f "$STATE_DIR/current.env" ] && [ "$(state_get "$STATE_DIR/current.env" APP_IMAGE)" != "$1" ]; then
    mv -f "$STATE_DIR/current.env" "$STATE_DIR/previous.env"
  fi
  printf '%s=%s\n' APP_IMAGE "$1" FRONTEND_IMAGE "$2" RELEASE_DIR "$3" VERSION "$4" INGRESS "$INGRESS" \
    DEPLOYED_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | atomic_write "$STATE_DIR/current.env" 0600
  printf '%s deployed %s %s %s (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$4" "$1" "$2" "$INGRESS" >> "$STATE_DIR/history.log"
}

prune() {
  local keep_ids=() f ref id repo line
  # Images any environment on this host may still run or roll back to.
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
      if docker image rm "$line" >/dev/null 2>&1; then log "removed old image $line"; fi
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
  printf '%-8s %s\n' ingress "$INGRESS"
  if [ "$INGRESS" = "funnel" ]; then
    st="$(ts_status_json || true)"
    if [ -n "$st" ]; then
      printf '%-8s %s %s\n' tailnet "$(json_string BackendState <<<"$st")" "$(json_string DNSName <<<"$st")"
    else
      printf '%-8s %s\n' tailnet "ts container not running"
    fi
  fi
  exit 0
fi

docker info >/dev/null 2>&1 \
  || die "cannot reach the Docker daemon: is it running, and is $(id -un) in the docker group (log in again after adding it)?"

if [ "$SECRETS_STDIN" -eq 1 ]; then
  read_values_from_stdin
  validate_values
  write_values_file
else
  [ -f "$SECRETS_FILE" ] || die "no stored values in $SECRETS_FILE; run once with --secrets-stdin"
  load_values_file "$SECRETS_FILE"
  validate_values
fi

if [ "$INGRESS" = "funnel" ] && [ -z "${VALUES[TS_AUTHKEY]:-}" ] && ! ts_state_exists; then
  die "the Tailscale node of $ENV_NAME has no state yet (volume $TS_STATE_VOLUME) and no TS_AUTHKEY was given: create an auth key in the Tailscale admin console (Settings > Keys: tags tag:soc, not ephemeral) and pass it as TS_AUTHKEY (the TS_AUTHKEY secret of the GitHub environment) for this first deploy"
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

log "deploying $VERSION to $PUBLIC_ORIGIN (project $PROJECT, $INGRESS ingress)"
if [ -n "$PREV_APP" ] && [ "${RECORDED_INGRESS:-caddy}" != "$INGRESS" ]; then
  # The edge network's addresses and the frontend's networking differ between
  # the modes; Compose cannot convert running containers. Volumes are kept.
  log "switching ingress from ${RECORDED_INGRESS:-caddy} to $INGRESS: stopping the stack first"
  (cd / && docker compose -p "$PROJECT" down --remove-orphans) || die "stopping $PROJECT failed"
fi
ensure_ingress

if attempt "$NEW_APP_IMAGE" "$NEW_FRONTEND_IMAGE" "$RELEASE_DIR"; then
  record_success "$NEW_APP_IMAGE" "$NEW_FRONTEND_IMAGE" "$RELEASE_DIR" "$VERSION"
  install_tools
  prune
  if [ "$INGRESS" = "funnel" ]; then
    ingress_checks || exit 4
    external_check
  fi
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
