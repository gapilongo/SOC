#!/usr/bin/env bash
# Build an offline installation bundle for an air-gapped host (run on a connected machine).
#
#   scripts/airgap/bundle.sh                                  # app, frontend, postgres, redis
#   scripts/airgap/bundle.sh --ollama                         # ... plus the Ollama image
#   scripts/airgap/bundle.sh --ollama --models                # ... plus the models in the ollama-models volume
#   scripts/airgap/bundle.sh --ollama --models-dir ~/.ollama  # ... or from an Ollama data directory
#   scripts/airgap/bundle.sh --output /media/usb/lg-sotf-1.0.0
#
# Writes into the output directory (default ./lg-sotf-airgap-<UTC date>):
#   images.tar.gz        `docker save` of every image, gzip-compressed
#   images.env           the image references, ready for the stack's .env
#   ollama-models.tar    the Ollama model store (--models / --models-dir only)
#   deploy.tar.gz        compose files, configs and scripts needed on the target
#   SHA256SUMS           SHA-256 of every file above
# and prints the SHA-256 of SHA256SUMS itself: send that value to the target
# over a separate channel and pass it to scripts/airgap/load.sh --expect so the
# manifest cannot be swapped together with the files.
#
# Images are taken from the local docker store, or pulled when missing
# (--no-pull refuses to pull). A reference pinned by digest (name:tag@sha256:...)
# is pulled by digest and saved under its tag, because `docker load` does not
# restore registry digests.
#
# Environment overrides: APP_IMAGE (lg-sotf:dev), FRONTEND_IMAGE
# (lg-sotf-frontend:dev), POSTGRES_IMAGE and REDIS_IMAGE (the pins in
# docker/docker-compose.yml), OLLAMA_IMAGE (the pin in docker/docker-compose.ollama.yml),
# OLLAMA_VOLUME (lg-sotf_ollama-models).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

OUTPUT="$PWD/lg-sotf-airgap-$(date -u +%Y%m%d)"
WITH_OLLAMA=0
MODELS=""
MODELS_DIR=""
PULL=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) [ "$#" -ge 2 ] || { echo "--output needs a directory" >&2; exit 2; }; OUTPUT="$2"; shift ;;
    --ollama) WITH_OLLAMA=1 ;;
    --models) MODELS="volume" ;;
    --models-dir) [ "$#" -ge 2 ] || { echo "--models-dir needs a directory" >&2; exit 2; }; MODELS="dir"; MODELS_DIR="$2"; shift ;;
    --no-pull) PULL=0 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }

command -v docker >/dev/null || fail "docker is not installed"
command -v sha256sum >/dev/null || fail "sha256sum is not installed"
[ -z "$MODELS" ] || [ "$WITH_OLLAMA" -eq 1 ] || fail "--models and --models-dir need --ollama"

# The Ollama pin lives in one place: the compose overlay. (Single quotes: ${...} is sed text here.)
# shellcheck disable=SC2016
pinned_ollama="$(sed -n 's/^x-ollama-image: &ollama-image \${OLLAMA_IMAGE:-\(.*\)}$/\1/p' docker/docker-compose.ollama.yml)"
[ -n "$pinned_ollama" ] || fail "could not read the Ollama image pin from docker/docker-compose.ollama.yml"

# Likewise the PostgreSQL and Redis digest pins live in docker/docker-compose.yml.
compose_pin() {
  local pin
  pin="$(sed -n "s/^    image: \${$1:-\(.*\)}\$/\1/p" docker/docker-compose.yml)"
  [ -n "$pin" ] || fail "could not read the $1 pin from docker/docker-compose.yml"
  printf '%s' "$pin"
}

APP_IMAGE="${APP_IMAGE:-lg-sotf:dev}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-lg-sotf-frontend:dev}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-$(compose_pin POSTGRES_IMAGE)}"
REDIS_IMAGE="${REDIS_IMAGE:-$(compose_pin REDIS_IMAGE)}"
OLLAMA_IMAGE="${OLLAMA_IMAGE:-$pinned_ollama}"
OLLAMA_VOLUME="${OLLAMA_VOLUME:-lg-sotf_ollama-models}"

ROLES=(APP_IMAGE FRONTEND_IMAGE POSTGRES_IMAGE REDIS_IMAGE)
[ "$WITH_OLLAMA" -eq 0 ] || ROLES+=(OLLAMA_IMAGE)

if [ -e "$OUTPUT" ] && [ -n "$(ls -A "$OUTPUT" 2>/dev/null)" ]; then
  fail "$OUTPUT exists and is not empty"
fi
mkdir -p "$OUTPUT"

# --------------------------------------------------------------------- images
SAVED=()
: >"$OUTPUT/images.env"
for role in "${ROLES[@]}"; do
  ref="${!role}"
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    [ "$PULL" -eq 1 ] || fail "image $ref is not present locally (and --no-pull was given)"
    step "pulling $ref"
    docker pull --quiet "$ref" >/dev/null
  fi
  saved="$ref"
  if [[ "$ref" == *@sha256:* ]]; then
    saved="${ref%@*}"
    [[ "$saved" == *:* ]] || saved="$saved:latest"
    docker tag "$ref" "$saved"
  fi
  SAVED+=("$saved")
  printf '%s=%s\n' "$role" "$saved" >>"$OUTPUT/images.env"
  printf '    %-15s %s\n' "$role" "$saved"
done

step "saving ${#SAVED[@]} images to images.tar.gz"
docker save "${SAVED[@]}" | gzip -c >"$OUTPUT/images.tar.gz"

# --------------------------------------------------------------------- models
if [ "$MODELS" = "volume" ]; then
  docker volume inspect "$OLLAMA_VOLUME" >/dev/null 2>&1 \
    || fail "volume $OLLAMA_VOLUME not found (pull the models first, see docs/air-gapped.md, or set OLLAMA_VOLUME)"
  step "archiving the models in volume $OLLAMA_VOLUME"
  docker run --rm --network none -v "$OLLAMA_VOLUME:/src:ro" -v "$OUTPUT:/out" \
    --entrypoint tar "$REDIS_IMAGE" -cf /out/ollama-models.tar -C /src .
elif [ "$MODELS" = "dir" ]; then
  [ -d "$MODELS_DIR/models" ] || fail "$MODELS_DIR has no models/ directory (expected an Ollama data directory such as ~/.ollama)"
  step "archiving the models in $MODELS_DIR"
  tar -cf "$OUTPUT/ollama-models.tar" -C "$MODELS_DIR" models
fi

# --------------------------------------------------------------- deploy files
step "packing the deployment files"
tar -czf "$OUTPUT/deploy.tar.gz" \
  docker/docker-compose.yml docker/docker-compose.prod.yml docker/docker-compose.ollama.yml \
  docker/postgres docker/empty-ca.crt configs .env.example Makefile \
  scripts/generate_secrets.py scripts/quickstart.sh scripts/demo scripts/airgap \
  docs/air-gapped.md docs/local-llm.md docs/quickstart.md

# ------------------------------------------------------------------- manifest
step "writing SHA256SUMS"
(
  cd "$OUTPUT"
  files=()
  for f in images.tar.gz images.env ollama-models.tar deploy.tar.gz; do
    [ -f "$f" ] && files+=("$f")
  done
  sha256sum "${files[@]}" >SHA256SUMS
)
manifest_sum="$(sha256sum "$OUTPUT/SHA256SUMS" | cut -d' ' -f1)"

echo
echo "bundle ready: $OUTPUT ($(du -sh "$OUTPUT" | cut -f1))"
echo "SHA-256 of SHA256SUMS: $manifest_sum"
echo "Send that value to the target separately and load with:"
echo "  scripts/airgap/load.sh --expect $manifest_sum <bundle directory>"
