#!/usr/bin/env bash
# Verify and load an offline bundle made by scripts/airgap/bundle.sh (run on the air-gapped host).
#
#   scripts/airgap/load.sh --expect <sha256 of SHA256SUMS> /media/usb/lg-sotf-airgap-20261001
#   scripts/airgap/load.sh <bundle dir>                   # without --expect: integrity only, warns
#   scripts/airgap/load.sh --skip-models <bundle dir>     # images only
#   scripts/airgap/load.sh --force-models <bundle dir>    # restore models into a non-empty volume
#
# 1. checks SHA256SUMS: every listed file must match, no path may leave the
#    bundle, and with --expect the manifest itself must have that SHA-256
#    (the value bundle.sh printed, carried over a separate channel);
# 2. `docker load` of images.tar.gz;
# 3. when the bundle has ollama-models.tar: restores it into the
#    ollama-models volume (default lg-sotf_ollama-models, the volume of
#    docker/docker-compose.ollama.yml with the default project name;
#    OLLAMA_VOLUME overrides), refusing to overwrite a volume that already has
#    content unless --force-models;
# 4. prints the image references to put in the stack's .env.
#
# Nothing is loaded when any check fails. Helper containers run with
# --network none.

set -euo pipefail

EXPECT=""
SKIP_MODELS=0
FORCE_MODELS=0
BUNDLE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --expect) [ "$#" -ge 2 ] || { echo "--expect needs a SHA-256 value" >&2; exit 2; }; EXPECT="$2"; shift ;;
    --skip-models) SKIP_MODELS=1 ;;
    --force-models) FORCE_MODELS=1 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *) [ -z "$BUNDLE" ] || { echo "only one bundle directory" >&2; exit 2; }; BUNDLE="$1" ;;
  esac
  shift
done
[ -n "$BUNDLE" ] || { echo "usage: $0 [--expect SHA256] [--skip-models] [--force-models] <bundle dir>" >&2; exit 2; }

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }

command -v docker >/dev/null || fail "docker is not installed"
command -v sha256sum >/dev/null || fail "sha256sum is not installed"
[ -d "$BUNDLE" ] || fail "$BUNDLE is not a directory"
BUNDLE="$(cd "$BUNDLE" && pwd)"
MANIFEST="$BUNDLE/SHA256SUMS"
[ -f "$MANIFEST" ] || fail "no SHA256SUMS in $BUNDLE"
OLLAMA_VOLUME="${OLLAMA_VOLUME:-lg-sotf_ollama-models}"

# ------------------------------------------------------------------- manifest
step "verifying $MANIFEST"
actual="$(sha256sum "$MANIFEST" | cut -d' ' -f1)"
if [ -n "$EXPECT" ]; then
  [ "$actual" = "$EXPECT" ] || fail "SHA256SUMS has SHA-256 $actual, expected $EXPECT: the bundle was altered"
  echo "ok    manifest matches the expected SHA-256"
else
  echo "WARN  no --expect given: the files are checked against the manifest, but the manifest itself is not"
  echo "      authenticated. Its SHA-256 is $actual; compare it with the value bundle.sh printed."
fi
while read -r sum name; do
  [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || fail "malformed line in SHA256SUMS"
  case "$name" in
    */*|..*|-*|"") fail "SHA256SUMS names a path outside the bundle: $name" ;;
  esac
done <"$MANIFEST"
grep -q ' images.tar.gz$' "$MANIFEST" || fail "SHA256SUMS does not cover images.tar.gz"
grep -q ' images.env$' "$MANIFEST" || fail "SHA256SUMS does not cover images.env"
for f in "$BUNDLE"/*; do
  name="$(basename "$f")"
  [ "$name" = "SHA256SUMS" ] && continue
  grep -q " $name\$" "$MANIFEST" || fail "$name is in the bundle but not in SHA256SUMS"
done
(cd "$BUNDLE" && sha256sum --check --strict --quiet SHA256SUMS) || fail "checksum mismatch: do not use this bundle"
echo "ok    every file matches SHA256SUMS"

# --------------------------------------------------------------------- images
step "loading images"
gzip -dc "$BUNDLE/images.tar.gz" | docker load

image_ref() { grep -m1 "^$1=" "$BUNDLE/images.env" | cut -d= -f2-; }
REDIS_IMAGE="$(image_ref REDIS_IMAGE)"
[ -n "$REDIS_IMAGE" ] || fail "images.env has no REDIS_IMAGE"

# --------------------------------------------------------------------- models
if [ -f "$BUNDLE/ollama-models.tar" ] && [ "$SKIP_MODELS" -eq 0 ]; then
  step "restoring the Ollama models into volume $OLLAMA_VOLUME"
  docker volume create "$OLLAMA_VOLUME" >/dev/null
  if [ "$FORCE_MODELS" -eq 0 ] && [ -n "$(docker run --rm --network none -v "$OLLAMA_VOLUME:/dst:ro" \
      --entrypoint ls "$REDIS_IMAGE" -A /dst)" ]; then
    fail "volume $OLLAMA_VOLUME is not empty (use --force-models to restore over it)"
  fi
  docker run --rm --network none -v "$OLLAMA_VOLUME:/dst" -v "$BUNDLE:/src:ro" \
    --entrypoint tar "$REDIS_IMAGE" -xf /src/ollama-models.tar -C /dst
  echo "ok    models restored"
fi

echo
echo "Loaded. Put these image references in the stack's .env (see docs/air-gapped.md):"
cat "$BUNDLE/images.env"
