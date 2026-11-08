#!/usr/bin/env bash
# oasdiff from its container image, pinned by digest: a drop-in for the oasdiff binary.
#
#   OASDIFF=scripts/ci/oasdiff.sh python scripts/ci/check_api_compat.py --self-test docs/openapi.json
#
# check_api_compat.py writes the documents under the temp directory and passes absolute paths, so
# that directory is mounted read-only at the same path. No network: oasdiff only reads those files.
# CI sets OASDIFF_IMAGE (.github/workflows/ci.yml); the default below must stay the same pin.
set -euo pipefail

IMAGE="${OASDIFF_IMAGE:-tufin/oasdiff:v1.34.1@sha256:67a23cfea7d251e2ae34ee703ac8733c5d96bc2e7b90fd0f4d475ec99367b85f}"
TMP="${TMPDIR:-/tmp}"
TMP="${TMP%/}"

exec docker run --rm --network none -v "${TMP}:${TMP}:ro" "${IMAGE}" "$@"
