#!/usr/bin/env bash
# Regenerates every hash-locked requirements file (docs/security.md, "Supply chain").
#
#   scripts/lock_requirements.sh                         # re-lock, keeping the current pins
#   scripts/lock_requirements.sh --upgrade-package fastapi
#   scripts/lock_requirements.sh --upgrade               # everything to the newest allowed
#
# Extra arguments go to every `uv pip compile` call. Never edit the .txt files by hand: each one
# carries a --hash for every wheel and sdist of every pinned version (all platforms, so the
# linux/amd64 and linux/arm64 image builds and macOS development installs all verify), and the
# Dockerfile, CI and `make install` install them with `pip install --require-hashes`.
#
#   requirements.txt               runtime set for the image ([openai] and [gemini] extras included,
#                                  so one image serves every LLM provider); pyproject.toml holds
#                                  the supported ranges, this file the exact tested versions
#   requirements-dev.txt           runtime + [dev], constrained to requirements.txt's versions
#   docker/requirements-build.txt  pip, setuptools and dumb-init for the image's builder stage
#   scripts/ci/requirements-tools.txt    pip-audit, bandit, CycloneDX SBOM and schema tooling
#   scripts/ci/requirements-nightly.txt  pytest-randomly for the nightly job
#
# The resolution is universal (platform markers kept) for CPython 3.11+, the image's Python.
# Needs uv (https://docs.astral.sh/uv/); the output does not depend on the host's Python.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v uv >/dev/null || { echo "uv is required: https://docs.astral.sh/uv/getting-started/installation/" >&2; exit 1; }

lock() {
  uv pip compile --quiet --universal --python-version 3.11 --generate-hashes --strip-extras \
    --custom-compile-command "scripts/lock_requirements.sh" "$@"
}

lock --extra openai --extra gemini -o requirements.txt pyproject.toml "$@"
lock --extra dev --extra openai --extra gemini --constraint requirements.txt \
  -o requirements-dev.txt pyproject.toml "$@"
lock -o docker/requirements-build.txt docker/requirements-build.in "$@"
lock -o scripts/ci/requirements-tools.txt scripts/ci/requirements-tools.in "$@"
lock --no-deps -o scripts/ci/requirements-nightly.txt scripts/ci/requirements-nightly.in "$@"
echo "locked: requirements.txt requirements-dev.txt docker/requirements-build.txt scripts/ci/requirements-{tools,nightly}.txt"
