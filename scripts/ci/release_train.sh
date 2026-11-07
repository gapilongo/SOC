#!/usr/bin/env bash
# Release train (docs/releases.md): plans the next release tag and checks its gates.
#
#   scripts/ci/release_train.sh plan           # appends key=value lines to $GITHUB_OUTPUT
#   scripts/ci/release_train.sh gates COMMIT   # waits for, then checks, CI and Release images on COMMIT
#
# plan reads PROMOTE and LTS:
#   PROMOTE empty         the weekly partner train: vX.Y.Z-rc.N on the head of origin/main, where
#                         X.Y.Z is __version__ there and N the next free number. Skips (skip=true) when
#                         vX.Y.Z is already released (bump __version__ to open the next train) or when
#                         the head already carries an RC of it.
#   PROMOTE=vX.Y.Z-rc.N   promote that RC to the stable vX.Y.Z (same commit, same digests); with
#                         LTS=true also move the LTS channel (lts-X.Y and the :lts image tags), forward only.
# Outputs: skip, tag, commit, prerelease, channels (the image tags to move), lts_ref (the git tag to
# move, or empty) and security (true when a "### Security" changelog entry is new since the
# previous release of the same kind).
#
# gates: the CI run of COMMIT's push to main must have succeeded, every CI job named in
# RELEASE_GATES (one per line) must have succeeded, and the Release images run that built and
# signed COMMIT's images must have succeeded. Waits up to RELEASE_WAIT_SECONDS (default 3600) for
# runs still in progress, polling every RELEASE_POLL_SECONDS (default 60).
#
# Needs git (the full history and tags), gh (GH_TOKEN, GITHUB_REPOSITORY) and jq.

set -euo pipefail

SEMVER='[0-9]+\.[0-9]+\.[0-9]+'

fail() { echo "::error::$*"; exit 1; }
tag_exists() { git rev-parse -q --verify "refs/tags/$1" >/dev/null; }
version_at() { git show "$1:src/lg_sotf/__init__.py" | sed -n 's/^__version__ = "\(.*\)"/\1/p'; }

plan() {
  local out="${GITHUB_OUTPUT:?}" commit version tag prerelease=false channels="" lts_ref="" prev n t
  if [ -z "${PROMOTE:-}" ]; then
    [ "${LTS:-false}" = false ] || fail "the LTS channel takes a promoted release: set promote to an RC tag"
    commit="$(git rev-parse 'origin/main^{commit}')"
    version="$(version_at "$commit")"
    [[ "$version" =~ ^$SEMVER$ ]] || fail "cannot read __version__ at $commit"
    if tag_exists "v$version"; then
      echo "::notice::v$version is already released; bump __version__ on main to open the next train"
      echo "skip=true" >> "$out"
      return
    fi
    t="$(git tag --points-at "$commit" --list "v$version-rc.*")"
    if [ -n "$t" ]; then
      echo "::notice::main ($commit) is already $t; nothing new to ship"
      echo "skip=true" >> "$out"
      return
    fi
    n="$(git tag --list "v$version-rc.*" | sed -n "s/^v$version-rc\.\([0-9][0-9]*\)$/\1/p" | sort -n | tail -n 1)"
    tag="v$version-rc.$(( ${n:-0} + 1 ))"
    prerelease=true
    channels="partner"
    prev="$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$commit^" 2>/dev/null || true)"
  else
    [[ "$PROMOTE" =~ ^v($SEMVER)-rc\.[0-9]+$ ]] || fail "promote takes an RC tag vX.Y.Z-rc.N (got $PROMOTE)"
    version="${BASH_REMATCH[1]}"
    tag_exists "$PROMOTE" || fail "no tag $PROMOTE"
    commit="$(git rev-parse "refs/tags/$PROMOTE^{commit}")"
    git merge-base --is-ancestor "$commit" origin/main || fail "$PROMOTE ($commit) is not on main"
    tag="v$version"
    ! tag_exists "$tag" || fail "$tag already exists; a release tag never moves"
    [ "$(version_at "$commit")" = "$version" ] || fail "__version__ at $PROMOTE is not $version"
    if [ "${LTS:-false}" = true ]; then
      for t in $(git tag --list 'lts-*'); do
        git merge-base --is-ancestor "$t" "$commit" || fail "$t is newer than $PROMOTE; the LTS channel only moves forward"
      done
      lts_ref="lts-${version%.*}"
      channels="lts $lts_ref"
    fi
    prev="$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-rc.*' "$commit^" 2>/dev/null || true)"
  fi
  local security=false
  if [ -n "$prev" ] && git diff "$prev" "$commit" -- CHANGELOG.md changelog.d | grep -q '^+### Security'; then
    security=true
  fi
  {
    echo "skip=false"
    echo "tag=$tag"
    echo "commit=$commit"
    echo "prerelease=$prerelease"
    echo "channels=$channels"
    echo "lts_ref=$lts_ref"
    echo "security=$security"
  } >> "$out"
  echo "plan: $tag on $commit (channels: ${channels:-none}; security-relevant: $security; previous: ${prev:-none})"
}

RUN_ID=""

# wait_for LABEL WORKFLOW_FILE EVENT: the latest run of WORKFLOW_FILE for COMMIT on main must succeed.
wait_for() {
  local label="$1" file="$2" event="$3" line id status conclusion
  while :; do
    line="$(gh api "repos/$REPO/actions/workflows/$file/runs?head_sha=$COMMIT&event=$event&per_page=20" \
      --jq '[.workflow_runs[] | select(.head_branch == "main")] | sort_by(.run_number) | last
            | if . == null then "" else "\(.id) \(.status) \(.conclusion)" end')"
    read -r id status conclusion <<<"${line:-- none -}" || true
    if [ "$status" = completed ]; then
      [ "$conclusion" = success ] || fail "$label on $COMMIT ended '$conclusion' (run $id); no release"
      RUN_ID="$id"
      return
    fi
    [ "$SECONDS" -lt "$DEADLINE" ] || fail "$label on $COMMIT has not finished (status: $status); no release"
    echo "waiting for $label on $COMMIT (status: $status)"
    sleep "$POLL"
  done
}

gates() {
  COMMIT="${1:?gates needs a commit}"
  REPO="${GITHUB_REPOSITORY:?}"
  DEADLINE=$(( SECONDS + ${RELEASE_WAIT_SECONDS:-3600} ))
  POLL="${RELEASE_POLL_SECONDS:-60}"
  [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "unexpected commit '$COMMIT'"
  [ -n "${RELEASE_GATES//[[:space:]]/}" ] || fail "RELEASE_GATES names no CI job"

  wait_for CI ci.yml push
  local jobs gate
  jobs="$(gh api "repos/$REPO/actions/runs/$RUN_ID/jobs?per_page=100" --jq '.jobs[] | "\(.conclusion)\t\(.name)"')"
  while IFS= read -r gate; do
    [ -n "$gate" ] || continue
    printf '%s\n' "$jobs" | grep -qxF "success	$gate" || fail "CI job '$gate' did not pass on $COMMIT (run $RUN_ID); no release"
    echo "gate passed: $gate (CI run $RUN_ID)"
  done <<<"$RELEASE_GATES"

  wait_for "Release images" release-images.yml workflow_run
  echo "gate passed: Release images built and signed $COMMIT (run $RUN_ID)"
}

case "${1:-}" in
  plan) plan ;;
  gates) shift; gates "$@" ;;
  *) echo "usage: $0 plan | gates COMMIT" >&2; exit 2 ;;
esac
