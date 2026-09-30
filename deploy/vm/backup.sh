#!/usr/bin/env bash
# Nightly PostgreSQL backups of the LG-SOTF environments on this host, with
# retention, an integrity check and an optional copy to OCI Object Storage.
# deploy.sh installs this script as <root>/bin/backup.sh; bootstrap.sh
# installs a systemd timer that runs `backup.sh --all` every night as the
# deploy user. See docs/cicd.md (Backups and restore).
#
#   backup.sh --all                      # every deployed environment
#   backup.sh --env dev                  # one environment
#   backup.sh --env dev --list
#   backup.sh --env dev --restore FILE --yes   # DESTRUCTIVE: replace the database
#
# Options:
#   --root DIR         state directory (default /opt/lg-sotf)
#   --keep-days N      delete local dumps older than N days (default 14)
#
# Optional upload (after `oci setup config` for the deploy user, see the docs):
#   OCI_BUCKET=<bucket> [OCI_NAMESPACE=<ns>] [OCI_PREFIX=lg-sotf/] in
#   <root>/backup.conf (KEY=value lines) or the environment. Object Storage
#   lifecycle rules handle remote retention.
#
# Dumps are `pg_dump -Fc` of the lgsotf database, owner-only (0600), in
# <root>/backups/<env>/. They hold tenant data but not the Fernet or HMAC keys,
# which stay in the GitHub environment secrets: keep both, or the encrypted
# columns cannot be read after a restore.

set -euo pipefail
umask 077

ROOT="/opt/lg-sotf"
ENVS=()
ALL=0
KEEP_DAYS=14
RESTORE=""
YES=0
LIST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="${2:-}"; shift 2 ;;
    --env) ENVS+=("${2:-}"); shift 2 ;;
    --all) ALL=1; shift ;;
    --keep-days) KEEP_DAYS="${2:-}"; shift 2 ;;
    --restore) RESTORE="${2:-}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --list) LIST=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 64 ;;
  esac
done

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf 'ERROR %s\n' "$*" >&2; exit 2; }

[[ "$ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--root must be an absolute path"
[[ "$KEEP_DAYS" =~ ^[0-9]{1,4}$ ]] || die "--keep-days must be a number"

if [ -f "$ROOT/backup.conf" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      OCI_BUCKET=*|OCI_NAMESPACE=*|OCI_PREFIX=*) export "${line?}" ;;
      ''|'#'*) ;;
      *) die "backup.conf: unsupported line (allowed: OCI_BUCKET, OCI_NAMESPACE, OCI_PREFIX)" ;;
    esac
  done < "$ROOT/backup.conf"
fi

if [ "$ALL" -eq 1 ]; then
  for d in "$ROOT"/env/*/; do
    [ -f "$d/state/current.env" ] && ENVS+=("$(basename "$d")")
  done
  [ "${#ENVS[@]}" -gt 0 ] || { log "no deployed environments under $ROOT/env"; exit 0; }
fi
[ "${#ENVS[@]}" -gt 0 ] || die "give --env NAME or --all"

compose_for() {  # $1 env; runs docker compose for that environment's current release
  local env="$1" rel ingress state="$ROOT/env/$1/state/current.env"
  shift
  rel="$(sed -n 's/^RELEASE_DIR=//p' "$state" | head -n 1)"
  if [ -z "$rel" ] || [ ! -d "$rel" ]; then die "$env: no current release recorded"; fi
  # The same files deploy.sh used: `up` in a restore must not rewire the ingress.
  ingress="$(sed -n 's/^INGRESS=//p' "$state" | head -n 1)"
  local files=(
    -f "$rel/docker/docker-compose.yml"
    -f "$rel/docker/docker-compose.prod.yml"
    -f "$rel/deploy/vm/docker-compose.vm.yml"
  )
  if [ "$ingress" = "funnel" ]; then
    files+=(-f "$rel/deploy/vm/docker-compose.funnel.yml")
  elif [ -f "$rel/deploy/vm/docker-compose.caddy.yml" ]; then
    files+=(-f "$rel/deploy/vm/docker-compose.caddy.yml")
  fi
  docker compose -p "lgsotf-$env" "${files[@]}" --env-file "$ROOT/env/$env/.env" "$@"
}

backup_one() {
  local env="$1" dir file tmp
  dir="$ROOT/backups/$env"
  install -d -m 0700 "$dir"
  file="$dir/lgsotf-$env-$(date -u +%Y%m%dT%H%M%SZ).dump"
  tmp="$file.partial"
  log "$env: dumping the lgsotf database"
  if ! compose_for "$env" exec -T postgres pg_dump -U postgres -d lgsotf -Fc > "$tmp"; then
    rm -f "$tmp"
    die "$env: pg_dump failed"
  fi
  # A readable archive with a table of contents, or it is not a backup.
  local toc
  toc="$(compose_for "$env" exec -T postgres pg_restore -l < "$tmp" 2>/dev/null || true)"
  if ! grep -q 'TABLE DATA' <<<"$toc"; then
    rm -f "$tmp"
    die "$env: the dump is not a readable archive"
  fi
  mv -f "$tmp" "$file"
  log "$env: wrote $file ($(du -h "$file" | cut -f1))"
  find "$dir" -maxdepth 1 -name "lgsotf-$env-*.dump" -type f -mtime +"$KEEP_DAYS" -print -delete \
    | sed "s/^/$(date -u +%Y-%m-%dT%H:%M:%SZ) $env: expired /"
  if [ -n "${OCI_BUCKET:-}" ]; then
    command -v oci >/dev/null || die "OCI_BUCKET is set but the oci CLI is not installed"
    oci os object put ${OCI_NAMESPACE:+--namespace "$OCI_NAMESPACE"} --bucket-name "$OCI_BUCKET" \
      --name "${OCI_PREFIX:-lg-sotf/}$env/$(basename "$file")" --file "$file" --no-multipart --force >/dev/null \
      || die "$env: upload to OCI bucket $OCI_BUCKET failed"
    log "$env: uploaded to oci://$OCI_BUCKET/${OCI_PREFIX:-lg-sotf/}$env/"
  fi
}

restore_one() {
  local env="$1" file="$2"
  [ -f "$file" ] || die "no such dump: $file"
  [ "$YES" -eq 1 ] || die "restore replaces the $env database; add --yes to confirm"
  log "$env: safety copy of the current database first"
  backup_one "$env"
  log "$env: stopping api, worker, scheduler"
  compose_for "$env" stop api worker scheduler
  # A fresh database with the same roles and grants as docker/postgres/init-roles.sh
  # (pg_restore --clean cannot drop the constraints of partitioned tables).
  log "$env: recreating the lgsotf database"
  compose_for "$env" exec -T postgres psql -v ON_ERROR_STOP=1 -q -U postgres -d postgres <<'SQL'
DROP DATABASE IF EXISTS lgsotf WITH (FORCE);
CREATE DATABASE lgsotf OWNER lgsotf_owner;
REVOKE ALL ON DATABASE lgsotf FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE lgsotf TO lgsotf_owner;
GRANT CONNECT ON DATABASE lgsotf TO lgsotf_app;
\connect lgsotf
ALTER SCHEMA public OWNER TO lgsotf_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO lgsotf_app;
SQL
  log "$env: restoring $file into lgsotf"
  compose_for "$env" exec -T postgres pg_restore -U postgres -d lgsotf --single-transaction --exit-on-error < "$file"
  log "$env: re-applying migrations and grants, then starting the stack"
  compose_for "$env" run --rm -T migrate
  compose_for "$env" up -d --wait --wait-timeout 300
  log "$env: restore complete"
}

for env in "${ENVS[@]}"; do
  [[ "$env" =~ ^[a-z][a-z0-9]{0,11}$ ]] || die "bad environment name"
  [ -f "$ROOT/env/$env/state/current.env" ] || die "$env is not deployed on this host"
  if [ "$LIST" -eq 1 ]; then
    ls -lh "$ROOT/backups/$env" 2>/dev/null || log "$env: no backups yet"
  elif [ -n "$RESTORE" ]; then
    restore_one "$env" "$RESTORE"
  else
    backup_one "$env"
  fi
done
