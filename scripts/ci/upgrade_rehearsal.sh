#!/usr/bin/env bash
# Upgrade rehearsal: release N-1 leaves runs waiting for an analyst, release N migrates and decides them.
#
#   scripts/ci/upgrade_rehearsal.sh                 # N-1 = the latest v* tag before HEAD, N = this checkout
#   scripts/ci/upgrade_rehearsal.sh --from v1.2.3   # any git ref as N-1
#
# What it does, as an upgrade runs in production (docs/deployment.md section 7):
#   1. starts PostgreSQL and Redis from docker/docker-compose.test.yml (own project
#      name and ports) and creates the production roles with docker/postgres/init-roles.sh:
#      lgsotf_owner runs every migration, lgsotf_app runs the api and worker;
#   2. checks N-1 out into a git worktree with its own venv (its requirements.txt),
#      runs its `lg-sotf migrate`, api and worker, and ingests C2 beacon alerts
#      the fake LLM escalates until they wait for an analyst; one escalation is
#      claimed and one decided, so its run waits for an approval;
#   3. runs N's `lg-sotf migrate` while N-1 still runs (expand-only migrations: the
#      previous release must keep working on the new schema), and ingests two more
#      alerts through N-1 on the migrated schema (those its worker has not settled
#      within 30s are left queued for N; its message failures are printed as warnings,
#      and fail the rehearsal on a stale cached statement once N-1 retries those);
#   4. stops N-1, runs the drain check (no waiting run on a graph N does not have),
#      starts N's api and worker and decides or approves every waiting run through
#      the API, then works one new alert end to end on N;
#   5. fails unless every run completed: no failed or dead-lettered run, no alert
#      left open, nothing in the dead-letter queue, no UnknownGraphVersion in the
#      worker log, and the new run stamped with N's graph version.
# The runtime role's attributes and privileges are snapshotted before and after N's
# migration: anything it had must be unchanged (privileges on new objects are listed).
#
# Needs docker with compose v2, git and python3. Environment overrides:
#   UPGRADE_FROM          N-1 ref (or --from; default: the latest v* tag reachable from HEAD^)
#   UPGRADE_PYTHON        interpreter that builds the N-1 venv (default python3; CPython 3.11)
#   UPGRADE_OLD_PYTHON    use this interpreter for N-1 instead of building a venv
#   UPGRADE_NEW_PYTHON    interpreter with this checkout's requirements (default python3)
#   UPGRADE_PROJECT       compose project name (default lgsotf-upgrade)
#   UPGRADE_PG_PORT, UPGRADE_REDIS_PORT, UPGRADE_API_PORT, UPGRADE_WORKER_PORT
#                         host ports (default 55491, 56391, 18291, 19291)
#   UPGRADE_TIMEOUT       seconds to wait for alerts to settle (default 180)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

FROM="${UPGRADE_FROM:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM="${2:?--from needs a git ref}"; shift 2 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$FROM" ] || FROM="$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD^)"

PROJECT="${UPGRADE_PROJECT:-lgsotf-upgrade}"
PG_PORT="${UPGRADE_PG_PORT:-55491}"
REDIS_PORT="${UPGRADE_REDIS_PORT:-56391}"
API_PORT="${UPGRADE_API_PORT:-18291}"
WORKER_PORT="${UPGRADE_WORKER_PORT:-19291}"
TIMEOUT="${UPGRADE_TIMEOUT:-180}"
NEW_PY="${UPGRADE_NEW_PYTHON:-python3}"
DB="soc_test_upg_rehearsal"
RUNTIME_ROLE="lgsotf_app"
# docs/deployment.md section 7: runs that resume after the upgrade, by the graph they started on (NULL is 1).
DRAIN_CHECK="SELECT graph_version, count(*) FROM workflow_runs WHERE status IN ('waiting_human', 'waiting_approval', 'failed') GROUP BY 1"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lgsotf-upgrade.XXXXXX")"
chmod 700 "$WORK"
ENV_FILE="$WORK/stack.env"
STATE="$WORK/state.json"
OLD="$WORK/n-1"
LOGS="$WORK/logs"
mkdir "$LOGS"
PIDS=()

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok    %s\n' "$*"; }

COMPOSE=(docker compose -p "$PROJECT" -f docker/docker-compose.test.yml -f "$WORK/ports.yml")

cleanup() {
  local rc=$?
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    for log in "$LOGS"/*.log; do
      [ -f "$log" ] && { echo "--- tail of $(basename "$log") ---" >&2; tail -n 20 "$log" | cut -c1-400 >&2; }
    done
  fi
  [ -f "$WORK/ports.yml" ] && "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  git worktree remove --force "$OLD" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

value() { grep -m1 "^$1=" "$ENV_FILE" | cut -d= -f2-; }
psql_super() { "${COMPOSE[@]}" exec -T postgres psql -U postgres -d "$DB" -v ON_ERROR_STOP=1 -X -q -At -F $'\t' "$@"; }

# Every grant, attribute and membership of the runtime role, the RLS flags of every table, and the objects
# that exist (so privileges on objects created by the upgrade can be told apart): "<kind>\t<object>\t<detail>".
privilege_snapshot() {
  psql_super <<SQL | LC_ALL=C sort
WITH app AS (SELECT oid FROM pg_roles WHERE rolname = '$RUNTIME_ROLE'),
grants AS (
  SELECT c.oid::regclass::text AS object, a.privilege_type AS detail, a.grantee, a.is_grantable
    FROM pg_class c, aclexplode(c.relacl) a
  UNION ALL SELECT c.oid::regclass::text, a.privilege_type || ' (' || att.attname || ')', a.grantee, a.is_grantable
    FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid, aclexplode(att.attacl) a
  UNION ALL SELECT p.oid::regprocedure::text, a.privilege_type, a.grantee, a.is_grantable
    FROM pg_proc p, aclexplode(p.proacl) a
  UNION ALL SELECT 'schema ' || n.nspname, a.privilege_type, a.grantee, a.is_grantable
    FROM pg_namespace n, aclexplode(n.nspacl) a
  UNION ALL SELECT 'database', a.privilege_type, a.grantee, a.is_grantable
    FROM pg_database d, aclexplode(d.datacl) a WHERE d.datname = current_database()
  UNION ALL SELECT 'default privileges', d.defaclobjtype::text || ' ' || a.privilege_type, a.grantee, a.is_grantable
    FROM pg_default_acl d, aclexplode(d.defaclacl) a
)
SELECT 'grant', object, detail || CASE WHEN is_grantable THEN ' with grant option' ELSE '' END
  FROM grants WHERE grantee = (SELECT oid FROM app)
UNION ALL SELECT 'role', rolname, format('super=%s inherit=%s createrole=%s createdb=%s login=%s replication=%s bypassrls=%s',
    rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls)
  FROM pg_roles WHERE oid = (SELECT oid FROM app)
UNION ALL SELECT 'member', m.roleid::regrole::text, 'admin=' || m.admin_option FROM pg_auth_members m
  WHERE m.member = (SELECT oid FROM app)
UNION ALL SELECT 'owns', c.oid::regclass::text, c.relkind::text FROM pg_class c WHERE c.relowner = (SELECT oid FROM app)
UNION ALL SELECT 'rls', c.oid::regclass::text, format('enabled=%s forced=%s', c.relrowsecurity, c.relforcerowsecurity)
  FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
UNION ALL SELECT 'object', c.oid::regclass::text, c.relkind::text FROM pg_class c
  WHERE c.relnamespace = 'public'::regnamespace
UNION ALL SELECT 'object', p.oid::regprocedure::text, 'function' FROM pg_proc p
  WHERE p.pronamespace = 'public'::regnamespace
UNION ALL SELECT 'object', unnest(ARRAY['schema public', 'database', 'default privileges']), '';
SQL
}

wait_http() {  # wait_http <url> <what>
  local deadline=$((SECONDS + 90))
  until [ "$(curl -s -o /dev/null -w '%{http_code}' "$1" || true)" = "200" ]; do
    [ "$SECONDS" -lt "$deadline" ] || fail "$2 not ready at $1"
    sleep 1
  done
  ok "$2 ready"
}

# lg <log name> <python> <src dir> <args...>: one lg-sotf command of a release, logged to $LOGS.
lg() {
  local label="$1" py="$2" src="$3"
  shift 3
  PYTHONPATH="$src" "$py" -m lg_sotf "$@" >>"$LOGS/$label.log" 2>&1
}
# The same, run in the background: exec, so the recorded PID is the process itself and SIGTERM reaches it.
lg_bg() {
  local label="$1" py="$2" src="$3"
  shift 3
  PYTHONPATH="$src" exec "$py" -m lg_sotf "$@" >>"$LOGS/$label.log" 2>&1
}

migrate() {  # migrate <label> <python> <src dir>: as the schema owner, like the migrate job
  LG_SOTF_DATABASE__MIGRATION_URL="$OWNER_URL" LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL="$SMOKE_ADMIN_EMAIL" \
    LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD="$SMOKE_ADMIN_PASSWORD" lg "$1-migrate" "$2" "$3" migrate \
    || fail "$1: lg-sotf migrate failed"
  ok "$1: migrated as lgsotf_owner"
}

start_release() {  # start_release <label> <python> <src dir>: api and worker as the runtime role
  lg_bg "$1-api" "$2" "$3" api --host 127.0.0.1 --port "$API_PORT" &
  PIDS+=($!)
  lg_bg "$1-worker" "$2" "$3" worker --metrics-host 127.0.0.1 --metrics-port "$WORKER_PORT" &
  PIDS+=($!)
  wait_http "http://127.0.0.1:$API_PORT/readyz" "$1 api"
  wait_http "http://127.0.0.1:$WORKER_PORT/readyz" "$1 worker"
}

stop_release() {  # SIGTERM: the worker finishes its in-flight runs and exits
  local pid
  for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  PIDS=()
  ok "$1 stopped"
}

driver() { "$NEW_PY" scripts/ci/upgrade_rehearsal.py "$@" --base-url "http://127.0.0.1:$API_PORT" \
  --state "$STATE" --timeout "$TIMEOUT"; }

# ------------------------------------------------------------------ services
step "PostgreSQL and Redis ($PROJECT, ports $PG_PORT and $REDIS_PORT)"
cat >"$WORK/ports.yml" <<YAML
services:
  postgres:
    ports: !override ["127.0.0.1:$PG_PORT:5432"]
  redis:
    ports: !override ["127.0.0.1:$REDIS_PORT:6379"]
YAML
install -m 600 /dev/null "$ENV_FILE"
"$NEW_PY" scripts/generate_secrets.py --append "$ENV_FILE" >/dev/null
"${COMPOSE[@]}" up -d --quiet-pull --wait --wait-timeout 120 postgres redis >"$LOGS/compose.log" 2>&1 \
  || fail "the test services did not start"
# The production roles and database, exactly as the production compose overlay creates them.
"${COMPOSE[@]}" exec -T -e LGSOTF_OWNER_PASSWORD="$(value LGSOTF_OWNER_PASSWORD)" \
  -e LGSOTF_APP_PASSWORD="$(value LGSOTF_APP_PASSWORD)" -e LGSOTF_DB="$DB" -e POSTGRES_DB=postgres \
  postgres sh -s <docker/postgres/init-roles.sh >/dev/null
ok "roles lgsotf_owner (schema owner) and $RUNTIME_ROLE (runtime) created; database $DB"

OWNER_URL="postgresql://lgsotf_owner:$(value LGSOTF_OWNER_PASSWORD)@127.0.0.1:$PG_PORT/$DB"
export LG_SOTF_ENVIRONMENT=staging LG_SOTF_CONFIG_FILE="" LG_SOTF_OBSERVABILITY__LOG_FORMAT=json
LG_SOTF_DATABASE__URL="postgresql://$RUNTIME_ROLE:$(value LGSOTF_APP_PASSWORD)@127.0.0.1:$PG_PORT/$DB"
export LG_SOTF_DATABASE__URL LG_SOTF_DATABASE__RUNTIME_ROLE="$RUNTIME_ROLE" LG_SOTF_REDIS__URL="redis://127.0.0.1:$REDIS_PORT/0"
export LG_SOTF_LLM__PROVIDER=fake LG_SOTF_LLM__ALLOW_FAKE=true
# The driver signs the bootstrap platform admin in with a password only (as scripts/smoke_stack.sh does).
export LG_SOTF_AUTH__REQUIRE_MFA_FOR_PLATFORM_ADMINS=false
for key in LG_SOTF_AUTH__JWT_SECRET LG_SOTF_SECURITY__ENCRYPTION_KEYS LG_SOTF_SECURITY__INDICATOR_HMAC_KEY \
  LG_SOTF_API__METRICS_TOKEN; do
  export "$key=$(value "$key")"
done
export SMOKE_ADMIN_EMAIL="admin@upgrade.example.com"
SMOKE_ADMIN_PASSWORD="$(value LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD)"
export SMOKE_ADMIN_PASSWORD

# -------------------------------------------------------------- release N-1
step "release N-1: $FROM ($(git rev-parse --short "$FROM^{commit}"))"
git worktree add --detach "$OLD" "$FROM" >/dev/null 2>&1 || fail "cannot check out $FROM"
OLD_PY="${UPGRADE_OLD_PYTHON:-}"
if [ -z "$OLD_PY" ]; then
  "${UPGRADE_PYTHON:-python3}" -m venv "$WORK/venv-n-1"
  "$WORK/venv-n-1/bin/pip" install -q --disable-pip-version-check -r "$OLD/requirements.txt" \
    >"$LOGS/n-1-pip.log" 2>&1 || fail "installing the requirements of $FROM"
  OLD_PY="$WORK/venv-n-1/bin/python"
fi
ok "N-1 is $(PYTHONPATH="$OLD/src" "$OLD_PY" -m lg_sotf version)"
migrate n-1 "$OLD_PY" "$OLD/src"
start_release n-1 "$OLD_PY" "$OLD/src"
driver seed --count 4 --mid-work
privilege_snapshot >"$WORK/privileges-before.txt" || fail "snapshot of the runtime role's privileges"

# ---------------------------------------------------------- migrate to N
step "release N: this checkout ($(git rev-parse --short HEAD)), migrated while N-1 still runs"
ok "N is $(PYTHONPATH="$ROOT/src" "$NEW_PY" -m lg_sotf version)"
migrate n "$NEW_PY" "$ROOT/src"
privilege_snapshot >"$WORK/privileges-after.txt" || fail "snapshot of the runtime role's privileges"
driver privileges --before "$WORK/privileges-before.txt" --after "$WORK/privileges-after.txt"
step "release N-1 keeps taking alerts on the migrated schema"
before_migration="$(grep -c '"worker.message_failed"' "$LOGS/n-1-worker.log" || true)"
driver seed --count 2 --settle-within 30
stop_release n-1
# Shown, not fatal (the entry stays pending and N's worker claims it from the stopped consumer)...
grep '"worker.message_failed"' "$LOGS/n-1-worker.log" | tail -n "+$((before_migration + 1))" \
  | grep -o '"error": "[A-Za-z]*"' | sort | uniq -c >"$WORK/n-1-failures.txt" || true
sed 's/^ */warn  N-1 worker after the migration: /' "$WORK/n-1-failures.txt"
# ...except a stale cached statement (the migration changed a table under one), once N-1 retries those
# (ARCH-E1.6; releases before it fail the message and leave it pending until the visibility timeout).
if grep -q 'def retry_stale_statement' "$OLD/src/lg_sotf/db/pool.py" \
  && grep -qE 'InvalidCachedStatementError|OutdatedSchemaCacheError' "$WORK/n-1-failures.txt"; then
  fail "the N-1 worker failed a message on a stale cached statement it should have retried"
fi

# ----------------------------------------------------------- drain on N
step "drain check (docs/deployment.md section 7)"
psql_super -c "$DRAIN_CHECK" | tee "$WORK/drain.txt" | sed 's/^/      /'
PYTHONPATH="$ROOT/src" "$NEW_PY" - "$WORK/drain.txt" <<'PY' || fail "a waiting run is on a graph release N does not have"
import sys
from lg_sotf.core.graph import GRAPH_BUILDERS, UNVERSIONED_GRAPH
rows = [line.split("\t") for line in open(sys.argv[1]).read().splitlines() if line]
versions = {int(v) if v else UNVERSIONED_GRAPH for v, _ in rows}
assert rows, "no waiting run to drain"
missing = versions - set(GRAPH_BUILDERS)
print(f"{'FAIL' if missing else 'ok  '}  graphs of waiting runs {sorted(versions)}; release N runs {sorted(GRAPH_BUILDERS)}")
sys.exit(1 if missing else 0)
PY
start_release n "$NEW_PY" "$ROOT/src"
step "deciding every run N-1 left waiting, through the API of release N"
driver drain
stop_release n

# --------------------------------------------------------------- verdict
step "every run completed"
runs="$(psql_super -c "SELECT status || '=' || count(*) FROM workflow_runs GROUP BY status ORDER BY 1" | paste -sd' ')"
[[ "$runs" =~ ^completed=[0-9]+$ ]] || fail "workflow runs not all completed: $runs"
ok "workflow runs: $runs"
open="$(psql_super -c "SELECT count(*) FROM alerts WHERE status <> 'closed'")"
[ "$open" = "0" ] || fail "$open alert(s) not closed"
ok "every alert closed"
fresh="$("$NEW_PY" -c 'import json, sys; print(json.load(open(sys.argv[1]))["fresh_alert_ids"][0])' "$STATE")"
stamped="$(psql_super -c "SELECT graph_version FROM workflow_runs WHERE alert_id = '$fresh'")"
current="$(PYTHONPATH="$ROOT/src" "$NEW_PY" -c 'from lg_sotf.core.graph import GRAPH_VERSION; print(GRAPH_VERSION)')"
[ "$stamped" = "$current" ] || fail "the new run is on graph '$stamped', not $current"
ok "the run started on N is stamped with graph version $current"
dlq=0
for key in $("${COMPOSE[@]}" exec -T redis redis-cli --scan --pattern '*:dlq'); do
  dlq=$((dlq + $("${COMPOSE[@]}" exec -T redis redis-cli XLEN "$key")))
done
[ "$dlq" = "0" ] || fail "$dlq dead-lettered queue entries"
ok "dead-letter queue empty"
if grep -h -e UnknownGraphVersion -e workflow.unknown_graph_version -e workflow.run_failed "$LOGS"/n-worker.log; then
  fail "release N's worker failed a run"
fi
ok "no UnknownGraphVersion or failed run in release N's worker log"

echo
echo "UPGRADE REHEARSAL PASSED ($FROM -> $(git rev-parse --short HEAD))"
