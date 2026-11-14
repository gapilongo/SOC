#!/bin/sh
# Creates the LG-SOTF database roles on first start of the postgres
# container (docker-entrypoint-initdb.d). Used by docker-compose.prod.yml.
#
#   lgsotf_owner  owns the database and schema; runs `lg-sotf migrate` and the
#                 scheduler (DDL, partitions, retention, cross-tenant sweeps).
#   lgsotf_app    runtime login for the api and worker: no ownership, no
#                 superuser, no BYPASSRLS. `lg-sotf migrate` grants it exactly
#                 the table privileges it needs (database.runtime_role).
#   lgsotf_shadow (only when LGSOTF_SHADOW_PASSWORD is set) the login shadow
#                 runs connect as (database.shadow_url): read-only sessions,
#                 and `lg-sotf migrate` grants it SELECT only
#                 (database.shadow_role). Without it shadow runs refuse to start.
#
# Passwords come from LGSOTF_OWNER_PASSWORD / LGSOTF_APP_PASSWORD /
# LGSOTF_SHADOW_PASSWORD and are passed as psql variables, never interpolated
# into SQL text.
set -eu

: "${LGSOTF_OWNER_PASSWORD:?LGSOTF_OWNER_PASSWORD is required}"
: "${LGSOTF_APP_PASSWORD:?LGSOTF_APP_PASSWORD is required}"
LGSOTF_DB="${LGSOTF_DB:-lgsotf}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v owner_pw="$LGSOTF_OWNER_PASSWORD" -v app_pw="$LGSOTF_APP_PASSWORD" \
     -v shadow_pw="${LGSOTF_SHADOW_PASSWORD:-}" -v db="$LGSOTF_DB" <<'SQL'
CREATE ROLE lgsotf_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE lgsotf_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
SELECT :'shadow_pw' <> '' AS with_shadow \gset
\if :with_shadow
CREATE ROLE lgsotf_shadow LOGIN PASSWORD :'shadow_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
ALTER ROLE lgsotf_shadow SET default_transaction_read_only = on;
\endif
CREATE DATABASE :"db" OWNER lgsotf_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO lgsotf_owner;
GRANT CONNECT ON DATABASE :"db" TO lgsotf_app;
\if :with_shadow
GRANT CONNECT ON DATABASE :"db" TO lgsotf_shadow;
\endif
\connect :"db"
ALTER SCHEMA public OWNER TO lgsotf_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO lgsotf_app;
\if :with_shadow
GRANT USAGE ON SCHEMA public TO lgsotf_shadow;
\endif
SQL
