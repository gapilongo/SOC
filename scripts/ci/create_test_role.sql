-- The test suite's database role and database (CI and docker/docker-compose.test.yml run this file).
--
-- Run as a superuser. The image's POSTGRES_USER is a superuser, and superusers bypass row-level
-- security, so the tests connect as this plain role instead; tests/integration refuses a role that is a
-- superuser or has BYPASSRLS. CREATEDB lets the parallel tier create one database per xdist worker
-- (soc_test_gw<N>). The password is for throwaway CI and local test containers only.
CREATE ROLE soc LOGIN PASSWORD 'ci_only_password' NOSUPERUSER NOBYPASSRLS CREATEDB;
CREATE DATABASE soc_test OWNER soc;
-- The SELECT-only role shadow runs connect as (AI-E1.5c), like lgsotf_shadow in docker/postgres/init-roles.sh:
-- read-only sessions; the tests grant it SELECT on each test database (tests/integration/db/_support.py).
CREATE ROLE lgsotf_shadow LOGIN PASSWORD 'ci_only_password' NOSUPERUSER NOBYPASSRLS NOINHERIT;
ALTER ROLE lgsotf_shadow SET default_transaction_read_only = on;
