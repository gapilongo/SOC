# LG-SOTF developer and operator shortcuts. `make help` lists targets.
#
# Variables (override on the command line, e.g. `make image IMAGE=lg-sotf:0.2.0`):
#   PYTHON             interpreter for local targets
#   IMAGE              image tag built by `make image` and used by compose
#   PYTHON_BASE_IMAGE  base image override (default: the digest-pinned one in docker/Dockerfile)
#   PROFILES           extra compose profiles, e.g. PROFILES=frontend
#   BUILD_CA_FILE      CA bundle for builds behind a TLS-intercepting proxy

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

PYTHON ?= python3
IMAGE ?= lg-sotf:dev
PYTHON_BASE_IMAGE ?=
PROFILES ?=
BUILD_CA_FILE ?=
HELM ?= helm
CHART := deploy/helm/lg-sotf

VERSION := $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' src/lg_sotf/__init__.py)
REVISION := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
CREATED := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

COMPOSE_FILES := -f docker/docker-compose.yml
COMPOSE_ENV := $(if $(wildcard .env),--env-file .env,)
COMPOSE_PROFILES := $(foreach p,$(PROFILES),--profile $(p))
COMPOSE = APP_IMAGE=$(IMAGE) PYTHON_BASE_IMAGE=$(PYTHON_BASE_IMAGE) \
	$(if $(BUILD_CA_FILE),BUILD_CA_FILE=$(abspath $(BUILD_CA_FILE)),) \
	docker compose $(COMPOSE_FILES) $(COMPOSE_ENV) $(COMPOSE_PROFILES)

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Local development
# ---------------------------------------------------------------------------
.PHONY: dev
dev: ## Install the hash-locked dev dependencies and the package (editable) into the active venv
	$(PYTHON) -m pip install --require-hashes -r requirements-dev.txt
	$(PYTHON) -m pip install --no-deps -e .

.PHONY: lock
lock: ## Re-lock every requirements file with hashes (needs uv; ARGS="--upgrade-package X")
	scripts/lock_requirements.sh $(ARGS)

.PHONY: env
env: ## Create .env from .env.example and add freshly generated secrets (never overwrites)
	@if [ ! -f .env ]; then install -m 600 .env.example .env; echo "created .env"; fi
	$(PYTHON) scripts/generate_secrets.py --append .env

.PHONY: secrets
secrets: ## Print a fresh set of secrets (KEY=value) without writing anything
	@$(PYTHON) scripts/generate_secrets.py

.PHONY: lint
lint: ## Ruff over the product, tests, scripts and examples
	ruff check src tests scripts docker examples

.PHONY: typecheck
typecheck: ## Mypy over every file listed in pyproject.toml [tool.mypy] files
	mypy

.PHONY: import-lint
import-lint: ## Layer and package dependency contracts (pyproject.toml [tool.importlinter])
	lint-imports

.PHONY: test-fast
test-fast: ## Unit, invariant and deploy tests only (no PostgreSQL or Redis needed)
	$(PYTHON) -m pytest tests/unit tests/invariants tests/deploy

.PHONY: check
check: lint typecheck import-lint test-fast ## Everything CI's lint and fast jobs run

.PHONY: security-scan
security-scan: ## Bandit over the product and the SOAR examples (bandit from scripts/ci/requirements-tools.txt, as CI)
	bandit -q -r src/lg_sotf examples -ll -ii -b scripts/ci/bandit-baseline.json

.PHONY: test
test: test-serial ## Run the test suite (integration tests need LG_SOTF_TEST_DATABASE_URL / LG_SOTF_TEST_REDIS_URL)

.PHONY: test-serial
test-serial: ## The whole suite in one process (what CI's blocking test job runs)
	$(PYTHON) -m pytest

.PHONY: test-parallel
test-parallel: ## The whole suite on 4 xdist workers (own database <name>_gw<N> and Redis DB base+N each)
	$(PYTHON) -m pytest -n 4 --dist loadfile

# Throwaway PostgreSQL and Redis for the integration tier (docker/docker-compose.test.yml, docs/testing.md).
TEST_COMPOSE = docker compose -f docker/docker-compose.test.yml
TEST_SERVICES_ENV = LG_SOTF_TEST_DATABASE_URL=postgresql://soc:ci_only_password@127.0.0.1:55433/soc_test \
	LG_SOTF_TEST_REDIS_URL=redis://127.0.0.1:56380/5

.PHONY: test-services
test-services: ## Start the test PostgreSQL (:55433) and Redis (:56380) on tmpfs and wait until healthy
	$(TEST_COMPOSE) up -d --wait

.PHONY: test-integration
test-integration: ## Integration tier against `make test-services` (PYTEST_ARGS="-n 4 --dist loadfile" for parallel)
	$(TEST_SERVICES_ENV) $(PYTHON) -m pytest tests/integration $(PYTEST_ARGS)

.PHONY: eval-cassettes
eval-cassettes: ## Record the committed evaluation cassettes again (fake model) against `make test-services`
	$(TEST_SERVICES_ENV) LG_SOTF_RECORD_CASSETTES=1 $(PYTHON) -m pytest tests/integration/eval/test_cassettes.py -k committed

.PHONY: eval-corpus-cassettes
eval-corpus-cassettes: ## Record the corpus_v1 cassettes again (fake model, about 4 min) against `make test-services`
	$(TEST_SERVICES_ENV) LG_SOTF_RECORD_CASSETTES=1 $(PYTHON) -m pytest tests/integration/eval/test_corpus_v1_eval.py

.PHONY: test-services-down
test-services-down: ## Stop and remove the test services (their data was on tmpfs)
	$(TEST_COMPOSE) down -v

# Wazuh 4.14 lab for the live ingestion contract tests (docker/docker-compose.wazuh-test.yml, docs/testing.md).
# The connector refuses loopback, so the tests reach the indexer on its Docker bridge address; the published
# port is for seeding and loading alerts only.
WAZUH_LAB_PROJECT ?= lg-sotf-test-wazuh
WAZUH_LAB_PORT ?= 59200
WAZUH_LAB_CA := build/wazuh-lab/root-ca.pem
WAZUH_COMPOSE = LG_SOTF_WAZUH_LAB_PROJECT=$(WAZUH_LAB_PROJECT) LG_SOTF_WAZUH_LAB_PORT=$(WAZUH_LAB_PORT) \
	docker compose -f docker/docker-compose.wazuh-test.yml
WAZUH_LAB_ADDRESS = $$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
	"$$($(WAZUH_COMPOSE) ps -q indexer)")

.PHONY: test-wazuh-up
test-wazuh-up: ## Start the Wazuh 4.14 indexer lab (:59200), copy its CA to build/wazuh-lab and seed it
	$(WAZUH_COMPOSE) up -d --wait
	mkdir -p $(dir $(WAZUH_LAB_CA))
	rm -f $(WAZUH_LAB_CA)
	$(WAZUH_COMPOSE) cp indexer:/usr/share/wazuh-indexer/config/certs/root-ca.pem $(WAZUH_LAB_CA)
	$(PYTHON) -m tests.fixtures.wazuh_lab --url https://127.0.0.1:$(WAZUH_LAB_PORT) --ca $(WAZUH_LAB_CA) seed

.PHONY: test-wazuh
test-wazuh: ## Live Wazuh contract tests (tests/live/wazuh) against `make test-wazuh-up`
	LG_SOTF_TEST_WAZUH_ADDRESS=$(WAZUH_LAB_ADDRESS) LG_SOTF_TEST_WAZUH_CA=$(WAZUH_LAB_CA) \
		$(PYTHON) -m pytest tests/live/wazuh -m live $(PYTEST_ARGS)

.PHONY: test-wazuh-down
test-wazuh-down: ## Stop and remove the Wazuh lab (its data was on tmpfs)
	$(WAZUH_COMPOSE) down -v

.PHONY: test-deploy
test-deploy: ## Deployment packaging tests only (Dockerfile, compose, Helm)
	$(PYTHON) -m pytest tests/deploy

.PHONY: coverage
coverage: ## Run the tests with a coverage report
	$(PYTHON) -m pytest --cov=lg_sotf --cov-branch --cov-report=term-missing:skip-covered --cov-report=xml

# ---------------------------------------------------------------------------
# Container image and compose stack
# ---------------------------------------------------------------------------
.PHONY: image
image: ## Build the application image (tag: IMAGE)
	docker build -f docker/Dockerfile -t $(IMAGE) \
		--build-arg BASE_IMAGE=$(PYTHON_BASE_IMAGE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg CREATED=$(CREATED) \
		$(if $(BUILD_CA_FILE),--secret id=build_ca$(,)src=$(BUILD_CA_FILE),) \
		.

.PHONY: up
up: ## Start the dev/eval stack (postgres, redis, migrate, api, worker, scheduler)
	$(COMPOSE) up -d --build --wait

.PHONY: down
down: ## Stop the stack (keeps volumes; `make clean-volumes` removes them)
	$(COMPOSE) down

.PHONY: clean-volumes
clean-volumes: ## Stop the stack and delete its database and redis volumes
	$(COMPOSE) down -v

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) ps -a

.PHONY: logs
logs: ## Follow stack logs
	$(COMPOSE) logs -f --tail=200

.PHONY: smoke
smoke: ## Build the image and run the end-to-end stack smoke test (scripts/smoke_stack.sh; tears down after)
	APP_IMAGE=$(IMAGE) PYTHON_BASE_IMAGE=$(PYTHON_BASE_IMAGE) \
		$(if $(BUILD_CA_FILE),BUILD_CA_FILE=$(abspath $(BUILD_CA_FILE)),) \
		scripts/smoke_stack.sh

.PHONY: quickstart
quickstart: ## Demo stack + seeded alerts, timed to the first verdict (OLLAMA=qwen3:8b for a local model)
	scripts/quickstart.sh $(if $(OLLAMA),--ollama $(OLLAMA),)

.PHONY: quickstart-down
quickstart-down: ## Stop the quickstart stack and delete its data and secrets
	scripts/quickstart.sh --down

.PHONY: pov
pov: ## Proof-of-value profile: SIEM=host[,host] [OLLAMA=model | LLM_URL=https://... LLM_MODEL=model] (docs/pov.md)
	scripts/pov.sh $(if $(SIEM),--siem-host $(SIEM),) $(if $(OLLAMA),--ollama $(OLLAMA),) \
		$(if $(LLM_URL),--llm-url $(LLM_URL) --llm-model $(LLM_MODEL),)

.PHONY: pov-down
pov-down: ## Stop the PoV stack and delete its data and secrets
	scripts/pov.sh --down

.PHONY: migrate
migrate: ## Run `lg-sotf migrate` in the stack (idempotent)
	$(COMPOSE) run --rm migrate

.PHONY: dlq
dlq: ## List dead-lettered queue entries in the stack
	$(COMPOSE) run --rm --no-deps scheduler dlq list

# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------
.PHONY: helm-lint
helm-lint: ## Lint and render the Helm chart (default and full values)
	$(HELM) lint --strict $(CHART)
	$(HELM) lint --strict $(CHART) -f $(CHART)/ci/full-values.yaml
	$(HELM) template ci $(CHART) >/dev/null
	$(HELM) template ci $(CHART) -f $(CHART)/ci/full-values.yaml >/dev/null
	@if command -v kubeconform >/dev/null; then \
		$(HELM) template ci $(CHART) -f $(CHART)/ci/full-values.yaml | kubeconform -strict -summary \
			-schema-location default \
			-schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'; \
	else echo "kubeconform not installed; skipped schema validation"; fi

, := ,
