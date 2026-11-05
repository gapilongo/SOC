# LG-SOTF developer and operator shortcuts. `make help` lists targets.
#
# Variables (override on the command line, e.g. `make image IMAGE=lg-sotf:0.2.0`):
#   PYTHON             interpreter for local targets
#   IMAGE              image tag built by `make image` and used by compose
#   PYTHON_BASE_IMAGE  base image (e.g. mirror.gcr.io/library/python:3.11-slim)
#   PROFILES           extra compose profiles, e.g. PROFILES=frontend
#   BUILD_CA_FILE      CA bundle for builds behind a TLS-intercepting proxy

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

PYTHON ?= python3
IMAGE ?= lg-sotf:dev
PYTHON_BASE_IMAGE ?= python:3.11-slim
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
dev: ## Install pinned dev dependencies and the package (editable) into the active venv
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install --no-deps -e .

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
test-fast: ## Unit and deploy tests only (no PostgreSQL or Redis needed)
	$(PYTHON) -m pytest tests/unit tests/deploy

.PHONY: check
check: lint typecheck import-lint test-fast ## Everything CI's lint and fast jobs run

.PHONY: security-scan
security-scan: ## Bandit over the product and the SOAR examples (pip install "bandit[toml]==1.8.6", as CI)
	bandit -q -r src/lg_sotf examples -ll -ii -b scripts/ci/bandit-baseline.json

.PHONY: test
test: ## Run the test suite (integration tests need LG_SOTF_TEST_DATABASE_URL / LG_SOTF_TEST_REDIS_URL)
	$(PYTHON) -m pytest

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
