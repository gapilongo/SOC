"""The browser end-to-end suite: its stack driver, its Playwright wiring and its CI job."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict

import yaml

from tests.deploy._support import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "e2e_ui_stack.sh"
FRONT = REPO_ROOT / "src" / "lg_front"
SPEC = FRONT / "e2e" / "triage.spec.ts"
SUPPORT = FRONT / "e2e" / "support.ts"


def ci_job() -> Dict[str, Any]:
    data = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job: Dict[str, Any] = data["jobs"]["e2e-ui"]
    return job


def test_stack_script_is_strict_private_and_cleans_up() -> None:
    text = SCRIPT.read_text()
    assert os.access(SCRIPT, os.X_OK)
    assert "set -euo pipefail" in text
    # Secrets are generated into a private temp dir and reach Playwright through the environment only.
    assert 'chmod 700 "$WORK"' in text and 'install -m 600 /dev/null "$ENV_FILE"' in text
    assert "scripts/generate_secrets.py" in text
    assert 'E2E_ADMIN_PASSWORD="$(value LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD)"' in text
    assert "trap cleanup EXIT" in text and "down -v --remove-orphans" in text


def test_stack_script_runs_the_production_overlay_with_the_ui() -> None:
    text = SCRIPT.read_text()
    assert "-f docker/docker-compose.yml -f docker/docker-compose.prod.yml" in text
    assert "--profile frontend" in text
    up = re.search(r'"\$\{COMPOSE\[@\]\}" up -d --no-build --wait[^\n]*\\\n([^\n]*)', text)
    assert up and "frontend" in up.group(1) and "api" in up.group(1) and "worker" in up.group(1)
    # The UI origin is the one allowed for CORS and the WebSocket handshake.
    assert 'LG_SOTF_API__CORS_ORIGINS=[\\"$UI_URL\\"]' in text
    assert 'UI_URL="http://localhost:${UI_PORT}"' in text


def test_stack_script_fails_when_a_token_reaches_the_logs() -> None:
    text = SCRIPT.read_text()
    check = text[text.index('step "container logs carry no access tokens"'):]
    assert "logs --no-color frontend api worker scheduler" in check
    pattern = re.search(r"grep -Eq '([^']+)'", check)
    assert pattern
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl"
    assert re.search(pattern.group(1), f"WebSocket /api/v1/ws?token={jwt} [accepted]")
    assert not re.search(pattern.group(1), "WebSocket /api/v1/ws?token=[REDACTED:jwt] [accepted]")


def test_playwright_is_pinned_and_the_suite_is_wired() -> None:
    package = json.loads((FRONT / "package.json").read_text())
    version = package["devDependencies"]["@playwright/test"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), "pin Playwright exactly (its browser build depends on it)"
    assert package["scripts"]["e2e"] == "playwright test"
    lock = json.loads((FRONT / "package-lock.json").read_text())
    assert lock["packages"]["node_modules/@playwright/test"]["version"] == version
    # Unit tests (vitest) do not pick up the browser suite, and the type-check covers it.
    assert "include: ['src/**/*.test.{ts,tsx}']" in (FRONT / "vite.config.ts").read_text()
    refs = [r["path"] for r in json.loads((FRONT / "tsconfig.json").read_text())["references"]]
    assert "./tsconfig.e2e.json" in refs
    ignored = (FRONT / ".gitignore").read_text().split()
    assert "test-results/" in ignored and "playwright-report/" in ignored


def test_suite_covers_the_analyst_workflow_and_the_security_checks() -> None:
    spec = SPEC.read_text()
    support = SUPPORT.read_text()
    for flow in (
        "the Overview updates live",
        "filters, pagination and the alert timeline",
        "claims and decides an escalation",
        "the admin approves, the alert closes as malicious",
        "a viewer reads everything but sees no administration",
        "an analyst has no administration either",
        "sign-out ends the session",
    ):
        assert flow in spec, flow
    # Security assertions: the CSP on the wire, no violations in the browser, no token in storage.
    assert "content-security-policy" in spec and "unsafe-inline" in spec
    assert "securitypolicyviolation" in support
    assert "assertNoTokenInStorage" in spec and "localStorage" in support and "sessionStorage" in support
    # Credentials come from the environment, never from the source.
    assert "requiredEnv('E2E_ADMIN_PASSWORD')" in spec
    assert not re.search(r"password:\s*'[^']+'", spec)


def test_ci_runs_the_suite_against_the_compose_stack() -> None:
    job = ci_job()
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "npm ci" in runs and "npx playwright install --with-deps chromium" in runs
    assert "scripts/e2e_ui_stack.sh" in runs and "--no-build" not in runs, "the job builds both images"
    upload = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["if"] == "always()"
    assert "src/lg_front/playwright-report" in upload["with"]["path"]
    assert job["timeout-minutes"] >= 20
    lint = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]["lint"]
    shellcheck = next(s for s in lint["steps"] if s.get("name") == "Shellcheck")
    assert "scripts/e2e_ui_stack.sh" in shellcheck["run"]
