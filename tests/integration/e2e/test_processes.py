"""The real process roles: ``lg-sotf migrate``, ``lg-sotf worker`` and ``lg-sotf scheduler`` as subprocesses.

Only the process entry points are exercised here (CLI wiring, settings from
the environment, connector selection from tenant settings, graceful
shutdown, log hygiene); the test itself plays the API: it ingests, dispatches,
records review decisions and approvals through the services and enqueues the
resumes. The fake LLM is used throughout.

Flow: the scheduler polls a file source and the worker triages what it
dispatches; an analyst confirms a C2 alert per tenant; tenant B's approved
actions run on the dry-run connector; tenant A (webhook connector) gets its
low-risk actions approved while the install-wide ``response.dry_run`` kill
switch is on (dry-run, no request), then the worker is restarted with the
kill switch off and the admin's approval of the rest is delivered, twice, to
a local SOAR receiver that verifies every request's HMAC signature.
"""

from __future__ import annotations

import asyncio
import http.server
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence
from uuid import uuid4

import httpx
import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources.netpolicy import DestinationPolicy
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.connectors import encrypt_webhook_secret, verify_request
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.services.review import ReviewDenied, ReviewService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.e2e.conftest import eventually

pytestmark = [pytest.mark.integration, pytest.mark.slow]

CANARY = f"canary-{uuid4().hex}"
WEBHOOK_SECRET = f"whsec-{uuid4().hex}"
SETTLED = ("waiting_human", "waiting_approval", "completed", "dead_lettered")


def c2_event(source_alert_id: str) -> Dict[str, Any]:
    return {
        "source_alert_id": source_alert_id,
        "title": "Possible C2 beacon from workstation",
        "severity": "medium",
        "occurred_at": "2026-09-29T07:55:00Z",
        "description": f"Beacon every 60s. {CANARY}",
        "entities": {
            "ips": ["185.220.101.44", "10.0.0.5"],
            "hosts": ["ws-042"],
            "users": ["jdoe"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "processes": ["powershell.exe"],
        },
    }


BENIGN = {
    "source_alert_id": "bk-001",
    "title": "Scheduled backup maintenance test job",
    "severity": "low",
    "occurred_at": "2026-09-29T07:50:00Z",
    "description": f"nightly job {CANARY}",
    "entities": {"hosts": ["backup-01"]},
}


def lg_sotf_executable() -> str:
    found = shutil.which("lg-sotf", path=os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")]))
    if found is None:
        pytest.skip("the lg-sotf console script is not installed")
    return found


def receiver_address() -> Optional[str]:
    """A local IPv4 address the webhook destination policy accepts with private destinations allowed."""
    policy = DestinationPolicy(require_https=False, allow_private=True)
    for probe in ("192.0.2.1", "10.255.255.255", "203.0.113.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                address = str(s.getsockname()[0])
        except OSError:
            continue
        if policy.address_allowed(ipaddress.ip_address(address)):
            return address
    return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Soar:
    """The tenant's SOAR endpoint: verifies each request (signature, freshness, key) and deduplicates on action.id."""

    def __init__(self, host: str) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.rejected = 0
        self._results: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        soar = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                headers = httpx.Headers(list(self.headers.items()))
                action_id = verify_request(WEBHOOK_SECRET.encode(), headers, body)
                with soar._lock:
                    if action_id is None:
                        soar.rejected += 1
                        self.send_response(401)
                        self.end_headers()
                        return
                    soar.requests.append({"action_id": action_id, "body": json.loads(body), "key": headers["Idempotency-Key"]})
                    result = soar._results.setdefault(action_id, {"status": "succeeded", "reference": f"case-{len(soar._results) + 1}"})
                data = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer((host, 0), Handler)
        self.url = f"http://{host}:{self._server.server_address[1]}/hooks/lgsotf"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class Role:
    """One ``lg-sotf <role>`` subprocess with its combined output in a log file."""

    def __init__(self, exe: str, args: Sequence[str], env: Dict[str, str], log_path: Path) -> None:
        self.log_path = log_path
        self._log = open(log_path, "wb")
        self.proc = subprocess.Popen([exe, *args], stdout=self._log, stderr=subprocess.STDOUT, env=env, cwd=log_path.parent)

    def running(self) -> bool:
        return self.proc.poll() is None

    async def stop(self, timeout_s: float = 30.0) -> int:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            code = await asyncio.to_thread(self.proc.wait, timeout_s)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            await asyncio.to_thread(self.proc.wait)
            code = -9
        finally:
            self._log.close()
        return code

    def records(self) -> List[Dict[str, Any]]:
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line.strip()]


def role_env(settings: Settings, **extra: str) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("LG_SOTF_") and k not in ("DATABASE_URL", "REDIS_URL")}
    assert settings.security.encryption_keys is not None and settings.security.indicator_hmac_key is not None
    env.update(
        {
            "LG_SOTF_ENVIRONMENT": "test",
            "LG_SOTF_DATABASE__URL": settings.database.url.get_secret_value(),
            "LG_SOTF_DATABASE__POOL_MIN": "1",
            "LG_SOTF_DATABASE__POOL_MAX": "4",
            "LG_SOTF_REDIS__URL": settings.redis.url.get_secret_value(),
            "LG_SOTF_REDIS__KEY_PREFIX": settings.redis.key_prefix,
            "LG_SOTF_LLM__PROVIDER": "fake",
            "LG_SOTF_SECURITY__ENCRYPTION_KEYS": settings.security.encryption_keys.get_secret_value(),
            "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY": settings.security.indicator_hmac_key.get_secret_value(),
            "LG_SOTF_WORKER__BLOCK_MS": "200",
            "LG_SOTF_WORKER__CONCURRENCY": "4",
            "LG_SOTF_SCHEDULER__TICK_S": "0.5",
            "LG_SOTF_OBSERVABILITY__LOG_FORMAT": "json",
            **extra,
        }
    )
    return env


async def runs_are(repos: Repositories, tenant_id: str, alert_ids: Sequence[str], statuses: Sequence[str]) -> bool:
    for alert_id in alert_ids:
        try:
            if (await repos.runs.get(tenant_id, alert_id)).status not in statuses:
                return False
        except Exception:  # noqa: BLE001 - not dispatched yet
            return False
    return True


async def ledger(repos: Repositories, tenant_id: str, alert_id: str) -> Dict[str, Any]:
    return {str(a.id): a for a in (await repos.actions.list(tenant_id, alert_id=alert_id, limit=100)).items}


async def decide_true_positive(review: ReviewService, queue: WorkQueue, repos: Repositories, tenant_id: str, alert_id: str, user: Any) -> None:
    esc = await repos.escalations.get_active_for_alert(tenant_id, alert_id)
    assert esc is not None
    for rid, payload in await review.decide(tenant_id, esc.id, user, "analyst", "true_positive", "confirmed", [], esc.version):
        await queue.enqueue_resume(tenant_id, rid, payload)


async def approve(review: ReviewService, queue: WorkQueue, tenant_id: str, ids: List[str], user: Any, role: str, *, twice: bool = False) -> None:
    for rid, payload in await review.approve_actions(tenant_id, ids, user, role):
        await queue.enqueue_resume(tenant_id, rid, payload)
        if twice:
            await queue.enqueue_resume(tenant_id, rid, payload)


async def test_migrate_worker_and_scheduler_processes_end_to_end(
    e2e_settings: Callable[..., Settings], db: Any, repos: Repositories, redis_client: Any, tmp_path: Path
) -> None:
    exe = lg_sotf_executable()
    host = receiver_address()
    if host is None:
        pytest.skip("no non-loopback IPv4 address for the local SOAR receiver")
    settings = e2e_settings()
    env = role_env(settings)
    roles: List[Role] = []
    soar = Soar(host)
    ingestion = IngestionService(db, settings)
    try:
        # One-shot migrate against the already migrated test database: idempotent, exit 0.
        migrated = await asyncio.to_thread(
            subprocess.run, [exe, "migrate"], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=120
        )
        assert migrated.returncode == 0, migrated.stderr[-2000:]
        assert "schema: up to date; tenant: default" in migrated.stdout

        queue = WorkQueue(redis_client, settings)
        review = ReviewService(repos, settings)
        analyst_a = (await repos.users.create(TENANT_A, "analyst@a.example", "analyst")).id
        admin_a = (await repos.users.create(TENANT_A, "admin@a.example", "admin")).id
        admin_b = (await repos.users.create(TENANT_B, "admin@b.example", "admin")).id
        ciphertext = encrypt_webhook_secret(SecretBox.from_settings(settings), TENANT_A, WEBHOOK_SECRET)
        await repos.tenants.update_settings(
            TENANT_A, {"response": {"connector": "webhook", "webhook_url": soar.url, "webhook_secret_ciphertext": ciphertext}}
        )
        jsonl = tmp_path / "alerts.jsonl"
        jsonl.write_text(json.dumps(BENIGN) + "\n", encoding="utf-8")
        await repos.sources.create(TENANT_B, "file", "Dev file", source_id="dev-file", config={"path": str(jsonl)})

        scheduler = Role(exe, ["scheduler", "--metrics-host", "127.0.0.1", "--metrics-port", str(free_port())], env, tmp_path / "scheduler.log")
        worker = Role(exe, ["worker", "--metrics-host", "127.0.0.1", "--metrics-port", str(free_port())], env, tmp_path / "worker-1.log")
        roles += [scheduler, worker]

        ingested = {t: await ingestion.ingest(t, "api", [c2_event(f"c2-{t}")]) for t in (TENANT_A, TENANT_B)}
        for tenant_id, result in ingested.items():
            assert await dispatch_new_alerts(repos, queue, tenant_id, result.inserted) == 1
        c2 = {t: r.inserted[0].alert_id for t, r in ingested.items()}

        async def polled() -> bool:
            return len((await repos.alerts.list(TENANT_B, limit=10)).items) == 2

        await eventually(polled, within=60)
        benign_b = next(a.id for a in (await repos.alerts.list(TENANT_B, limit=10)).items if a.id != c2[TENANT_B])
        await eventually(lambda: runs_are(repos, TENANT_B, [benign_b], ("completed",)), within=60)
        benign = await repos.alerts.get(TENANT_B, benign_b)
        assert (benign.status, benign.disposition) == ("closed", "benign")
        await eventually(lambda: runs_are(repos, TENANT_A, [c2[TENANT_A]], ("waiting_human",)), within=60)
        await eventually(lambda: runs_are(repos, TENANT_B, [c2[TENANT_B]], ("waiting_human",)), within=60)
        assert scheduler.running() and worker.running()

        # Tenant B (no connector configured): the analyst confirms, the admin approves, actions run as dry-run.
        await decide_true_positive(review, queue, repos, TENANT_B, c2[TENANT_B], admin_b)
        await eventually(lambda: runs_are(repos, TENANT_B, [c2[TENANT_B]], ("waiting_approval",)), within=60)
        pending_b = [i for i, a in (await ledger(repos, TENANT_B, c2[TENANT_B])).items() if a.status == "awaiting_approval"]
        await approve(review, queue, TENANT_B, pending_b, admin_b, "admin")
        await eventually(lambda: runs_are(repos, TENANT_B, [c2[TENANT_B]], ("completed",)), within=60)
        final_b = await ledger(repos, TENANT_B, c2[TENANT_B])
        assert pending_b and all(final_b[i].status == "dry_run" and final_b[i].connector == "dry_run" for i in pending_b)

        # Tenant A (webhook connector) under the install kill switch: low risk approved by the analyst runs dry.
        await decide_true_positive(review, queue, repos, TENANT_A, c2[TENANT_A], analyst_a)
        await eventually(lambda: runs_are(repos, TENANT_A, [c2[TENANT_A]], ("waiting_approval",)), within=60)
        plan_a = await ledger(repos, TENANT_A, c2[TENANT_A])
        low = [i for i, a in plan_a.items() if a.status == "awaiting_approval" and a.risk_level == "low"]
        high = [i for i, a in plan_a.items() if a.status == "awaiting_approval" and a.risk_level == "high"]
        assert low and high
        with pytest.raises(ReviewDenied):
            await review.approve_actions(TENANT_A, high, analyst_a, "analyst")
        await approve(review, queue, TENANT_A, low, analyst_a, "analyst")

        async def low_ran() -> bool:
            current = await ledger(repos, TENANT_A, c2[TENANT_A])
            return all(current[i].status == "dry_run" for i in low)

        await eventually(low_ran, within=60)
        await eventually(lambda: runs_are(repos, TENANT_A, [c2[TENANT_A]], ("waiting_approval",)), within=60)
        assert soar.requests == []
        assert await worker.stop() == 0

        # Restart the worker with the kill switch off: the waiting run resumes from its checkpoint in a new process.
        live_env = role_env(settings, LG_SOTF_RESPONSE__DRY_RUN="false", LG_SOTF_INGESTION__ALLOW_PRIVATE_DESTINATIONS="true")
        worker = Role(exe, ["worker", "--metrics-host", "127.0.0.1", "--metrics-port", str(free_port())], live_env, tmp_path / "worker-2.log")
        roles.append(worker)
        rest = [i for i, a in (await ledger(repos, TENANT_A, c2[TENANT_A])).items() if a.status == "awaiting_approval"]
        await approve(review, queue, TENANT_A, rest, admin_a, "admin", twice=True)
        await eventually(lambda: runs_are(repos, TENANT_A, [c2[TENANT_A]], ("completed",)), within=60)

        final_a = await ledger(repos, TENANT_A, c2[TENANT_A])
        for action_id in rest:
            action = final_a[action_id]
            assert (action.status, action.connector, action.approved_by) == ("succeeded", "webhook", str(admin_a))
            assert action.result is not None and action.result["http_status"] == 200
            assert action.result["destination"] == "tenant" and action.result["response"]["status"] == "succeeded"
        assert soar.rejected == 0
        assert sorted(r["action_id"] for r in soar.requests) == sorted(rest), "exactly one request per approved action"
        assert all(r["key"] == r["action_id"] and r["body"]["tenant_id"] == TENANT_A for r in soar.requests)
        for tenant_id, alert_id in c2.items():
            alert = await repos.alerts.get(tenant_id, alert_id)
            assert (alert.status, alert.disposition) == ("closed", "malicious")
            assert (await repos.audit.verify_chain(tenant_id)).ok

        codes = [await role.stop() for role in (worker, scheduler)]
        assert codes == [0, 0]
    finally:
        for role in roles:
            if role.running():
                await role.stop(timeout_s=10)
        soar.close()
        await ingestion.close()

    for role in roles:
        records = role.records()
        events = {r["event"] for r in records}
        text = role.log_path.read_text()
        assert CANARY not in text and WEBHOOK_SECRET not in text, f"{role.log_path.name} leaks alert data or a secret"
        assert "Traceback" not in text
        assert [r for r in records if r["level"] in ("error", "critical")] == []
        assert "runtime.shutdown_requested" in events
    assert {"worker.started", "worker.stopped", "workflow.resumed"} <= {r["event"] for r in roles[-1].records()}
    assert {"scheduler.leadership_acquired", "scheduler.source_polled", "scheduler.stopped"} <= {r["event"] for r in roles[0].records()}
