#!/usr/bin/env python3
"""Load and capacity test of a real LG-SOTF deployment on one host.

Starts the real processes (``lg-sotf migrate``, ``lg-sotf api``, ``lg-sotf
scheduler`` and N ``lg-sotf worker`` subprocesses) against a PostgreSQL
database and a Redis database that it is allowed to wipe, seeds a large alert
history, then drives the public API the way customers do and measures the
whole system:

* ingest: ``POST /api/v1/ingest/alerts`` at open-loop rates (bursts and a
  sustained phase), per-request latency p50/p95/p99, status codes, 429s,
  errors, inserted/duplicate/rejected counts;
* end to end: time from ingestion to the run settling (closed, waiting for
  an analyst or an approval), alerts that never settle (dropped), failed and
  dead-lettered runs;
* workers: throughput per worker, run duration, node timings (``/metrics``),
  RSS and CPU over time (memory growth), warnings and errors in their logs;
* queue: stream depth, pending entries and consumer-group lag over time,
  DLQ depth;
* PostgreSQL: connections per application and state over time, the longest
  running statement, and ``EXPLAIN ANALYZE`` timings of the dashboard and
  alert-list queries at the seeded volume (default 100k alerts);
* Redis: ``used_memory`` and clients over time;
* readers: concurrent dashboard (cached and uncached windows) and alert list
  (filters, text search, second page) readers plus WebSocket clients
  (events received, delivery delay, disconnects).

The LLM is the offline ``fake`` provider with an injected per-call latency
(``--llm-latency``/``--deep-latency``, uniform in ``lo:hi`` seconds) so the
workflow waits like it does on a hosted model. The latency is injected by a
``sitecustomize`` module that this script writes to its work directory and
puts on the workers' ``PYTHONPATH``; the application code is unchanged.

Examples::

    source /home/user/venv/bin/activate
    # the default scenario: 100k seeded alerts, 4 workers, 1-3 s LLM calls,
    # bursts of 10/50/200 alerts/s and 5 minutes at 30 alerts/s
    python scripts/load_test.py --reset \\
        --database-url postgresql://soc:soc_dev_password@127.0.0.1:5432/soc_test_e \\
        --redis-url redis://127.0.0.1:6379/5

    # capacity: queue 800 alerts at once and measure how fast N workers drain them
    python scripts/load_test.py --reset --seed 0 --mode drain --backlog 800 --workers 2

The run is destructive: ``--reset`` drops the ``public`` schema of the
database and flushes the Redis database. It refuses a database whose name
does not contain ``test``, ``load`` or ``perf`` unless ``--force`` is given.
The JSON report (``--out``) holds every number; a summary is printed at the
end. See docs/performance.md for the methodology and the results.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import random
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import httpx
import redis.asyncio as aioredis

try:
    from websockets.asyncio.client import connect as ws_connect
except ImportError:  # pragma: no cover - older websockets
    from websockets import connect as ws_connect  # type: ignore[no-redef,attr-defined]

API = "/api/v1"
ROOT = Path(__file__).resolve().parent.parent
SETTLED_ALERT = ("closed", "waiting_human", "waiting_approval", "failed")
ADMIN_EMAIL = "loadtest-admin@example.com"
KEY_PREFIX = "lgsotf-load"

SITECUSTOMIZE = '''
"""Load-test hook (scripts/load_test.py): adds latency to the fake LLM's structured calls."""
import os as _os

_SPEC = _os.environ.get("LOADTEST_LLM_LATENCY")
if _SPEC:
    import asyncio as _asyncio
    import random as _random
    import time as _time

    from langchain_core.runnables import RunnableLambda as _RunnableLambda

    from lg_sotf.llm import fake as _fake

    _RANGES = {}
    for _part in _SPEC.split(","):
        _tier, _, _rng = _part.partition("=")
        _lo, _, _hi = _rng.partition(":")
        _RANGES[_tier.strip()] = (float(_lo), float(_hi or _lo))
    _orig = _fake.FakeChatModel.with_structured_output

    def _patched(self, schema, **kwargs):
        inner = _orig(self, schema, **kwargs)
        tier = "deep" if str(self.model_name).endswith("deep") else "fast"
        lo, hi = _RANGES.get(tier, _RANGES.get("fast", (0.0, 0.0)))

        def _run(input_, config=None):
            _time.sleep(_random.uniform(lo, hi))
            return inner.invoke(input_, config)

        async def _arun(input_, config=None):
            await _asyncio.sleep(_random.uniform(lo, hi))
            return await inner.ainvoke(input_, config)

        return _RunnableLambda(_run, afunc=_arun, name=f"Delayed[{getattr(schema, '__name__', 'schema')}]")

    _fake.FakeChatModel.with_structured_output = _patched
'''


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def pct(values: Sequence[float], p: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[k]


def dist(values: Sequence[float], scale: float = 1.0, digits: int = 1) -> Dict[str, Any]:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": round(sum(values) / len(values) * scale, digits),
        "p50": round((pct(values, 50) or 0) * scale, digits),
        "p95": round((pct(values, 95) or 0) * scale, digits),
        "p99": round((pct(values, 99) or 0) * scale, digits),
        "max": round(max(values) * scale, digits),
    }


def parse_range(text: str) -> Tuple[float, float]:
    lo, _, hi = text.partition(":")
    return float(lo), float(hi or lo)


def db_name(url: str) -> str:
    return urlsplit(url).path.lstrip("/")


def asyncpg_url(url: str) -> str:
    parts = urlsplit(url)
    scheme = "postgresql" if parts.scheme.startswith("postgres") else parts.scheme
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, ""))


def proc_stats(pid: int) -> Optional[Tuple[float, float]]:
    """(RSS MiB, CPU seconds) of a process from /proc, or None when it is gone."""
    try:
        with open(f"/proc/{pid}/status") as fh:
            rss_kb = next(int(line.split()[1]) for line in fh if line.startswith("VmRSS:"))
        with open(f"/proc/{pid}/stat") as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        ticks = os.sysconf("SC_CLK_TCK")
        cpu = (int(fields[11]) + int(fields[12])) / ticks
        return rss_kb / 1024.0, cpu
    except (OSError, StopIteration, ValueError, IndexError):
        return None


def host_cpu() -> Tuple[float, float]:
    """(busy, total) jiffies of the whole host from /proc/stat."""
    with open("/proc/stat") as fh:
        vals = [float(x) for x in fh.readline().split()[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0.0)
    return sum(vals) - idle, sum(vals)


def cpu_by_command(names: Tuple[str, ...] = ("postgres", "redis-server")) -> Dict[str, float]:
    """CPU seconds summed over all processes whose command name is one of ``names``."""
    ticks = os.sysconf("SC_CLK_TCK")
    out: Dict[str, float] = {n: 0.0 for n in names}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as fh:
                raw = fh.read()
        except OSError:
            continue
        comm = raw[raw.find("(") + 1 : raw.rfind(")")]
        for n in names:
            if comm.startswith(n[:15]):
                fields = raw.rsplit(")", 1)[1].split()
                out[n] += (int(fields[11]) + int(fields[12])) / ticks
    return out


async def redis_commandstats(redis: Any) -> Dict[str, int]:
    """Calls per Redis command since the server started."""
    stats = await redis.info("commandstats")
    return {
        k.replace("cmdstat_", ""): int(v["calls"]) for k, v in stats.items() if isinstance(v, dict) and "calls" in v
    }


def parse_prometheus(text: str) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            name, value = line.rsplit(" ", 1)
            out[name] = float(value)
        except ValueError:
            continue
    return out


# --------------------------------------------------------------------------
# alert generation
# --------------------------------------------------------------------------

BENIGN_TITLES = (
    "Scheduled backup job connected to storage",
    "Known software update downloaded",
    "Authorized vulnerability scan from scanner host",
    "Health check probe from monitoring",
    "Approved admin maintenance session",
)
SUSPICIOUS_TITLES = (
    "Unusual sign-in location for user",
    "Rare outbound connection to new domain",
    "New service installed on server",
    "Multiple failed logins followed by success",
    "Unusual process spawned by office application",
)
MALICIOUS_TITLES = (
    "Possible C2 beacon from workstation",
    "Mimikatz credential dumping detected on host",
    "Ransomware behaviour: mass file encryption",
    "Reverse shell spawned by web server",
    "Lateral movement with psexec",
)


@dataclass
class AlertFactory:
    run: str
    mix: Dict[str, float]
    hot_share: float
    rng: random.Random = field(default_factory=lambda: random.Random(1234))  # noqa: S311 - test data, not secrets
    n: int = 0

    def make(self) -> Dict[str, Any]:
        self.n += 1
        r = self.rng.random()
        benign_p = self.mix.get("benign", 0.55)
        susp_p = self.mix.get("suspicious", 0.30)
        if r < benign_p:
            kind, title, severity = (
                "benign",
                self.rng.choice(BENIGN_TITLES),
                self.rng.choice(("info", "low", "low", "medium")),
            )
            description = "Scheduled maintenance activity, expected and approved."
        elif r < benign_p + susp_p:
            kind, title, severity = (
                "suspicious",
                self.rng.choice(SUSPICIOUS_TITLES),
                self.rng.choice(("low", "medium", "medium", "high")),
            )
            description = "Activity deviates from the user's baseline."
        else:
            kind, title, severity = (
                "malicious",
                self.rng.choice(MALICIOUS_TITLES),
                self.rng.choice(("medium", "high", "high", "critical")),
            )
            description = "Malware suspected: beacon to command and control server, credential dump."
        ips = [
            f"203.0.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}",
            f"10.{self.rng.randint(0, 20)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}",
        ]
        if self.rng.random() < self.hot_share:
            ips.append("198.51.100.53")  # a proxy / DNS server that appears in many alerts
        return {
            "source_alert_id": f"load-{self.run}-{self.n}",
            "title": f"{title} ({kind[:1]}{self.n % 97})",
            "description": description,
            "severity": severity,
            "category": "load-test",
            "occurred_at": datetime.now(UTC).isoformat(),
            "entities": {
                "hosts": [f"host-{self.rng.randint(1, 500)}"],
                "users": [f"user{self.rng.randint(1, 300)}"],
                "ips": ips,
                "domains": [f"d{self.rng.randint(1, 3000)}.example.net"],
                "processes": ["powershell.exe"] if kind == "malicious" else [],
            },
            "mitre": {"tactics": ["TA0011"], "techniques": ["T1071"]} if kind == "malicious" else {},
        }


# --------------------------------------------------------------------------
# process management
# --------------------------------------------------------------------------


@dataclass
class Proc:
    name: str
    popen: subprocess.Popen
    log_path: Path
    metrics_url: Optional[str] = None
    samples: List[Tuple[float, float, float]] = field(default_factory=list)  # (t, rss MiB, cpu s)


class Stack:
    def __init__(self, args: argparse.Namespace, workdir: Path) -> None:
        self.args = args
        self.workdir = workdir
        self.procs: List[Proc] = []
        self.admin_password = "Adm1n-" + secrets.token_urlsafe(18)
        self.metrics_token = secrets.token_urlsafe(24)
        self.env = self._base_env()

    def _base_env(self) -> Dict[str, str]:
        from cryptography.fernet import Fernet

        env = {k: v for k, v in os.environ.items() if not k.startswith("LG_SOTF_")}
        env.update(
            {
                "LG_SOTF_ENVIRONMENT": "development",
                "LG_SOTF_DATABASE__URL": self.args.database_url,
                "LG_SOTF_REDIS__URL": self.args.redis_url,
                "LG_SOTF_REDIS__KEY_PREFIX": KEY_PREFIX,
                "LG_SOTF_LLM__PROVIDER": "fake",
                "LG_SOTF_AUTH__JWT_SECRET": secrets.token_urlsafe(48),
                "LG_SOTF_AUTH__COOKIE_SECURE": "false",
                "LG_SOTF_AUTH__ACCESS_TOKEN_TTL_S": "14400",
                "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL": ADMIN_EMAIL,
                "LG_SOTF_SECURITY__ENCRYPTION_KEYS": Fernet.generate_key().decode(),
                "LG_SOTF_SECURITY__INDICATOR_HMAC_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
                "LG_SOTF_API__METRICS_TOKEN": self.metrics_token,
                "LG_SOTF_API__PORT": str(self.args.api_port),
                "LG_SOTF_OBSERVABILITY__LOG_FORMAT": "json",
                "LG_SOTF_OBSERVABILITY__LOG_LEVEL": "INFO",
                "PYTHONUNBUFFERED": "1",
            }
        )
        if self.args.worker_concurrency:
            env["LG_SOTF_WORKER__CONCURRENCY"] = str(self.args.worker_concurrency)
        if self.args.per_tenant_concurrency:
            env["LG_SOTF_WORKER__PER_TENANT_CONCURRENCY"] = str(self.args.per_tenant_concurrency)
        for item in self.args.env or []:
            key, _, value = item.partition("=")
            env[key] = value
        return env

    def lg_sotf(self) -> List[str]:
        exe = shutil.which("lg-sotf")
        return [exe] if exe else [sys.executable, "-m", "lg_sotf"]

    def migrate(self) -> None:
        env = dict(self.env, LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD=self.admin_password)
        out = subprocess.run(  # noqa: S603 - our own CLI, fixed arguments
            self.lg_sotf() + ["migrate"], env=env, capture_output=True, text=True, timeout=300
        )
        if out.returncode != 0:
            raise SystemExit(f"lg-sotf migrate failed:\n{out.stdout[-2000:]}\n{out.stderr[-4000:]}")
        log(f"migrate: {out.stdout.strip().splitlines()[-1] if out.stdout.strip() else 'ok'}")

    def start(
        self, name: str, argv: List[str], extra_env: Optional[Dict[str, str]] = None, metrics_url: Optional[str] = None
    ) -> Proc:
        path = self.workdir / f"{name}.log"
        fh = open(path, "wb")  # noqa: SIM115 - closed with the process
        env = dict(self.env, **(extra_env or {}))
        popen = subprocess.Popen(  # noqa: S603 - our own CLI, fixed arguments
            self.lg_sotf() + argv,
            env=env,
            stdout=fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            cwd=str(self.workdir),
        )
        proc = Proc(name, popen, path, metrics_url)
        self.procs.append(proc)
        return proc

    def start_all(self) -> None:
        a = self.args
        self.start("api", ["api", "--host", "127.0.0.1", "--port", str(a.api_port)], extra_env={"PGAPPNAME": "api"})
        self.start(
            "scheduler",
            ["scheduler", "--metrics-host", "127.0.0.1", "--metrics-port", str(a.metrics_base_port)],
            metrics_url=f"http://127.0.0.1:{a.metrics_base_port}/metrics",
        )
        hook_dir = self.workdir / "hook"
        hook_dir.mkdir(exist_ok=True)
        (hook_dir / "sitecustomize.py").write_text(SITECUSTOMIZE)
        spec = f"fast={a.llm_latency},deep={a.deep_latency or a.llm_latency}"
        for i in range(a.workers):
            port = a.metrics_base_port + 1 + i
            self.start(
                f"worker{i + 1}",
                ["worker", "--metrics-host", "127.0.0.1", "--metrics-port", str(port)],
                extra_env={
                    "PYTHONPATH": str(hook_dir) + os.pathsep + self.env.get("PYTHONPATH", ""),
                    "LOADTEST_LLM_LATENCY": spec,
                    # names the LangGraph checkpointer's psycopg pool in pg_stat_activity
                    "PGAPPNAME": f"ckpt-worker{i + 1}",
                },
                metrics_url=f"http://127.0.0.1:{port}/metrics",
            )

    @property
    def workers(self) -> List[Proc]:
        return [p for p in self.procs if p.name.startswith("worker")]

    def check_alive(self) -> List[str]:
        return [f"{p.name} exited with {p.popen.returncode}" for p in self.procs if p.popen.poll() is not None]

    def stop(self) -> None:
        for p in self.procs:
            if p.popen.poll() is None:
                try:
                    os.killpg(p.popen.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.time() + 75
        for p in self.procs:
            try:
                p.popen.wait(timeout=max(1.0, deadline - time.time()))
            except subprocess.TimeoutExpired:
                os.killpg(p.popen.pid, signal.SIGKILL)
                p.popen.wait()


# --------------------------------------------------------------------------
# database preparation and seeding
# --------------------------------------------------------------------------


async def reset_database(url: str) -> None:
    conn = await asyncpg.connect(asyncpg_url(url))
    try:
        await conn.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    finally:
        await conn.close()


SEED_SQL = """
WITH s AS (
    SELECT g,
           now() - (random() * interval '30 days') AS ing,
           (g * 37) % 100 AS b,
           (g * 7) % 100 AS sb
    FROM generate_series($2::int, $3::int) AS g
)
INSERT INTO alerts (tenant_id, id, source_id, source_alert_id, fingerprint, title, severity, category, status,
                    disposition, confidence, threat_score, priority, occurred_at, ingested_at, closed_at,
                    raw, normalized, summary)
SELECT $1, 'seed-' || g, 'seed', 'seed-' || g, md5('fp' || (g % 20000)),
       (ARRAY['Suspicious PowerShell execution', 'Impossible travel sign-in', 'Outbound connection to rare domain',
              'Brute force against VPN', 'Scheduled task created', 'Port scan detected',
              'Malware quarantined by EDR', 'Admin group membership changed'])[1 + g % 8] || ' #' || (g % 997),
       CASE WHEN sb < 10 THEN 'info' WHEN sb < 40 THEN 'low' WHEN sb < 75 THEN 'medium' WHEN sb < 95 THEN 'high'
            ELSE 'critical' END,
       'seed',
       CASE WHEN b < 86 THEN 'closed' WHEN b < 94 THEN 'waiting_human' WHEN b < 96 THEN 'waiting_approval'
            ELSE 'failed' END,
       CASE WHEN b < 60 THEN 'benign' WHEN b < 80 THEN 'malicious' WHEN b < 86 THEN 'inconclusive' END,
       (b % 90) + 5, (sb % 90) + 5, 1 + (g % 10),
       ing - interval '2 minutes', ing,
       CASE WHEN b < 86 THEN ing + (random() * interval '4 hours') END,
       jsonb_build_object('title', 'seeded', 'vendor', 'seed', 'n', g,
            'detail', (SELECT string_agg(md5(g::text || 'r' || i), ' ') FROM generate_series(1, 25) AS i)),
       jsonb_build_object('title', 'seeded', 'entities', jsonb_build_object(
            'hosts', jsonb_build_array('host-' || (g % 500)), 'users', jsonb_build_array('user' || (g % 300)),
            'ips', jsonb_build_array('203.0.113.' || (g % 250))),
            'description', (SELECT string_agg(md5(g::text || 'n' || i), ' ') FROM generate_series(1, 15) AS i)),
       jsonb_build_object('verdict', CASE WHEN b < 60 THEN 'benign' ELSE 'malicious' END,
            'reasoning_digest', (SELECT string_agg(md5(g::text || 's' || i), ' ') FROM generate_series(1, 40) AS i),
            'indicators', jsonb_build_array('203.0.113.' || (g % 250), 'host-' || (g % 500)),
            'recommended_actions', jsonb_build_array('create_ticket'),
            'llm_usage', jsonb_build_object('calls', 3, 'input_tokens', 4200, 'output_tokens', 700))
FROM s
"""

SEED_RELATED_SQL = (
    """
    INSERT INTO workflow_runs (tenant_id, alert_id, thread_id, status, attempt, worker_id, created_at, updated_at, completed_at)
    SELECT tenant_id, id, tenant_id || ':' || id,
           CASE status WHEN 'closed' THEN 'completed' WHEN 'failed' THEN 'dead_lettered' ELSE status END, 1, 'seed',
           ingested_at, COALESCE(closed_at, ingested_at + interval '1 minute'),
           CASE WHEN status IN ('closed', 'failed') THEN COALESCE(closed_at, ingested_at + interval '1 minute') END
    FROM alerts WHERE tenant_id = $1 AND source_id = 'seed'
    """,
    """
    INSERT INTO escalations (tenant_id, alert_id, thread_id, level, status, reason, priority, sla_deadline,
                             decision, decided_at, claimed_at, created_at)
    SELECT tenant_id, id, tenant_id || ':' || id, 'L1',
           CASE WHEN status = 'waiting_human' THEN 'open' ELSE 'decided' END,
           'seeded', 5, ingested_at + interval '4 hours',
           CASE WHEN status = 'waiting_human' THEN NULL ELSE 'false_positive' END,
           CASE WHEN status = 'waiting_human' THEN NULL ELSE closed_at END,
           CASE WHEN status = 'waiting_human' THEN NULL ELSE ingested_at + interval '20 minutes' END,
           ingested_at
    FROM alerts
    WHERE tenant_id = $1 AND source_id = 'seed'
      AND (status = 'waiting_human' OR (status = 'closed' AND disposition = 'malicious'))
    """,
    """
    INSERT INTO indicator_sightings (tenant_id, indicator_type, value_hash, value_display, alert_id, seen_at)
    SELECT a.tenant_id, v.t, md5(v.t || ':' || v.val) || md5(v.val), left(v.val, 3) || '…', a.id, a.ingested_at
    FROM alerts a
    CROSS JOIN LATERAL (VALUES
        ('ip', '203.0.113.' || (substr(a.id, 6)::int % 250)),
        ('host', 'host-' || (substr(a.id, 6)::int % 500)),
        ('user', 'user' || (substr(a.id, 6)::int % 300))
    ) AS v(t, val)
    WHERE a.tenant_id = $1 AND a.source_id = 'seed'
    """,
    """
    INSERT INTO llm_usage_daily (tenant_id, day, model, agent, calls, input_tokens, output_tokens, cost_usd)
    SELECT $1, d::date, m, ag, 3000, 12000000, 2000000, 42.5
    FROM generate_series(current_date - 30, current_date - 1, interval '1 day') AS d,
         (VALUES ('claude-haiku-4-5'), ('claude-opus-5-5')) AS mm(m),
         (VALUES ('triage'), ('correlation'), ('analysis')) AS aa(ag)
    """,
)


async def seed(url: str, tenant_id: str, count: int) -> Dict[str, Any]:
    conn = await asyncpg.connect(asyncpg_url(url))
    started = time.perf_counter()
    try:
        await conn.execute("SELECT set_config('app.tenant_id', $1, false)", tenant_id)
        await conn.execute("SET statement_timeout = 0")
        batch = 25_000
        done = 0
        while done < count:
            n = min(batch, count - done)
            await conn.execute(SEED_SQL, tenant_id, done + 1, done + n)
            done += n
        for sql in SEED_RELATED_SQL:
            await conn.execute(sql, tenant_id)
        await conn.execute("ANALYZE")
        sizes = await conn.fetchrow(
            """SELECT count(*) AS n, avg(pg_column_size(summary))::int AS summary_b,
                      avg(pg_column_size(raw))::int AS raw_b, avg(pg_column_size(normalized))::int AS normalized_b,
                      pg_size_pretty(pg_total_relation_size('alerts')) AS alerts_total
               FROM alerts WHERE tenant_id = $1""",
            tenant_id,
        )
    finally:
        await conn.close()
    return {"alerts": count, "seconds": round(time.perf_counter() - started, 1), **dict(sizes)}


# --------------------------------------------------------------------------
# query plans at volume
# --------------------------------------------------------------------------

QUERY_PLANS: Dict[str, str] = {
    # lg_sotf.db.repos.alerts.AlertsRepo.dashboard_counts (24 h window)
    "dashboard_counts_24h": """
        SELECT GROUPING(status), GROUPING(severity), GROUPING(disposition), status, severity, disposition, count(*)
        FROM alerts WHERE tenant_id = $1 AND ingested_at >= now() - interval '24 hours'
        GROUP BY GROUPING SETS ((status), (severity), (disposition), ())""",
    "dashboard_counts_30d": """
        SELECT GROUPING(status), GROUPING(severity), GROUPING(disposition), status, severity, disposition, count(*)
        FROM alerts WHERE tenant_id = $1 AND ingested_at >= now() - interval '30 days'
        GROUP BY GROUPING SETS ((status), (severity), (disposition), ())""",
    # AlertsRepo.response_times
    "response_times_30d": """
        SELECT
          (SELECT extract(epoch FROM avg(e.claimed_at - e.created_at)) FROM escalations e
            WHERE e.tenant_id = $1 AND e.claimed_at >= now() - interval '30 days'),
          (SELECT count(*) FROM escalations e WHERE e.tenant_id = $1 AND e.claimed_at >= now() - interval '30 days'),
          (SELECT extract(epoch FROM avg(a.closed_at - a.ingested_at)) FROM alerts a
            WHERE a.tenant_id = $1 AND a.status = 'closed' AND a.closed_at >= now() - interval '30 days'),
          (SELECT count(*) FROM alerts a
            WHERE a.tenant_id = $1 AND a.status = 'closed' AND a.closed_at >= now() - interval '30 days')""",
    # RunsRepo.counts_by_status (dashboard queue depth)
    "runs_by_status": "SELECT status, count(*) FROM workflow_runs WHERE tenant_id = $1 GROUP BY status",
    "escalations_active": "SELECT count(*) FROM escalations WHERE tenant_id = $1 AND status IN ('open', 'claimed')",
    # AlertsRepo.list variants (GET /alerts)
    "alerts_list_first_page": """
        SELECT tenant_id, id, title, severity, status, summary FROM alerts WHERE tenant_id = $1
        ORDER BY ingested_at DESC, id DESC LIMIT 51""",
    "alerts_list_status_waiting": """
        SELECT tenant_id, id, title, severity, status, summary FROM alerts
        WHERE tenant_id = $1 AND status = ANY(ARRAY['waiting_human'])
        ORDER BY ingested_at DESC, id DESC LIMIT 51""",
    "alerts_list_severity_critical_open": """
        SELECT tenant_id, id, title, severity, status, summary FROM alerts
        WHERE tenant_id = $1 AND severity = ANY(ARRAY['critical']) AND status = ANY(ARRAY['waiting_human','failed'])
        ORDER BY ingested_at DESC, id DESC LIMIT 51""",
    "alerts_list_disposition_inconclusive": """
        SELECT tenant_id, id, title, severity, status, summary FROM alerts
        WHERE tenant_id = $1 AND disposition = ANY(ARRAY['inconclusive'])
        ORDER BY ingested_at DESC, id DESC LIMIT 51""",
    "alerts_search_q_30d": """
        SELECT tenant_id, id, title, severity, status, summary FROM alerts
        WHERE tenant_id = $1 AND title ILIKE '%brute force%' AND ingested_at >= now() - interval '30 days'
        ORDER BY ingested_at DESC, id DESC LIMIT 51""",
    "alerts_search_q_rare_30d": """
        SELECT tenant_id, id, title, severity, status, summary FROM alerts
        WHERE tenant_id = $1 AND title ILIKE '%no such title%' AND ingested_at >= now() - interval '30 days'
        ORDER BY ingested_at DESC, id DESC LIMIT 51""",
    # IndicatorsRepo.related_alerts for the shared "hot" indicator (correlation, 60 min window)
    "correlation_related_hot": """
        WITH hot AS (
            SELECT indicator_type, value_hash FROM indicator_sightings
            WHERE tenant_id = $1 AND seen_at >= now() - interval '60 minutes'
            GROUP BY 1, 2 ORDER BY count(*) DESC LIMIT 1
        )
        SELECT s.alert_id, count(*)::int, max(s.seen_at) FROM hot
        JOIN indicator_sightings s
          ON s.tenant_id = $1 AND s.indicator_type = hot.indicator_type AND s.value_hash = hot.value_hash
        WHERE s.seen_at >= now() - interval '60 minutes'
        GROUP BY s.alert_id ORDER BY 2 DESC, 3 DESC, 1 LIMIT 20""",
}


async def explain_queries(url: str, tenant_id: str) -> Dict[str, Any]:
    """EXPLAIN ANALYZE each query under the tenant's RLS scope (as the API runs them)."""
    conn = await asyncpg.connect(asyncpg_url(url))
    out: Dict[str, Any] = {}
    try:
        for name, sql in QUERY_PLANS.items():
            timings = []
            plan_text = ""
            for _ in range(3):
                async with conn.transaction(readonly=True):
                    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
                    rows = await conn.fetch(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}", tenant_id)
                plan = json.loads(rows[0][0])[0]
                timings.append(plan["Execution Time"] + plan.get("Planning Time", 0.0))
                plan_text = _plan_summary(plan["Plan"])
            out[name] = {"ms_min": round(min(timings), 2), "ms_max": round(max(timings), 2), "plan": plan_text}
    finally:
        await conn.close()
    return out


def _plan_summary(node: Dict[str, Any], depth: int = 0) -> str:
    label = node.get("Node Type", "?")
    if node.get("Index Name"):
        label += f" using {node['Index Name']}"
    if node.get("Relation Name") and "Index Name" not in node:
        label += f" on {node['Relation Name']}"
    label += f" rows={node.get('Actual Rows')}"
    if node.get("Rows Removed by Filter"):
        label += f" removed={node['Rows Removed by Filter']}"
    parts = [("  " * depth) + label]
    for child in node.get("Plans", []) or []:
        parts.append(_plan_summary(child, depth + 1))
    return "\n".join(parts)


# --------------------------------------------------------------------------
# measurement state
# --------------------------------------------------------------------------


@dataclass
class PhaseStats:
    name: str
    rate: float
    seconds: float
    batch: int
    sent_requests: int = 0
    sent_alerts: int = 0
    latencies: List[float] = field(default_factory=list)
    timed: List[Tuple[float, float]] = field(default_factory=list)  # (send offset s, latency s)
    codes: Counter = field(default_factory=Counter)
    errors: Counter = field(default_factory=Counter)
    inserted: int = 0
    duplicates: int = 0
    rejected: int = 0
    enqueued: int = 0
    max_inflight: int = 0
    max_start_lag: float = 0.0
    started_at: float = 0.0
    ended_at: float = 0.0
    last_done_at: float = 0.0

    def report(self) -> Dict[str, Any]:
        elapsed = max(self.ended_at - self.started_at, 1e-9)
        ok = self.codes.get(202, 0)
        return {
            "name": self.name,
            "target_alerts_per_s": self.rate,
            "seconds": self.seconds,
            "batch": self.batch,
            "requests": self.sent_requests,
            "alerts_sent": self.sent_alerts,
            "achieved_alerts_per_s": round(self.sent_alerts / elapsed, 1),
            # alerts the API accepted per second, measured to the last response (not the last send)
            "accepted_alerts_per_s": round(self.inserted / max(self.last_done_at - self.started_at, 1e-9), 1),
            "latency_ms": dist(self.latencies, 1000.0),
            "status_codes": {str(k): v for k, v in sorted(self.codes.items(), key=lambda kv: str(kv[0]))},
            "error_rate": round(1 - ok / self.sent_requests, 4) if self.sent_requests else None,
            "errors": dict(self.errors),
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "enqueued": self.enqueued,
            "max_inflight_requests": self.max_inflight,
            "max_client_start_lag_s": round(self.max_start_lag, 3),
            "latency_ms_by_10s": self._buckets(),
        }

    def _buckets(self) -> List[Dict[str, Any]]:
        buckets: Dict[int, List[float]] = defaultdict(list)
        for offset, lat in self.timed:
            buckets[int(offset // 10)].append(lat)
        return [{"from_s": k * 10, **dist(v, 1000.0)} for k, v in sorted(buckets.items())]


@dataclass
class Readers:
    latencies: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    codes: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    errors: Counter = field(default_factory=Counter)
    ws_events: int = 0
    ws_delays: List[float] = field(default_factory=list)
    ws_closes: Counter = field(default_factory=Counter)
    ws_connects: int = 0
    ws_types: Counter = field(default_factory=Counter)

    def report(self) -> Dict[str, Any]:
        return {
            "http": {
                name: {"latency_ms": dist(vals, 1000.0), "codes": {str(k): v for k, v in self.codes[name].items()}}
                for name, vals in sorted(self.latencies.items())
            },
            "errors": dict(self.errors),
            "websocket": {
                "connections": self.ws_connects,
                "events_received": self.ws_events,
                "delivery_delay_ms": dist(self.ws_delays, 1000.0),
                "closes": dict(self.ws_closes),
                "events_by_type": dict(self.ws_types),
            },
        }


# --------------------------------------------------------------------------
# the test
# --------------------------------------------------------------------------


class LoadTest:
    def __init__(self, args: argparse.Namespace, stack: Stack) -> None:
        self.args = args
        self.stack = stack
        self.base = f"http://127.0.0.1:{args.api_port}"
        self.run_id = uuid.uuid4().hex[:8]
        self.tenants: List[str] = ["default"]
        self.ingest_keys: Dict[str, str] = {}
        self.source_ids: List[str] = []
        self.reader_tokens: List[Tuple[str, str]] = []  # (tenant, token)
        self.admin_token = ""
        self.phases: List[PhaseStats] = []
        self.readers = Readers()
        self.timeline: List[Dict[str, Any]] = []
        self.t0 = time.monotonic()
        self.stop_readers = asyncio.Event()
        self.stop_sampler = asyncio.Event()
        self.alert_ids: List[str] = []
        self.marks: List[Tuple[float, str]] = []
        self.redis_commands_start: Dict[str, int] = {}
        self.redis_commands_end: Dict[str, int] = {}
        self.loop_lag_max = 0.0
        self.loop_lags: List[float] = []

    async def loop_lag_monitor(self) -> None:
        """Measures this client's own event-loop lag, so client-side stalls are not blamed on the server."""
        while not self.stop_sampler.is_set():
            before = time.perf_counter()
            await asyncio.sleep(0.1)
            lag = time.perf_counter() - before - 0.1
            self.loop_lag_max = max(self.loop_lag_max, lag)
            self.loop_lags.append(lag)

    # -- setup -----------------------------------------------------------------

    async def wait_ready(self, client: httpx.AsyncClient) -> None:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            dead = self.stack.check_alive()
            if dead:
                raise SystemExit("process died during start-up: " + "; ".join(dead))
            try:
                r = await client.get(f"{self.base}/readyz")
                if r.status_code == 200:
                    ready_workers = 0
                    for p in self.stack.workers:
                        try:
                            rr = await client.get(p.metrics_url.replace("/metrics", "/readyz"))  # type: ignore[union-attr]
                            ready_workers += rr.status_code == 200
                        except httpx.HTTPError:
                            pass
                    if ready_workers == len(self.stack.workers):
                        return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(1)
        raise SystemExit("stack did not become ready within 120 s")

    async def login(self, client: httpx.AsyncClient, email: str, password: str, tenant: Optional[str] = None) -> str:
        body: Dict[str, Any] = {"email": email, "password": password}
        if tenant:
            body["tenant"] = tenant
        r = await client.post(f"{self.base}{API}/auth/login", json=body)
        r.raise_for_status()
        return str(r.json()["access_token"])

    async def setup(self, client: httpx.AsyncClient) -> None:
        self.admin_token = await self.login(client, ADMIN_EMAIL, self.stack.admin_password)
        admin = {"Authorization": f"Bearer {self.admin_token}"}
        for i in range(1, self.args.tenants):
            tid = f"load-t{i}"
            r = await client.post(
                f"{self.base}{API}/platform/tenants", headers=admin, json={"id": tid, "name": f"Load {i}"}
            )
            if r.status_code not in (200, 201):
                raise SystemExit(f"tenant creation failed: {r.status_code} {r.text[:300]}")
            self.tenants.append(tid)
        for tid in self.tenants:
            headers = dict(admin, **({"X-Tenant-ID": tid} if tid != "default" else {}))
            r = await client.post(
                f"{self.base}{API}/api-keys", headers=headers, json={"name": f"load-{tid}", "scopes": ["ingest"]}
            )
            r.raise_for_status()
            data = r.json()
            self.ingest_keys[tid] = data["key"]
            self.source_ids.append(f"api:{data['id']}")
        # one viewer account per reader so per-principal rate limits apply as for real analysts
        for i in range(self.args.readers + min(self.args.ws_clients, 5)):
            tid = self.tenants[i % len(self.tenants)]
            email = f"viewer{i}-{self.run_id}@example.com"
            password = "Viewer-" + secrets.token_urlsafe(12)
            headers = dict(admin, **({"X-Tenant-ID": tid} if tid != "default" else {}))
            r = await client.post(
                f"{self.base}{API}/users",
                headers=headers,
                json={"email": email, "role": "viewer", "password": password},
            )
            r.raise_for_status()
            self.reader_tokens.append((tid, await self.login(client, email, password, tenant=tid)))

    # -- ingest ----------------------------------------------------------------

    async def run_phase(
        self, client: httpx.AsyncClient, factory: AlertFactory, name: str, rate: float, seconds: float
    ) -> PhaseStats:
        batch = self.args.batch
        stats = PhaseStats(name, rate, seconds, batch)
        self.phases.append(stats)
        self.mark(f"phase {name} start")
        interval = batch / rate
        total_requests = int(round(rate * seconds / batch))
        stats.started_at = time.monotonic()
        inflight: set[asyncio.Task[None]] = set()
        sem = asyncio.Semaphore(self.args.max_inflight)

        async def one(tenant: str, alerts: List[Dict[str, Any]]) -> None:
            key = self.ingest_keys[tenant]
            started = time.perf_counter()
            try:
                r = await client.post(f"{self.base}{API}/ingest/alerts", headers={"X-API-Key": key}, json=alerts)
                stats.latencies.append(time.perf_counter() - started)
                stats.timed.append((time.monotonic() - stats.started_at, time.perf_counter() - started))
                stats.codes[r.status_code] += 1
                if r.status_code == 202:
                    body = r.json()
                    stats.inserted += body.get("inserted", 0)
                    stats.duplicates += body.get("duplicates", 0)
                    stats.rejected += body.get("rejected", 0)
                    stats.enqueued += body.get("enqueued", 0)
                    self.alert_ids.extend(i["alert_id"] for i in body.get("items", []) if i.get("status") == "inserted")
                else:
                    try:
                        stats.errors[str(r.json().get("error", {}).get("code"))] += 1
                    except ValueError:
                        stats.errors[f"http_{r.status_code}"] += 1
            except httpx.HTTPError as exc:
                stats.latencies.append(time.perf_counter() - started)
                stats.codes["exception"] += 1
                stats.errors[type(exc).__name__] += 1
            finally:
                stats.last_done_at = max(stats.last_done_at, time.monotonic())
                sem.release()

        for i in range(total_requests):
            due = stats.started_at + i * interval
            delay = due - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            else:
                stats.max_start_lag = max(stats.max_start_lag, -delay)
            await sem.acquire()
            tenant = self.tenants[i % len(self.tenants)]
            alerts = [factory.make() for _ in range(batch)]
            stats.sent_requests += 1
            stats.sent_alerts += batch
            task = asyncio.create_task(one(tenant, alerts))
            inflight.add(task)
            task.add_done_callback(inflight.discard)
            stats.max_inflight = max(stats.max_inflight, len(inflight))
        stats.ended_at = time.monotonic()
        if inflight:
            await asyncio.gather(*inflight, return_exceptions=True)
        self.mark(f"phase {name} end")
        rep = stats.report()
        log(
            f"phase {name}: {rep['alerts_sent']} alerts at {rep['achieved_alerts_per_s']}/s, "
            f"latency p50/p95/p99 {rep['latency_ms'].get('p50')}/{rep['latency_ms'].get('p95')}/{rep['latency_ms'].get('p99')} ms, "
            f"codes {rep['status_codes']}"
        )
        return stats

    # -- readers ---------------------------------------------------------------

    async def reader(self, client: httpx.AsyncClient, idx: int) -> None:
        tenant, token = self.reader_tokens[idx]
        headers = {"Authorization": f"Bearer {token}"}
        rng = random.Random(idx)  # noqa: S311 - request mix, not secrets
        requests = [
            ("dashboard_cached", lambda: f"{API}/dashboard/summary?window_hours=24"),
            ("dashboard_uncached", lambda: f"{API}/dashboard/summary?window_hours={rng.randint(25, 2160)}"),
            ("alerts_list", lambda: f"{API}/alerts?limit=50"),
            ("alerts_waiting_human", lambda: f"{API}/alerts?status=waiting_human&limit=50"),
            ("alerts_critical", lambda: f"{API}/alerts?severity=critical&severity=high&limit=50"),
            ("alerts_search", lambda: f"{API}/alerts?q=beacon&limit=50"),
        ]
        cursor: Optional[str] = None
        i = 0
        while not self.stop_readers.is_set():
            name, path_fn = requests[i % len(requests)]
            i += 1
            path = path_fn()
            if name == "alerts_list" and cursor and i % 12 == 3:
                name, path = "alerts_page2", f"{API}/alerts?limit=50&cursor={cursor}"
            started = time.perf_counter()
            try:
                r = await client.get(f"{self.base}{path}", headers=headers)
                self.readers.latencies[name].append(time.perf_counter() - started)
                self.readers.codes[name][r.status_code] += 1
                if r.status_code == 200 and name == "alerts_list":
                    cursor = r.json().get("next_cursor")
            except httpx.HTTPError as exc:
                self.readers.errors[f"{name}:{type(exc).__name__}"] += 1
            try:
                await asyncio.wait_for(self.stop_readers.wait(), timeout=self.args.reader_interval)
            except TimeoutError:
                pass

    async def ws_client(self, idx: int) -> None:
        _tenant, token = self.reader_tokens[idx % len(self.reader_tokens)]
        url = f"ws://127.0.0.1:{self.args.api_port}{API}/ws?token={token}"
        while not self.stop_readers.is_set():
            try:
                async with ws_connect(url, open_timeout=15, max_size=2**20) as ws:
                    self.readers.ws_connects += 1
                    while not self.stop_readers.is_set():
                        try:
                            raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        except TimeoutError:
                            continue
                        now = datetime.now(UTC)
                        try:
                            msg = json.loads(raw)
                        except ValueError:
                            continue
                        if msg.get("type") in ("hello", "ping"):
                            continue
                        self.readers.ws_events += 1
                        self.readers.ws_types[str(msg.get("type"))] += 1
                        ts = msg.get("ts")
                        if ts:
                            try:
                                self.readers.ws_delays.append((now - datetime.fromisoformat(ts)).total_seconds())
                            except ValueError:
                                pass
            except Exception as exc:  # noqa: BLE001 - count and reconnect
                code = getattr(getattr(exc, "rcvd", None), "code", None)
                self.readers.ws_closes[f"{type(exc).__name__}:{code}"] += 1
                await asyncio.sleep(1.0)

    # -- sampler ---------------------------------------------------------------

    def mark(self, label: str) -> None:
        self.marks.append((round(time.monotonic() - self.t0, 1), label))

    async def sampler(self, client: httpx.AsyncClient) -> None:
        conn = await asyncpg.connect(asyncpg_url(self.args.database_url))
        await conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
        redis = aioredis.from_url(self.args.redis_url)
        streams = {"high": f"{KEY_PREFIX}:q:alerts:high", "normal": f"{KEY_PREFIX}:q:alerts:normal"}
        dlq = f"{KEY_PREFIX}:q:alerts:dlq"
        dbname = db_name(self.args.database_url)
        self.redis_commands_start = await redis_commandstats(redis)
        prev_host = host_cpu()
        prev_cmd = cpu_by_command()
        prev_self = proc_stats(os.getpid())
        prev_t = time.monotonic()
        try:
            while not self.stop_sampler.is_set():
                t = round(time.monotonic() - self.t0, 1)
                sample: Dict[str, Any] = {"t": t}
                try:
                    q: Dict[str, Any] = {}
                    for label, key in streams.items():
                        depth = int(await redis.xlen(key))
                        pending = 0
                        lag = None
                        try:
                            pending = int((await redis.xpending(key, "workers")).get("pending") or 0)
                            for g in await redis.xinfo_groups(key):
                                if (g.get("name") or b"") in (b"workers", "workers"):
                                    lag = g.get("lag")
                        except Exception as exc:  # noqa: BLE001 - group not created yet
                            q["group_error"] = type(exc).__name__
                        q[label] = {"depth": depth, "pending": pending, "lag": lag}
                    q["dlq"] = int(await redis.xlen(dlq))
                    sample["queue"] = q
                    info = await redis.info("memory")
                    clients = await redis.info("clients")
                    sample["redis_mb"] = round(int(info["used_memory"]) / 2**20, 2)
                    sample["redis_clients"] = int(clients["connected_clients"])
                except Exception as exc:  # noqa: BLE001
                    sample["redis_error"] = type(exc).__name__
                try:
                    rows = await conn.fetch(
                        """SELECT COALESCE(NULLIF(application_name, ''), '?') AS app, state, count(*) AS n,
                                  max(extract(epoch FROM now() - query_start)) FILTER (WHERE state = 'active') AS longest
                           FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()
                           GROUP BY 1, 2""",
                        dbname,
                    )
                    pg: Dict[str, Dict[str, int]] = defaultdict(dict)
                    longest = 0.0
                    for r in rows:
                        pg[r["app"]][r["state"] or "none"] = int(r["n"])
                        longest = max(longest, float(r["longest"] or 0))
                    sample["pg"] = dict(pg)
                    sample["pg_total"] = sum(sum(v.values()) for v in pg.values())
                    sample["pg_longest_active_s"] = round(longest, 2)
                    total = await conn.fetchval("SELECT count(*) FROM pg_stat_activity")
                    sample["pg_server_total"] = int(total)
                    status_rows = await conn.fetch(
                        "SELECT status, count(*) AS n FROM alerts WHERE tenant_id = ANY($1::text[]) AND source_id = ANY($2::text[]) GROUP BY status",
                        self.tenants,
                        self.source_ids,
                    )
                    sample["alerts"] = {r["status"]: int(r["n"]) for r in status_rows}
                except Exception as exc:  # noqa: BLE001
                    sample["pg_error"] = type(exc).__name__
                procs: Dict[str, Any] = {}
                for p in self.stack.procs:
                    st = proc_stats(p.popen.pid)
                    if st is not None:
                        p.samples.append((t, st[0], st[1]))
                        procs[p.name] = {"rss_mb": round(st[0], 1), "cpu_s": round(st[1], 1)}
                sample["procs"] = procs
                now_host, now_cmd, now_self, now_t = (
                    host_cpu(),
                    cpu_by_command(),
                    proc_stats(os.getpid()),
                    time.monotonic(),
                )
                dt = max(now_t - prev_t, 1e-9)
                busy = now_host[0] - prev_host[0]
                total = now_host[1] - prev_host[1]
                sample["host_cpu_pct"] = round(100 * busy / total, 1) if total else None
                sample["postgres_cores"] = round((now_cmd["postgres"] - prev_cmd["postgres"]) / dt, 2)
                sample["redis_cores"] = round((now_cmd["redis-server"] - prev_cmd["redis-server"]) / dt, 2)
                if now_self and prev_self:
                    sample["loadgen_cores"] = round((now_self[1] - prev_self[1]) / dt, 2)
                sample["loadgen_loop_lag_max_s"] = round(self.loop_lag_max, 3)
                self.loop_lag_max = 0.0
                prev_host, prev_cmd, prev_self, prev_t = now_host, now_cmd, now_self, now_t
                self.timeline.append(sample)
                try:
                    await asyncio.wait_for(self.stop_sampler.wait(), timeout=self.args.sample_interval)
                except TimeoutError:
                    pass
            self.redis_commands_end = await redis_commandstats(redis)
        finally:
            await conn.close()
            await redis.aclose()

    # -- settle ----------------------------------------------------------------

    async def wait_settled(self, limit_s: float) -> Dict[str, Any]:
        conn = await asyncpg.connect(asyncpg_url(self.args.database_url))
        await conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
        started = time.monotonic()
        expected = len(self.alert_ids)
        last_log = 0.0
        counts: Dict[str, int] = {}
        try:
            while True:
                rows = await conn.fetch(
                    """SELECT a.status AS alert_status, r.status AS run_status, count(*) AS n
                       FROM alerts a LEFT JOIN workflow_runs r ON r.tenant_id = a.tenant_id AND r.alert_id = a.id
                       WHERE a.tenant_id = ANY($1::text[]) AND a.source_id = ANY($2::text[])
                       GROUP BY 1, 2""",
                    self.tenants,
                    self.source_ids,
                )
                counts = {f"{r['alert_status']}/{r['run_status']}": int(r["n"]) for r in rows}
                settled = sum(
                    int(r["n"])
                    for r in rows
                    if r["alert_status"] in SETTLED_ALERT and r["run_status"] not in ("queued", "running")
                )
                elapsed = time.monotonic() - started
                if time.monotonic() - last_log > 15:
                    log(f"settling: {settled}/{expected} after {elapsed:.0f}s {counts}")
                    last_log = time.monotonic()
                if settled >= expected or elapsed > limit_s:
                    return {"expected": expected, "settled": settled, "seconds": round(elapsed, 1), "by_status": counts}
                dead = self.stack.check_alive()
                if dead:
                    log("WARNING: " + "; ".join(dead))
                await asyncio.sleep(2)
        finally:
            await conn.close()

    async def end_to_end(self) -> Dict[str, Any]:
        conn = await asyncpg.connect(asyncpg_url(self.args.database_url))
        await conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
        try:
            rows = await conn.fetch(
                """SELECT a.status, a.severity, a.disposition, r.status AS run_status, r.worker_id, r.attempt,
                          extract(epoch FROM (COALESCE(r.completed_at, r.updated_at) - a.ingested_at)) AS e2e,
                          a.ingested_at, COALESCE(r.completed_at, r.updated_at) AS finished_at,
                          pg_column_size(a.summary) AS summary_bytes
                   FROM alerts a LEFT JOIN workflow_runs r ON r.tenant_id = a.tenant_id AND r.alert_id = a.id
                   WHERE a.tenant_id = ANY($1::text[]) AND a.source_id = ANY($2::text[])""",
                self.tenants,
                self.source_ids,
            )
            usage = await conn.fetch(
                "SELECT model, agent, sum(calls) AS calls, sum(input_tokens) AS it, sum(output_tokens) AS ot FROM llm_usage_daily "
                "WHERE day = current_date AND tenant_id = ANY($1::text[]) GROUP BY 1, 2 ORDER BY 1, 2",
                self.tenants,
            )
            esc = await conn.fetchval(
                "SELECT count(*) FROM escalations WHERE tenant_id = ANY($1::text[]) AND reason <> 'seeded'",
                self.tenants,
            )
            actions = await conn.fetch(
                "SELECT status, count(*) AS n FROM response_actions WHERE tenant_id = ANY($1::text[]) GROUP BY 1",
                self.tenants,
            )
            events = await conn.fetchval(
                "SELECT count(*) FROM alert_events WHERE tenant_id = ANY($1::text[])", self.tenants
            )
            checkpoints = await conn.fetchrow(
                "SELECT (SELECT count(*) FROM checkpoints) AS checkpoints, (SELECT count(*) FROM checkpoint_writes) AS writes, "
                "(SELECT count(*) FROM checkpoint_blobs) AS blobs, "
                "pg_size_pretty(pg_total_relation_size('checkpoints') + pg_total_relation_size('checkpoint_writes') "
                "+ pg_total_relation_size('checkpoint_blobs')) AS size"
            )
        finally:
            await conn.close()
        settled_rows = [
            r for r in rows if r["status"] in SETTLED_ALERT and r["run_status"] not in ("queued", "running")
        ]
        e2e = [float(r["e2e"]) for r in settled_rows if r["e2e"] is not None]
        by_outcome: Dict[str, List[float]] = defaultdict(list)
        for r in settled_rows:
            if r["e2e"] is not None:
                by_outcome[f"{r['status']}"].append(float(r["e2e"]))
            attempts = Counter(int(r["attempt"] or 0) for r in rows)
        finished = sorted(r["finished_at"] for r in settled_rows if r["finished_at"] is not None)
        # completions per minute (throughput over time)
        per_minute: Counter = Counter()
        if finished:
            first = finished[0]
            for f in finished:
                per_minute[int((f - first).total_seconds() // 60)] += 1
        total_calls = sum(int(u["calls"]) for u in usage)
        return {
            "alerts": len(rows),
            "settled": len(settled_rows),
            "not_settled": len(rows) - len(settled_rows),
            "by_status": dict(Counter(r["status"] for r in rows)),
            "by_run_status": dict(Counter(str(r["run_status"]) for r in rows)),
            "by_disposition": dict(Counter(str(r["disposition"]) for r in rows)),
            "run_attempts": {str(k): v for k, v in sorted(attempts.items())},
            "e2e_s": dist(e2e, 1.0, 1),
            "e2e_s_by_status": {k: dist(v, 1.0, 1) for k, v in by_outcome.items()},
            "completions_per_minute": [per_minute[i] for i in range(max(per_minute) + 1)] if per_minute else [],
            "avg_summary_bytes": round(sum(int(r["summary_bytes"]) for r in rows) / max(len(rows), 1)),
            "llm_usage_today": [
                {
                    "model": u["model"],
                    "agent": u["agent"],
                    "calls": int(u["calls"]),
                    "input_tokens": int(u["it"]),
                    "output_tokens": int(u["ot"]),
                }
                for u in usage
            ],
            "llm_calls_per_alert": round(total_calls / max(len(settled_rows), 1), 2),
            "escalations_created": int(esc),
            "response_actions": {r["status"]: int(r["n"]) for r in actions},
            "alert_events": int(events),
            "checkpoints": dict(checkpoints) if checkpoints else None,
        }

    # -- process metrics --------------------------------------------------------

    async def scrape(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for p in self.stack.procs:
            url = p.metrics_url
            headers = {}
            if p.name == "api":
                url, headers = f"{self.base}/metrics", {"Authorization": f"Bearer {self.stack.metrics_token}"}
            if not url:
                continue
            try:
                r = await client.get(url, headers=headers)
                metrics = parse_prometheus(r.text)
            except httpx.HTTPError as exc:
                out[p.name] = {"error": type(exc).__name__}
                continue
            summary: Dict[str, Any] = {}
            nodes: Dict[str, Dict[str, float]] = defaultdict(dict)
            http: Dict[str, Dict[str, float]] = defaultdict(dict)
            for name, value in metrics.items():
                m = re.match(r'lgsotf_node_seconds_(sum|count)\{node="([^"]+)"\}', name)
                if m:
                    nodes[m.group(2)][m.group(1)] = value
                    continue
                m = re.match(r"lgsotf_http_request_seconds_(sum|count)\{(.*)\}", name)
                if m:
                    labels = dict(re.findall(r'(\w+)="([^"]*)"', m.group(2)))
                    http[f"{labels.get('method')} {labels.get('route')}"][m.group(1)] = value
                    continue
                if name.startswith(("lgsotf_runs_total", "lgsotf_llm_calls_total", "lgsotf_queue_")):
                    summary[name] = value
            if nodes:
                summary["node_avg_s"] = {
                    k: {
                        "count": int(v.get("count", 0)),
                        "avg_s": round(v.get("sum", 0) / v["count"], 3) if v.get("count") else None,
                    }
                    for k, v in sorted(nodes.items())
                }
            if http:
                summary["http_avg_ms"] = {
                    k: {
                        "count": int(v.get("count", 0)),
                        "avg_ms": round(1000 * v.get("sum", 0) / v["count"], 1) if v.get("count") else None,
                    }
                    for k, v in sorted(http.items())
                    if v.get("count")
                }
            out[p.name] = summary
        return out

    def process_report(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for p in self.stack.procs:
            if not p.samples:
                continue
            rss = [s[1] for s in p.samples]
            first_t, _, first_cpu = p.samples[0]
            last_t, _, last_cpu = p.samples[-1]
            # growth over the second half of the run (after warm-up)
            half = p.samples[len(p.samples) // 2 :]
            growth = None
            if len(half) >= 2 and half[-1][0] > half[0][0]:
                growth = round((half[-1][1] - half[0][1]) / ((half[-1][0] - half[0][0]) / 60.0), 3)
            out[p.name] = {
                "rss_mb_start": round(rss[0], 1),
                "rss_mb_max": round(max(rss), 1),
                "rss_mb_end": round(rss[-1], 1),
                "rss_growth_mb_per_min_second_half": growth,
                "cpu_s": round(last_cpu - first_cpu, 1),
                "cpu_util_pct": round(100 * (last_cpu - first_cpu) / max(last_t - first_t, 1e-9), 1),
            }
        return out

    def log_report(self) -> Dict[str, Any]:
        """Warnings and errors per process, by structured-log event name."""
        out: Dict[str, Any] = {}
        finished: Dict[str, List[float]] = {}
        for p in self.stack.procs:
            levels: Counter = Counter()
            events: Counter = Counter()
            run_seconds: List[float] = []
            try:
                lines = p.log_path.read_text(errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                try:
                    rec = json.loads(line)
                except ValueError:
                    if "Traceback" in line or "Error" in line:
                        events[f"raw: {line.strip()[:120]}"] += 1
                    continue
                level = str(rec.get("level", "")).lower()
                levels[level] += 1
                if level in ("warning", "error", "critical"):
                    key = f"{level}:{rec.get('event')}"
                    if rec.get("error") or rec.get("error_type"):
                        key += f" ({rec.get('error') or rec.get('error_type')})"
                    events[key] += 1
                if rec.get("event") == "worker.run_finished" and isinstance(rec.get("seconds"), (int, float)):
                    run_seconds.append(float(rec["seconds"]))
            out[p.name] = {
                "levels": dict(levels),
                "runs_finished": len(run_seconds),
                "warnings_errors": dict(events.most_common(25)),
            }
            if run_seconds:
                finished[p.name] = run_seconds
        return {"by_process": out, "run_seconds": {k: dist(v, 1.0, 2) for k, v in finished.items()}}


def summarize_timeline(timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not timeline:
        return {}
    # acked entries are XDEL'd, so the stream length is the backlog (queued + in flight)
    backlog = [
        (s["t"], sum(v.get("depth", 0) for v in s.get("queue", {}).values() if isinstance(v, dict)))
        for s in timeline
        if "queue" in s
    ]
    pg_by_app: Dict[str, int] = defaultdict(int)
    for s in timeline:
        for app, states in (s.get("pg") or {}).items():
            pg_by_app[app] = max(pg_by_app[app], sum(states.values()))
    return {
        "samples": len(timeline),
        "queue_backlog_max": max((b for _, b in backlog), default=0),
        "queue_backlog_max_at_s": max(backlog, key=lambda x: x[1])[0] if backlog else None,
        "dlq_max": max((s.get("queue", {}).get("dlq", 0) for s in timeline), default=0),
        "redis_mb_max": max((s.get("redis_mb", 0) for s in timeline), default=0),
        "redis_mb_start": timeline[0].get("redis_mb"),
        "redis_mb_end": timeline[-1].get("redis_mb"),
        "redis_clients_max": max((s.get("redis_clients", 0) for s in timeline), default=0),
        "pg_connections_max_this_db": max((s.get("pg_total", 0) for s in timeline), default=0),
        "pg_connections_max_server": max((s.get("pg_server_total", 0) for s in timeline), default=0),
        "pg_connections_max_by_app": dict(pg_by_app),
        "pg_longest_active_s": max((s.get("pg_longest_active_s", 0) for s in timeline), default=0),
        "host_cpu_pct_max": max((s.get("host_cpu_pct") or 0 for s in timeline), default=0),
        "host_cpu_pct_mean": round(sum(s.get("host_cpu_pct") or 0 for s in timeline) / len(timeline), 1),
        "postgres_cores_max": max((s.get("postgres_cores") or 0 for s in timeline), default=0),
        "redis_cores_max": max((s.get("redis_cores") or 0 for s in timeline), default=0),
        "loadgen_cores_max": max((s.get("loadgen_cores") or 0 for s in timeline), default=0),
        "loadgen_loop_lag_max_s": max((s.get("loadgen_loop_lag_max_s") or 0 for s in timeline), default=0),
    }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def parse_phases(spec: str) -> List[Tuple[str, float, float]]:
    out = []
    for part in spec.split(","):
        name, rate, seconds = part.split(":")
        out.append((name, float(rate), float(seconds)))
    return out


async def main_async(args: argparse.Namespace, workdir: Path) -> int:
    log(f"work directory {workdir}")
    name = db_name(args.database_url)
    if not args.force and not any(tag in name for tag in ("test", "load", "perf")):
        raise SystemExit(f"refusing to wipe database {name!r}; use a test database or --force")
    report: Dict[str, Any] = {
        "started_at": datetime.now(UTC).isoformat(),
        "config": {k: v for k, v in vars(args).items() if k not in ("database_url", "redis_url")},
        "host": {
            "cpus": os.cpu_count(),
            "mem_gb": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1),
        },
    }
    if args.reset:
        log("resetting database schema and Redis database")
        await reset_database(args.database_url)
        r = aioredis.from_url(args.redis_url)
        await r.flushdb()
        await r.aclose()
    stack = Stack(args, workdir)
    stack.migrate()
    if args.seed:
        log(f"seeding {args.seed} alerts")
        report["seed"] = await seed(args.database_url, "default", args.seed)
        log(f"seeded: {report['seed']}")
    report["query_plans_before"] = await explain_queries(args.database_url, "default")
    stack.start_all()
    test = LoadTest(args, stack)
    limits = httpx.Limits(max_connections=args.max_inflight + 64, max_keepalive_connections=args.max_inflight + 64)
    exit_code = 0
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(args.http_timeout), limits=limits) as client:
            await test.wait_ready(client)
            log("stack ready")
            await test.setup(client)
            test.t0 = time.monotonic()
            sampler = asyncio.create_task(test.sampler(client))
            lagmon = asyncio.create_task(test.loop_lag_monitor())
            readers = [asyncio.create_task(test.reader(client, i)) for i in range(args.readers)]
            ws = [asyncio.create_task(test.ws_client(i)) for i in range(args.ws_clients)]
            factory = AlertFactory(test.run_id, dict(parse_mix(args.mix)), args.hot_share)
            if args.mode == "drain":
                # queue the backlog as fast as the API takes it, then measure the drain
                await test.run_phase(client, factory, "backlog", args.backlog_rate, args.backlog / args.backlog_rate)
            else:
                for pname, rate, seconds in parse_phases(args.phases):
                    await test.run_phase(client, factory, pname, rate, seconds)
                    if args.pause:
                        await asyncio.sleep(args.pause)
            test.mark("ingest done")
            settle = await test.wait_settled(args.settle_timeout)
            test.mark("settled")
            log(f"settled {settle['settled']}/{settle['expected']} in {settle['seconds']} s after ingestion ended")
            await asyncio.sleep(min(10.0, args.sample_interval * 2))
            test.stop_readers.set()
            await asyncio.gather(*readers, *ws, return_exceptions=True)
            report["metrics"] = await test.scrape(client)
            test.stop_sampler.set()
            await sampler
            await lagmon
            report["loadgen_loop_lag_ms"] = dist(test.loop_lags, 1000.0)
            report["ingest_phases"] = [p.report() for p in test.phases]
            report["settle"] = settle
            report["readers"] = test.readers.report()
            report["timeline_summary"] = summarize_timeline(test.timeline)
            elapsed = max(test.timeline[-1]["t"] - test.timeline[0]["t"], 1e-9) if test.timeline else 1.0
            report["redis_commands"] = {
                k: {
                    "calls": v - test.redis_commands_start.get(k, 0),
                    "per_s": round((v - test.redis_commands_start.get(k, 0)) / elapsed, 1),
                }
                for k, v in sorted(
                    test.redis_commands_end.items(), key=lambda kv: -(kv[1] - test.redis_commands_start.get(kv[0], 0))
                )
                if v - test.redis_commands_start.get(k, 0) > 0
            }
            report["processes"] = test.process_report()
            report["marks"] = test.marks
            report["dead_processes"] = stack.check_alive()
            if settle["settled"] < settle["expected"] or report["dead_processes"]:
                exit_code = 1
    finally:
        stack.stop()
        if "settle" in report:
            # after the graceful stop, so the workers have flushed their LLM usage
            report["end_to_end"] = await test.end_to_end()
        report["logs"] = test.log_report()
        report["query_plans_after"] = await explain_queries(args.database_url, "default")
        report["timeline"] = test.timeline
        out = Path(args.out or workdir / "report.json")
        await asyncio.to_thread(out.write_text, json.dumps(report, indent=2, default=str))
        log(f"report written to {out}")
    print_summary(report)
    return exit_code


def parse_mix(text: str) -> List[Tuple[str, float]]:
    out = []
    for part in text.split(","):
        k, _, v = part.partition("=")
        out.append((k.strip(), float(v)))
    return out


def print_summary(report: Dict[str, Any]) -> None:
    print("\n==== summary ====")
    for p in report.get("ingest_phases", []):
        lat = p["latency_ms"]
        print(
            f"ingest {p['name']:>12}: {p['alerts_sent']:>6} alerts @ {p['achieved_alerts_per_s']:>6}/s  "
            f"p50 {lat.get('p50')} p95 {lat.get('p95')} p99 {lat.get('p99')} ms  codes {p['status_codes']} "
            f"err {p['error_rate']}"
        )
    e2e = report.get("end_to_end", {})
    if e2e:
        print(f"end-to-end: {e2e['settled']}/{e2e['alerts']} settled, e2e s {e2e['e2e_s']}")
        print(f"  by status {e2e['by_status']}  LLM calls/alert {e2e['llm_calls_per_alert']}")
    ts = report.get("timeline_summary", {})
    if ts:
        print(
            f"queue backlog max {ts['queue_backlog_max']} (t={ts['queue_backlog_max_at_s']}s), dlq max {ts['dlq_max']}, "
            f"redis max {ts['redis_mb_max']} MB, pg conns max {ts['pg_connections_max_this_db']} "
            f"(server {ts['pg_connections_max_server']}) {ts['pg_connections_max_by_app']}"
        )
        print(
            f"host cpu mean {ts['host_cpu_pct_mean']}% max {ts['host_cpu_pct_max']}%, postgres max {ts['postgres_cores_max']} cores, "
            f"redis max {ts['redis_cores_max']} cores, load generator max {ts['loadgen_cores_max']} cores, "
            f"load generator loop lag max {ts['loadgen_loop_lag_max_s']} s"
        )
    rc = report.get("redis_commands", {})
    if rc:
        print("  redis commands: " + ", ".join(f"{k} {v['calls']}" for k, v in list(rc.items())[:12]))
    for name, lg in report.get("logs", {}).get("by_process", {}).items():
        print(f"  {name:>10}: runs finished {lg.get('runs_finished')}  warnings/errors {lg['warnings_errors']}")
    for name, pr in report.get("processes", {}).items():
        print(
            f"  {name:>10}: rss {pr['rss_mb_start']} -> {pr['rss_mb_end']} MB (max {pr['rss_mb_max']}), cpu {pr['cpu_util_pct']}%, growth {pr['rss_growth_mb_per_min_second_half']} MB/min"
        )
    rd = report.get("readers", {})
    for name, r in rd.get("http", {}).items():
        print(f"  reader {name:>22}: {r['latency_ms']} {r['codes']}")
    if rd:
        print(f"  websocket: {rd['websocket']}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--database-url", default=os.environ.get("LG_SOTF_TEST_DATABASE_URL"))
    p.add_argument("--redis-url", default=os.environ.get("LG_SOTF_TEST_REDIS_URL"))
    p.add_argument("--reset", action="store_true", help="drop the public schema and flush the Redis database first")
    p.add_argument("--force", action="store_true", help="allow a database name without test/load/perf")
    p.add_argument("--seed", type=int, default=100_000, help="alerts of history to seed (0: none)")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument(
        "--worker-concurrency", type=int, default=None, help="worker.concurrency (default: the setting's default)"
    )
    p.add_argument("--per-tenant-concurrency", type=int, default=None, help="worker.per_tenant_concurrency")
    p.add_argument("--llm-latency", default="1.0:3.0", help="fast tier latency per call, lo:hi seconds")
    p.add_argument("--deep-latency", default=None, help="deep tier latency per call (default: --llm-latency)")
    p.add_argument("--mode", choices=("phases", "drain"), default="phases")
    p.add_argument(
        "--phases",
        default="burst10:10:30,burst50:50:30,burst200:200:15,sustained30:30:300",
        help="name:alerts_per_s:seconds,...",
    )
    p.add_argument("--pause", type=float, default=0.0, help="seconds between phases")
    p.add_argument("--backlog", type=int, default=600, help="drain mode: alerts queued up front")
    p.add_argument("--backlog-rate", type=float, default=100.0, help="drain mode: ingest rate of the backlog")
    p.add_argument("--batch", type=int, default=1, help="alerts per ingest request")
    p.add_argument("--tenants", type=int, default=1, help="tenants to spread ingestion over")
    p.add_argument("--mix", default="benign=0.55,suspicious=0.30,malicious=0.15")
    p.add_argument("--hot-share", type=float, default=0.2, help="share of alerts carrying one common IP indicator")
    p.add_argument("--readers", type=int, default=4, help="concurrent dashboard/list readers (one viewer account each)")
    p.add_argument("--reader-interval", type=float, default=1.0)
    p.add_argument("--ws-clients", type=int, default=20)
    p.add_argument("--max-inflight", type=int, default=512, help="cap on concurrent ingest requests")
    p.add_argument("--http-timeout", type=float, default=30.0)
    p.add_argument("--settle-timeout", type=float, default=1800.0)
    p.add_argument("--sample-interval", type=float, default=2.0)
    p.add_argument("--api-port", type=int, default=18080)
    p.add_argument("--metrics-base-port", type=int, default=19200)
    p.add_argument("--env", action="append", help="extra KEY=VALUE for every process (repeatable)")
    p.add_argument("--workdir", default=None)
    p.add_argument("--out", default=None, help="JSON report path (default: <workdir>/report.json)")
    args = p.parse_args()
    if not args.database_url or not args.redis_url:
        p.error("--database-url and --redis-url (or LG_SOTF_TEST_DATABASE_URL / LG_SOTF_TEST_REDIS_URL) are required")
    for spec in (args.llm_latency, args.deep_latency):
        if spec:
            parse_range(spec)
    if args.workdir:
        workdir = Path(args.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="lgsotf-loadtest-"))
    return asyncio.run(main_async(args, workdir))


if __name__ == "__main__":
    sys.exit(main())
