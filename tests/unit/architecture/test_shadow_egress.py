"""Shadow mode (AI-E1.5a): every egress path is found in the source, and every one is diverted in shadow mode.

The egress call sites are discovered with the AST, not listed by hand, in
every module of ``src/lg_sotf`` but ``api/`` and ``mcp/`` (the import
contracts ``api-no-workflow`` and ``mcp-thin-client`` keep both out of any
process that runs the workflow, so no shadow run can reach them):

* network and database clients: ``httpx.AsyncClient``/``Client`` and their
  transports, ``smtplib.SMTP``/``SMTP_SSL``, sockets and ``asyncio``/loop
  connections, ``websockets``/``aiohttp``/``requests``/``urllib`` clients,
  new database pools or connections (asyncpg, psycopg) and new Redis
  clients. Slack, webhooks, tickets, Microsoft Graph and Defender all go
  through ``net.http.guarded_client``;
* every Redis write command (``set``, ``delete``, ``incrby``, ``xadd``,
  ``xack``, ``xreadgroup``, ``publish``...) on a Redis client or pipeline, in
  any module that mentions Redis;
* WebSocket sends (``send_json``/``send_text``/``send_bytes``);
* response execution: ``.execute(`` on a connector or the action executor;
* the outbox: any function using SQL that inserts into ``notification_outbox``.

Calls to the LLM provider are made inside the provider SDKs and are not
scanned: the candidate's model is what a shadow run is for.

A second rule keeps the shadow flag from being lost: ``run_in_executor``,
``.submit(``, ``threading.Thread(``, ``contextvars.Context()`` and
``create_task(..., context=...)`` drop the caller's context, so code reached
through them would run live. Each must carry the context over
(``contextvars.copy_context()``).

Each site must be inside a function registered with
:func:`lg_sotf.security.shadow.egress`, whose policy diverts it in shadow
mode (refuse, or record in the sink and return a stand-in). A new egress
path that is not registered fails here. Database writes need no site list:
in shadow mode every transaction is read only (``tests/integration/engine/test_shadow.py``).
"""

from __future__ import annotations

import ast
import importlib
import re
import tomllib
from typing import Dict, List

import grimp
import pytest

from lg_sotf.security.shadow import EGRESS_POINTS, EgressPoint
from tests.unit.architecture._support import MODULE_LEVEL, REPO_ROOT, in_dir, source_files, walk_scoped

pytestmark = pytest.mark.unit

EXEMPT = ("api", "mcp")
LIBRARY_CALLS = frozenset({
    "httpx.AsyncClient", "httpx.Client", "httpx.AsyncHTTPTransport", "httpx.HTTPTransport",
    "smtplib.SMTP", "smtplib.SMTP_SSL", "socket.socket", "socket.create_connection", "asyncio.open_connection",
    "websockets.connect", "aiohttp.ClientSession", "requests.request", "requests.get", "requests.post",
    "urllib.request.urlopen", "asyncio.open_unix_connection",
    "asyncpg.connect", "asyncpg.create_pool", "psycopg.connect", "psycopg.AsyncConnection.connect",
    "psycopg_pool.AsyncConnectionPool", "psycopg_pool.ConnectionPool",
    "redis.Redis", "redis.asyncio.Redis", "redis.from_url", "redis.asyncio.from_url", "redis.Redis.from_url",
    "redis.asyncio.Redis.from_url", "lg_sotf.queue.redis.ShadowSafeRedis.from_url", "ShadowSafeRedis.from_url",
})
LOOP_CONNECTIONS = frozenset({"create_connection", "create_unix_connection", "create_datagram_endpoint"})
REDIS_WRITES = frozenset({
    "set", "setex", "setnx", "psetex", "getset", "getdel", "getex", "mset", "msetnx", "setrange", "append",
    "delete", "unlink", "rename", "renamenx", "persist", "expire", "pexpire", "expireat", "pexpireat",
    "incr", "incrby", "incrbyfloat", "decr", "decrby", "hset", "hsetnx", "hmset", "hdel", "hincrby",
    "hincrbyfloat", "lpush", "rpush", "lpop", "rpop", "lrem", "ltrim", "lset", "linsert", "sadd", "srem", "spop",
    "zadd", "zrem", "zincrby", "zremrangebyscore", "zremrangebyrank", "pfadd", "publish", "spublish",
    "xadd", "xack", "xdel", "xtrim", "xclaim", "xautoclaim", "xreadgroup", "xgroup_create", "xgroup_destroy",
    "xgroup_delconsumer", "xgroup_createconsumer", "xgroup_setid", "eval", "evalsha", "fcall",
    "execute_command", "register_script", "flushdb", "flushall", "copy", "restore", "move",
})
WS_SENDS = frozenset({"send_json", "send_text", "send_bytes"})
OUTBOX_INSERT = re.compile(r"INSERT\s+INTO\s+notification_outbox", re.IGNORECASE)
REDIS_RECEIVER = re.compile(r"redis|pipe")
EXECUTOR_RECEIVER = re.compile(r"connector|executor")

# Egress that runs in shadow mode too. Adding one is a security review: it must change nothing outside.
REVIEWED_ALLOWED = {
    "lg_sotf.runtime.health:HealthServer._bind",
}


def _aliases(tree: ast.Module) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                out[name.asname or name.name.split(".")[0]] = name.name if name.asname else name.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for name in node.names:
                out[name.asname or name.name] = f"{node.module}.{name.name}"
    return out


def _dotted(node: ast.expr) -> str:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _outbox_constants(tree: ast.Module) -> set[str]:
    return {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        and OUTBOX_INSERT.search(node.value.value)
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def _resolved(call: ast.Call, aliases: Dict[str, str]) -> str:
    head, _, rest = _dotted(call.func).partition(".")
    return (aliases.get(head, head) + ("." + rest if rest else "")) if head else ""


def _call_kind(call: ast.Call, aliases: Dict[str, str], mentions_redis: bool) -> str:
    if _resolved(call, aliases) in LIBRARY_CALLS:
        return "network client"
    if not isinstance(call.func, ast.Attribute):
        return ""
    receiver, method = ast.unparse(call.func.value), call.func.attr
    if method in LOOP_CONNECTIONS:
        return "network client"
    if mentions_redis and method in REDIS_WRITES and REDIS_RECEIVER.search(receiver.lower()):
        return f"redis {method}"
    if method in WS_SENDS:
        return "websocket send"
    if method == "execute" and EXECUTOR_RECEIVER.search(receiver):
        return "response execution"
    return ""


def egress_sites(tree: ast.Module) -> Dict[str, str]:
    """``{qualname: kind}`` of the functions in ``tree`` that contain an egress call site."""
    aliases, outbox = _aliases(tree), _outbox_constants(tree)
    mentions_redis = "redis" in ast.unparse(tree).lower()
    sites: Dict[str, str] = {}
    for node, qual in walk_scoped(tree):
        kind = ""
        if isinstance(node, ast.Call):
            kind = _call_kind(node, aliases, mentions_redis)
        elif qual != MODULE_LEVEL and (
            (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in outbox)
            or (isinstance(node, ast.Constant) and isinstance(node.value, str) and OUTBOX_INSERT.search(node.value))
        ):
            kind = "outbox insert"
        if kind:
            sites.setdefault(qual, kind)
    return sites


def module_name(rel: str) -> str:
    parts = rel.removesuffix(".py").split("/")
    return ".".join(["lg_sotf", *(parts[:-1] if parts[-1] == "__init__" else parts)])


def discovered() -> Dict[str, str]:
    """``{module:qualname: kind}`` of every egress site outside the exempt packages."""
    found: Dict[str, str] = {}
    for src in source_files():
        if in_dir(src.rel, *EXEMPT):
            continue
        for qual, kind in egress_sites(src.tree).items():
            found[f"{module_name(src.rel)}:{qual}"] = kind
    return found


def _decorates_egress(tree: ast.Module) -> bool:
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(d, ast.Call) and _dotted(d.func).endswith("egress") for d in node.decorator_list)
        for node in ast.walk(tree)
    )


def nested_boundaries() -> set[str]:
    """``@egress`` functions defined inside another function: they register only when the outer one runs."""
    return {
        f"{module_name(src.rel)}:{qual}"
        for src in source_files()
        for node, qual in walk_scoped(src.tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and "." in qual
        and any(isinstance(d, ast.Call) and _dotted(d.func).endswith("egress") for d in node.decorator_list)
        and not any(isinstance(n, ast.ClassDef) and qual.startswith(n.name + ".") for n in src.tree.body)
    }


@pytest.fixture(scope="module")
def registry() -> Dict[str, EgressPoint]:
    """Every registered boundary: the modules with an egress site or an ``@egress`` decorator are imported."""
    for src in source_files():
        if egress_sites(src.tree) or _decorates_egress(src.tree):
            importlib.import_module(module_name(src.rel))
    # A boundary nested in a function registers only once that function runs (an earlier test may have run it):
    # those are checked statically, by nested_boundaries().
    return {
        key: point for key, point in EGRESS_POINTS.items() if key.startswith("lg_sotf.") and ".<locals>." not in key
    }


def test_the_scan_finds_every_kind_of_egress() -> None:
    sample = ast.parse(
        "import httpx, smtplib\n"
        "from redis.asyncio import Redis\n"
        "_SQL = 'INSERT INTO notification_outbox (a) VALUES ($1)'\n"
        "def http(): return httpx.AsyncClient()\n"
        "def mail(): smtplib.SMTP_SSL('h')\n"
        "class Bus:\n"
        "    async def ws(self): await self._redis.publish('c', 'm')\n"
        "    async def work(self, pipe): pipe.xadd('s', {})\n"
        "async def push(socket): await socket.send_json({})\n"
        "async def act(connector, a): await connector.execute(a)\n"
        "async def notify(conn): await conn.execute(_SQL, 1)\n"
        "async def not_egress(conn, event): await conn.execute('SELECT 1'); event.set()\n"
        "import asyncpg, redis\n"
        "async def pool(): await asyncpg.create_pool('dsn')\n"
        "def cache(): return redis.from_url('redis://x')\n"
        "async def raw(loop): await loop.create_connection(object, 'h', 1)\n"
        "async def budget(self): await self.redis.incrby('k', 1)\n"
        "async def heartbeat(self): await self._redis.set('alive', 1)\n"
        "class Consumer:\n"
        "    async def read(self): await self._redis.xreadgroup('g', 'c', {})\n"
        "    async def ack(self, pipe): pipe.xack('s', 'g', '1')\n"
        "def not_redis(): import os; os.unlink('f')\n"
    )
    assert egress_sites(sample) == {
        "http": "network client", "mail": "network client", "Bus.ws": "redis publish", "Bus.work": "redis xadd",
        "push": "websocket send", "act": "response execution", "notify": "outbox insert",
        "pool": "network client", "cache": "network client", "raw": "network client", "budget": "redis incrby",
        "heartbeat": "redis set", "Consumer.read": "redis xreadgroup", "Consumer.ack": "redis xack",
    }


def context_hops(tree: ast.Module) -> List[str]:
    """Calls that run code without the caller's context (and so without its run mode), unless they copy it."""
    aliases, found = _aliases(tree), []
    for node, qual in walk_scoped(tree):
        if not isinstance(node, ast.Call) or "copy_context" in ast.unparse(node):
            continue
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        hop = (
            method in ("run_in_executor", "submit")
            or _resolved(node, aliases) in ("threading.Thread", "contextvars.Context")
            or (method == "create_task" and any(k.arg == "context" for k in node.keywords))
        )
        if hop:
            found.append(qual)
    return list(dict.fromkeys(found))


def test_the_hop_scan_finds_every_context_drop() -> None:
    sample = ast.parse(
        "import asyncio, contextvars, threading\n"
        "async def a(loop, fn): await loop.run_in_executor(None, fn)\n"
        "def b(pool, fn): pool.submit(fn)\n"
        "def c(fn): threading.Thread(target=fn).start()\n"
        "def d(fn): contextvars.Context().run(fn)\n"
        "def e(loop, coro): loop.create_task(coro, context=contextvars.Context())\n"
        "async def kept(loop, fn): await loop.run_in_executor(None, contextvars.copy_context().run, fn)\n"
    )
    assert context_hops(sample) == ["a", "b", "c", "d", "e"]


def test_no_code_drops_the_run_mode_on_a_thread_or_fresh_context() -> None:
    """A shadow run's flag is a context variable: a hop that does not copy the context would run code live."""
    dropped = sorted(
        f"{module_name(src.rel)}:{qual}"
        for src in source_files()
        if not in_dir(src.rel, *EXEMPT)
        for qual in context_hops(src.tree)
    )
    assert dropped == [], "carry the caller's context (contextvars.copy_context().run): " + ", ".join(dropped)


def test_shadow_no_side_effects_every_egress_site_is_a_registered_boundary(registry: Dict[str, EgressPoint]) -> None:
    """The enumerated egress list is complete: a new egress path fails until it is a shadow-mode boundary."""
    sites = discovered()
    assert len(sites) >= 15, "the scan found too little; is it still looking at src/lg_sotf?"
    covered = set(registry) | nested_boundaries()
    missing = sorted(f"{site} ({kind})" for site, kind in sites.items() if site not in covered)
    assert not missing, (
        "egress outside a shadow-mode boundary; decorate the function with "
        "lg_sotf.security.shadow.egress (REFUSE, or sink with a stand-in):\n" + "\n".join(missing)
    )


def test_shadow_no_side_effects_every_boundary_diverts_in_shadow_mode(registry: Dict[str, EgressPoint]) -> None:
    """Every registered boundary refuses or sinks in shadow mode, except the reviewed read-only lookups."""
    actions = {key: point.policy.action for key, point in registry.items()}
    assert set(actions.values()) <= {"refuse", "sink", "allow"}
    assert {key for key, action in actions.items() if action == "allow"} == REVIEWED_ALLOWED
    for key in registry:
        module, _, qual = key.partition(":")
        target: object = importlib.import_module(module)
        for part in qual.split("."):
            target = getattr(target, part)
        assert hasattr(target, "__wrapped__"), f"{key} is registered but not wrapped by its boundary"


def test_the_exempt_packages_cannot_run_a_shadow_run() -> None:
    """``api/`` and ``mcp/`` are left out of the scan because the import contracts keep the workflow out of them."""
    contracts = {
        c["id"]: c for c in tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["tool"]["importlinter"]["contracts"]
    }
    assert "lg_sotf.core.nodes" in contracts["api-no-workflow"]["forbidden_modules"]
    assert contracts["api-no-workflow"].get("allow_indirect_imports") is not True
    assert "lg_sotf.core" in contracts["mcp-thin-client"]["forbidden_modules"]
    graph = grimp.build_graph("lg_sotf")
    assert "lg_sotf.core.nodes" in graph.find_upstream_modules("lg_sotf.core.shadow")
