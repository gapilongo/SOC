"""Shadow mode (AI-E1.5a): every egress path is found in the source, and every one is diverted in shadow mode.

The egress call sites are discovered with the AST, not listed by hand, in
every module of ``src/lg_sotf`` but ``api/`` and ``mcp/`` (the import
contracts ``api-no-workflow`` and ``mcp-thin-client`` keep both out of any
process that runs the workflow, so no shadow run can reach them):

* network clients: ``httpx.AsyncClient``/``Client`` and their transports,
  ``smtplib.SMTP``/``SMTP_SSL``, sockets, ``asyncio.open_connection``,
  ``websockets``/``aiohttp``/``requests``/``urllib`` clients. Slack,
  webhooks, tickets, Microsoft Graph and Defender all go through
  ``net.http.guarded_client``;
* Redis ``publish`` (the WebSocket fan-out) and ``xadd`` (queued work) on a
  Redis client or pipeline;
* WebSocket sends (``send_json``/``send_text``/``send_bytes``);
* response execution: ``.execute(`` on a connector or the action executor;
* the outbox: any function using SQL that inserts into ``notification_outbox``.

Calls to the LLM provider are made inside the provider SDKs and are not
scanned: the candidate's model is what a shadow run is for.

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
    "urllib.request.urlopen",
})
REDIS_SENDS = frozenset({"publish", "xadd"})
WS_SENDS = frozenset({"send_json", "send_text", "send_bytes"})
OUTBOX_INSERT = re.compile(r"INSERT\s+INTO\s+notification_outbox", re.IGNORECASE)
REDIS_RECEIVER = re.compile(r"redis|pipe")
EXECUTOR_RECEIVER = re.compile(r"connector|executor")

# Egress that runs in shadow mode too. Adding one is a security review: it must change nothing outside.
REVIEWED_ALLOWED = {
    "lg_sotf.tools.enrichment.http:JsonHttpClient._get_client",
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


def _call_kind(call: ast.Call, aliases: Dict[str, str]) -> str:
    head, _, rest = _dotted(call.func).partition(".")
    if head and (aliases.get(head, head) + ("." + rest if rest else "")) in LIBRARY_CALLS:
        return "network client"
    if not isinstance(call.func, ast.Attribute):
        return ""
    receiver, method = ast.unparse(call.func.value), call.func.attr
    if method in REDIS_SENDS and REDIS_RECEIVER.search(receiver):
        return f"redis {method}"
    if method in WS_SENDS:
        return "websocket send"
    if method == "execute" and EXECUTOR_RECEIVER.search(receiver):
        return "response execution"
    return ""


def egress_sites(tree: ast.Module) -> Dict[str, str]:
    """``{qualname: kind}`` of the functions in ``tree`` that contain an egress call site."""
    aliases, outbox = _aliases(tree), _outbox_constants(tree)
    sites: Dict[str, str] = {}
    for node, qual in walk_scoped(tree):
        kind = ""
        if isinstance(node, ast.Call):
            kind = _call_kind(node, aliases)
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


@pytest.fixture(scope="module")
def registry() -> Dict[str, EgressPoint]:
    """Every registered boundary: the modules with an egress site or an ``@egress`` decorator are imported."""
    for src in source_files():
        if egress_sites(src.tree) or _decorates_egress(src.tree):
            importlib.import_module(module_name(src.rel))
    return {key.replace(".<locals>", ""): point for key, point in EGRESS_POINTS.items() if key.startswith("lg_sotf.")}


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
    )
    assert egress_sites(sample) == {
        "http": "network client", "mail": "network client", "Bus.ws": "redis publish", "Bus.work": "redis xadd",
        "push": "websocket send", "act": "response execution", "notify": "outbox insert",
    }


def test_shadow_no_side_effects_every_egress_site_is_a_registered_boundary(registry: Dict[str, EgressPoint]) -> None:
    """The enumerated egress list is complete: a new egress path fails until it is a shadow-mode boundary."""
    sites = discovered()
    assert len(sites) >= 15, "the scan found too little; is it still looking at src/lg_sotf?"
    missing = sorted(f"{site} ({kind})" for site, kind in sites.items() if site not in registry)
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
