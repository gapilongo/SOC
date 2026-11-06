"""A fake Microsoft (identity platform, Graph, Defender) for the Microsoft framework and capability tests.

No test ever reaches a real Microsoft endpoint: :class:`FakeMicrosoft` is an
``httpx.MockTransport`` handler bound to the fixed hosts of one cloud, and
its :meth:`FakeMicrosoft.resolver` maps those hosts (and nothing else) to a
public test address so the destination policy accepts them.

Credential material is never a literal (GitGuardian scans every commit):
client secrets, GUIDs, certificates and tokens are built at runtime. Tokens
the fake issues are unsigned JWTs carrying the ``roles`` granted with
:meth:`FakeMicrosoft.grant`.

Typical capability unit test::

    fake = FakeMicrosoft()
    fake.grant("graph", ["User.EnableDisableAccount.All"])
    fake.route("GET", "graph", "/v1.0/users/alice@contoso.example", httpx.Response(200, json={...}))
    fake.route("PATCH", "graph", "/v1.0/users/<id>", httpx.Response(204))
    ctx, store = make_context(fake, SPEC, action=make_action("disable_user", "alice@contoso.example"))
    result = await SPEC.handler(ctx).execute(make_action(...))
    assert [r.method for r in fake.writes()] == ["PATCH"]
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Pattern, Sequence, Tuple, Union
from urllib.parse import parse_qs

import httpx

from lg_sotf.db.repos.actions import ResponseAction, action_idempotency_key
from lg_sotf.domain.actions import ACTION_CATALOG
from lg_sotf.integrations.microsoft.alert_view import AlertView
from lg_sotf.integrations.microsoft.auth import AppCredentials, TokenProvider, fingerprint_of
from lg_sotf.integrations.microsoft.capability import (
    CapabilityOptions,
    CapabilitySpec,
    CheckpointLost,
    HandlerContext,
    ProtectedLookup,
    action_marker,
    nothing_protected,
)
from lg_sotf.integrations.microsoft.clouds import Api, CloudProfile, cloud_profile
from lg_sotf.integrations.microsoft.http import MicrosoftApi, MicrosoftHttpFactory
from lg_sotf.settings import Settings

PUBLIC_IP = "93.184.216.34"  # a public address the destination policy accepts (not a Microsoft one)
HostName = Literal["login", "graph", "defender"]
Reply = Union[httpx.Response, Callable[[httpx.Request], httpx.Response]]
TENANT = "tenant-a"


def fake_secret(label: str = "client") -> str:
    """A client secret built at runtime (never a credential-shaped literal)."""
    return "-".join(("fake", label, "secret", uuid.uuid4().hex))


def ms_settings(**overrides: Any) -> Settings:
    """Explicit test settings (no .env), Microsoft retries without real sleeps, a runtime encryption key."""
    key = base64.urlsafe_b64encode(("lg-sotf-microsoft-fixture-" + "k" * 6).encode()).decode()
    base: Dict[str, Any] = {
        "environment": "test",
        "llm": {"provider": "fake", "allow_fake": True},
        "security": {"encryption_keys": key, "indicator_hmac_key": "fixture-" + "h" * 32},
        "response": {"microsoft_retries": 2, "microsoft_timeout_s": 5.0},
    }
    for name, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(name), dict):
            base[name] = {**base[name], **value}
        else:
            base[name] = value
    return Settings(_env_file=None, **base)


def _b64(data: Mapping[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()


def unsigned_token(claims: Mapping[str, Any]) -> str:
    """An unsigned JWT (``alg: none``) built at runtime; the connector never validates tokens."""
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}."


def make_certificate(*, days: int = 30, bits: int = 2048, common_name: str = "lg-sotf-test") -> Tuple[str, str]:
    """A self-signed RSA certificate and its unencrypted PKCS#8 key, generated now: ``(cert_pem, key_pem)``."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1) if days > 0 else now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return cert_pem, key_pem


def fake_config(**overrides: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """A valid Microsoft integration ``(config, secret)``: fresh GUIDs, a runtime client secret or certificate.

    ``credential="certificate"`` generates a certificate and key. Other
    keyword arguments override config keys (``capabilities={...}``,
    ``cloud=...``, ``defender_geo=...``).
    """
    credential = overrides.pop("credential", "client_secret")
    config: Dict[str, Any] = {
        "cloud": "global",
        "directory_tenant_id": str(uuid.uuid4()),
        "client_id": str(uuid.uuid4()),
        "credential": credential,
        "capabilities": {},
    }
    secret: Dict[str, Any]
    if credential == "certificate":
        cert_pem, key_pem = make_certificate()
        config["certificate_pem"] = cert_pem
        secret = {"private_key_pem": key_pem}
    else:
        secret = {"client_secret": fake_secret()}
    config.update(overrides)
    return config, secret


@dataclass
class _Route:
    method: str
    host: str
    path: Union[str, Pattern[str]]
    reply: Reply
    times: Optional[int]
    calls: int = 0

    def matches(self, request: httpx.Request) -> bool:
        if request.method != self.method or request.url.host != self.host:
            return False
        if self.times is not None and self.calls >= self.times:
            return False
        raw = request.url.raw_path.split(b"?", 1)[0].decode("ascii")
        if isinstance(self.path, str):
            return self.path in (raw, request.url.path)
        return bool(self.path.fullmatch(request.url.path) or self.path.fullmatch(raw))


class FakeMicrosoft:
    """Scripted Microsoft endpoints for one cloud (see the module docstring).

    ``requests`` records every request (token requests included);
    ``unmatched`` the ones no route answered (they get a 501).
    """

    def __init__(self, *, cloud: str = "global", geo: Optional[str] = None) -> None:
        self.cloud = cloud
        self.geo = geo
        self.profile: CloudProfile = cloud_profile(cloud)
        self.requests: List[httpx.Request] = []
        self.unmatched: List[httpx.Request] = []
        self.token_lifetime_s = 3599
        self._routes: List[_Route] = []
        self._roles: Dict[str, List[str]] = {"graph": [], "defender": []}
        self.tokens_issued = 0

    # -- scripting -------------------------------------------------------------

    def host(self, name: HostName) -> str:
        if name == "login":
            return self.profile.login_host
        if name == "graph":
            return self.profile.graph_host
        return self.profile.defender_host(self.geo)

    def route(
        self,
        method: str,
        host: HostName,
        path: Union[str, Pattern[str]],
        reply: Reply,
        *,
        times: Optional[int] = None,
    ) -> None:
        """Answer ``method host path`` with ``reply`` (a response or a function of the request).

        Earlier routes win; ``times`` limits how often a route answers (then
        the next matching route does). ``path`` is compared with the raw
        (encoded) and the decoded path; a compiled pattern must match fully.
        """
        self._routes.append(_Route(method.upper(), self.host(host), path, reply, times))

    def grant(self, api: str, roles: Sequence[str]) -> None:
        """The ``roles`` claim of tokens issued for ``api`` from now on."""
        self._roles[api] = list(roles)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def resolver(self) -> Callable[[str, int], Any]:
        """Maps this cloud's fixed hosts to a public test address; any other host fails to resolve."""
        known = {self.profile.login_host, self.profile.graph_host}
        if self.profile.defender_supported:
            known.add(self.profile.defender_host(self.geo))

        async def resolve(host: str, port: int) -> List[str]:
            if host not in known:
                raise httpx.ConnectError(f"fake resolver: unknown host {host}")
            return [PUBLIC_IP]

        return resolve

    # -- inspection ------------------------------------------------------------

    def is_token_request(self, request: httpx.Request) -> bool:
        return request.url.host == self.profile.login_host

    def writes(self) -> List[httpx.Request]:
        """Every request that is not a GET or a token request (what must stay empty in rehearsals)."""
        return [r for r in self.requests if r.method != "GET" and not self.is_token_request(r)]

    def token_forms(self) -> List[Dict[str, str]]:
        """The form fields of every token request (for credential assertions)."""
        out: List[Dict[str, str]] = []
        for request in self.requests:
            if self.is_token_request(request):
                parsed = parse_qs(request.content.decode("ascii"))
                out.append({k: v[0] for k, v in parsed.items()})
        return out

    def api_requests(self) -> List[httpx.Request]:
        return [r for r in self.requests if not self.is_token_request(r)]

    # -- handler ---------------------------------------------------------------

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for route in self._routes:
            if route.matches(request):
                route.calls += 1
                reply = route.reply
                return reply(request) if callable(reply) else reply
        if self.is_token_request(request) and request.method == "POST":
            return self._issue_token(request)
        self.unmatched.append(request)
        return httpx.Response(
            501, json={"error": {"code": "FakeMicrosoft_NoRoute", "message": f"no route for {request.method}"}}
        )

    def _issue_token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode("ascii")).items()}
        scope = form.get("scope", "")
        api = "defender" if scope == self.profile.defender_scope else "graph"
        if form.get("grant_type") != "client_credentials" or not (
            form.get("client_secret") or form.get("client_assertion")
        ):
            return httpx.Response(400, json={"error": "invalid_request", "error_codes": [900144]})
        self.tokens_issued += 1
        now = int(time.time())
        claims = {
            "aud": scope.rsplit("/.default", 1)[0],
            "appid": form.get("client_id"),
            "roles": list(self._roles.get(api, [])),
            "iat": now,
            "exp": now + self.token_lifetime_s,
            "jti": uuid.uuid4().hex,
        }
        return httpx.Response(
            200, json={"token_type": "Bearer", "expires_in": self.token_lifetime_s, "access_token": unsigned_token(claims)}
        )


# ----------------------------------------------------------------------------- ledger and context helpers


def make_action(action_type: str, target: str, **fields: Any) -> ResponseAction:
    """A ledger row as handlers receive it (status ``executing`` unless overridden)."""
    spec = ACTION_CATALOG.get(action_type)
    now = datetime.now(UTC)
    tenant_id = fields.pop("tenant_id", TENANT)
    alert_id = fields.pop("alert_id", "alert-1")
    row: Dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "alert_id": alert_id,
        "action_type": action_type,
        "target": target,
        "params": {},
        "risk_level": spec.risk if spec is not None else "medium",
        "idempotency_key": action_idempotency_key(tenant_id, alert_id, action_type, target),
        "status": "executing",
        "blocked_reason": None,
        "requested_by": "agent:workflow",
        "approved_by": "policy:auto",
        "approved_at": now,
        "executed_at": now,
        "connector": "microsoft",
        "result": None,
        "rollback_of": None,
        "created_at": now,
        "updated_at": now,
        "attempts": 1,
    }
    row.update(fields)
    return ResponseAction.model_validate(row)


def default_alert(**fields: Any) -> AlertView:
    values: Dict[str, Any] = {
        "alert_id": "alert-1",
        "title": "Reported phishing",
        "severity": "high",
        "disposition": "malicious",
        "email": MappingProxyType({}),
        "received_at": datetime.now(UTC),
    }
    values.update(fields)
    return AlertView(**values)


@dataclass
class ContextParts:
    """What :func:`make_context` built, for tests that need the pieces."""

    creds: AppCredentials
    http: MicrosoftHttpFactory
    tokens: TokenProvider
    settings: Settings


async def _no_sleep(_: float) -> None:
    return None


def make_credentials(
    fake: FakeMicrosoft,
    *,
    config: Optional[Mapping[str, Any]] = None,
    secret: Optional[Mapping[str, Any]] = None,
    tenant_id: str = TENANT,
    integration_id: Optional[uuid.UUID] = None,
) -> AppCredentials:
    cfg, sec = (dict(config), dict(secret or {})) if config is not None else fake_config(cloud=fake.cloud)
    return AppCredentials(
        lg_tenant_id=tenant_id,
        integration_id=integration_id or uuid.uuid4(),
        cloud=cloud_profile(cfg.get("cloud", fake.cloud)),
        directory_tenant_id=cfg["directory_tenant_id"],
        client_id=cfg["client_id"],
        fingerprint=fingerprint_of(json.dumps(sec, sort_keys=True)),
        client_secret=sec.get("client_secret"),
        private_key_pem=sec.get("private_key_pem"),
        certificate_pem=cfg.get("certificate_pem"),
        defender_geo=fake.geo,
    )


def make_context(
    fake: FakeMicrosoft,
    spec: CapabilitySpec,
    *,
    options: Mapping[str, Any] = MappingProxyType({}),
    action: Optional[ResponseAction] = None,
    original: Optional[ResponseAction] = None,
    alert: Optional[AlertView] = None,
    deadline_s: float = 30.0,
    read_only: bool = False,
    settings: Optional[Settings] = None,
    parts: Optional[List[ContextParts]] = None,
    protected: ProtectedLookup = nothing_protected,
) -> Tuple[HandlerContext, Dict[str, Any]]:
    """A handler context wired to ``fake``: ``(ctx, checkpoint store)``.

    ``options`` are validated with ``spec.options``. The checkpoint store is
    a dict that ``ctx.checkpoint`` merges into (seeded with
    ``action.external_ref``); set ``store["_lost"] = True`` to make the next
    checkpoint raise :class:`CheckpointLost`. ``read_only`` gives the
    rehearsal/verify/probe client (writes refused). ``protected`` is the
    tenant's protected-asset lookup (nothing protected by default). Must be called inside a
    running event loop (the deadline is ``loop.time()`` based).
    """
    settings = settings or ms_settings()
    http = MicrosoftHttpFactory(settings, transport=fake.transport(), resolver=fake.resolver(), sleep=_no_sleep)
    tokens = TokenProvider(http)
    creds = make_credentials(fake)
    if parts is not None:
        parts.append(ContextParts(creds=creds, http=http, tokens=tokens, settings=settings))
    parsed: CapabilityOptions = spec.options.model_validate(dict(options))
    store: Dict[str, Any] = dict(action.external_ref or {}) if action is not None else {}
    clients: Dict[str, MicrosoftApi] = {}
    view = alert or default_alert()

    def api(name: Api) -> MicrosoftApi:
        if name not in clients:
            clients[name] = http.api(creds, name, tokens, read_only=read_only)
        return clients[name]

    async def get_alert() -> AlertView:
        return view

    async def checkpoint(patch: Mapping[str, Any]) -> None:
        if store.get("_lost"):
            raise CheckpointLost("the fake ledger row is no longer executing")
        store.update(patch)

    loop = asyncio.get_running_loop()
    ctx = HandlerContext(
        tenant_id=creds.lg_tenant_id,
        integration_id=creds.integration_id,
        cloud=creds.cloud,
        defender_geo=fake.geo,
        options=parsed,
        api=api,
        deadline=loop.time() + deadline_s,
        marker=action_marker(action.id) if action is not None else "",
        alert=get_alert,
        original=original,
        checkpoint=checkpoint,
        protected=protected,
    )
    return ctx, store


def graph_error(status: int, code: str, *, request_id: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> httpx.Response:
    """A Graph error response with the documented envelope."""
    return httpx.Response(
        status,
        json={"error": {"code": code, "message": "fake error text", "innerError": {"request-id": request_id or str(uuid.uuid4())}}},
        headers=headers,
    )


def defender_error(status: int, code: str, *, headers: Optional[Dict[str, str]] = None) -> httpx.Response:
    """A Defender for Endpoint error response (``target`` is the correlation id)."""
    return httpx.Response(
        status, json={"error": {"code": code, "message": "fake error text", "target": str(uuid.uuid4())}}, headers=headers
    )


def token_error(error: str, *, aadsts: Optional[int] = None, status: int = 400) -> httpx.Response:
    """A token endpoint error (``error`` decides; ``error_codes`` only feeds hints)."""
    body: Dict[str, Any] = {
        "error": error,
        "error_description": "fake description",
        "trace_id": str(uuid.uuid4()),
        "correlation_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if aadsts is not None:
        body["error_codes"] = [aadsts]
    return httpx.Response(status, json=body)


TOKEN_PATH: Pattern[str] = re.compile(r"/[0-9a-fA-F-]{36}/oauth2/v2\.0/token")

__all__ = [
    "ContextParts",
    "FakeMicrosoft",
    "PUBLIC_IP",
    "TOKEN_PATH",
    "default_alert",
    "defender_error",
    "fake_config",
    "fake_secret",
    "graph_error",
    "make_action",
    "make_certificate",
    "make_context",
    "make_credentials",
    "ms_settings",
    "token_error",
    "unsigned_token",
]
