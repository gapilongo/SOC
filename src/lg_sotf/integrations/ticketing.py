"""Ticketing: Jira (Cloud REST v3, or Data Center v2 with a personal access token) and ServiceNow (Table API).

Tickets are opened for escalations (``escalation.created`` on a ticketing
integration) and by the ``create_ticket`` response action
(:class:`TicketConnector`), at most one per escalation and integration: an
alert's existing ticket is reused and linked to its escalation. Creation is
idempotent across retries and crashes: each ticket carries a correlation
token (a Jira label, the ServiceNow ``correlation_id``) derived from the
tenant and escalation (or alert) and the client searches for it before
creating.

When an analyst decides the escalation, the ticket gets a comment and,
when configured, the resolve transition (Jira) or resolved state
(ServiceNow). The scheduler polls linked open tickets
(:func:`lg_sotf.integrations.delivery.sync_tickets`); a ticket resolved or
closed outside LG-SOTF adds a note to the alert timeline. Ticket state
never decides an escalation: a human does.

Everything written to a ticket is the event summary (title, severity,
verdict, capped entities, a link), never the raw alert.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Protocol, Tuple
from urllib.parse import quote

import httpx

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.repos.integrations import ExternalTicket, Integration
from lg_sotf.integrations.channels import entity_line, facts, link
from lg_sotf.integrations.config import IntegrationConfigError, decrypt_secret
from lg_sotf.integrations.events import alert_summary, build_event, clean_text, ui_base_url
from lg_sotf.integrations.http import DeliveryError, HttpResult, IntegrationHttp, tls_verify
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.services.connectors.base import ConnectorResult
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories, ResponseAction

log = get_logger(__name__)

TICKET_CONNECTOR = "ticketing"
FINAL_DECISIONS = frozenset({"true_positive", "false_positive", "benign_positive"})
SERVICENOW_RESOLVED_STATES = frozenset({"6", "7", "8"})  # Resolved, Closed, Canceled
SERVICENOW_URGENCY: Dict[str, Tuple[str, str]] = {  # severity -> (urgency, impact); 1 = high
    "critical": ("1", "1"),
    "high": ("1", "2"),
    "medium": ("2", "2"),
    "low": ("3", "3"),
    "info": ("3", "3"),
}
MAX_SUMMARY_CHARS = 250
_ALERT_SQL = """
    SELECT id, title, severity, status, disposition, confidence, threat_score, category, source_id,
           summary, jsonb_build_object('entities', normalized->'entities') AS normalized
    FROM alerts WHERE tenant_id = $1 AND id = $2
"""


class DeliveryDeferred(Exception):
    """Not an error: try again in ``delay_s`` without counting an attempt (e.g. the ticket is still being opened)."""

    def __init__(self, reason: str, delay_s: float = 60.0) -> None:
        super().__init__(reason)
        self.delay_s = delay_s


@dataclass(frozen=True)
class TicketRef:
    key: str
    id: str
    url: str
    status: Optional[str] = None


@dataclass(frozen=True)
class TicketState:
    status: str
    resolved: bool
    resolved_by: Optional[str] = None


@dataclass(frozen=True)
class TicketDraft:
    summary: str
    lines: List[str]
    severity: str
    correlation: str


def correlation_token(tenant_id: str, subject: str, subject_id: str) -> str:
    """Stable, opaque search key of a ticket (no tenant or alert id in clear text)."""
    digest = hashlib.sha256(f"{tenant_id}:{subject}:{subject_id}".encode()).hexdigest()[:32]
    return f"lgsotf-{digest}"


def draft_from_event(payload: Mapping[str, Any], base_url: str, correlation: str) -> TicketDraft:
    alert = payload.get("alert") if isinstance(payload.get("alert"), Mapping) else {}
    lines = [f"{name}: {value}" for name, value in facts(payload)]
    entities = entity_line(payload)
    if entities:
        lines.append(f"Entities: {entities}")
    url = link(payload, base_url)
    if url:
        lines.append(f"LG-SOTF: {url}")
    lines.append(f"Reference: {correlation}")
    title = str((alert or {}).get("title") or "Security alert")
    summary = f"[LG-SOTF] [{str((alert or {}).get('severity') or '').upper()}] {title}"
    return TicketDraft(
        summary=summary if len(summary) <= MAX_SUMMARY_CHARS else summary[: MAX_SUMMARY_CHARS - 3] + "...",
        lines=lines,
        severity=str((alert or {}).get("severity") or "medium"),
        correlation=correlation,
    )


def decision_text(payload: Mapping[str, Any], base_url: str) -> str:
    esc = payload.get("escalation") if isinstance(payload.get("escalation"), Mapping) else {}
    decision = str((esc or {}).get("decision") or "a decision").replace("_", " ")
    text = f"LG-SOTF: an analyst decided this escalation: {decision}."
    url = link(payload, base_url)
    return text + (f" Details: {url}" if url else "")


class TicketClient(Protocol):
    system: str

    async def check(self) -> Dict[str, Any]: ...

    async def find(self, correlation: str) -> Optional[TicketRef]: ...

    async def create(self, draft: TicketDraft) -> TicketRef: ...

    async def comment(self, ticket: ExternalTicket, text: str) -> None: ...

    async def resolve(self, ticket: ExternalTicket, text: str) -> Optional[str]: ...

    async def state(self, ticket: ExternalTicket) -> TicketState: ...


def _json(result: HttpResult) -> Dict[str, Any]:
    data = result.json()
    if not isinstance(data, dict):
        raise DeliveryError(f"unexpected response (HTTP {result.status})", retryable=True, code="bad_response")
    return data


def _text(value: Any, limit: int = 200) -> Optional[str]:
    return clean_text(value, limit) if isinstance(value, str) and value else None


class JiraClient:
    system = "jira"

    def __init__(self, http: IntegrationHttp, config: Mapping[str, Any], secret: Mapping[str, str], *, retries: int = 0):
        token = secret.get("api_token")
        if not token:
            raise IntegrationConfigError("the Jira API token is not set")
        self._http = http
        self._config = dict(config)
        self._base = str(config["base_url"]).rstrip("/")
        self._cloud = config.get("deployment", "cloud") == "cloud"
        self._api = f"{self._base}/rest/api/{'3' if self._cloud else '2'}"
        self._headers: Dict[str, str] = {"Accept": "application/json"}
        self._auth: Optional[httpx.Auth] = None
        if self._cloud:
            self._auth = httpx.BasicAuth(str(config.get("email") or ""), token)
        else:
            self._headers["Authorization"] = f"Bearer {token}"
        self._verify = tls_verify(config)
        self._retries = retries

    async def _call(self, method: str, path: str, **kwargs: Any) -> HttpResult:
        return await self._http.request(
            method, self._api + path, headers=self._headers, auth=self._auth, verify=self._verify,
            retries=self._retries, **kwargs,
        )

    def _doc(self, lines: List[str]) -> Any:
        if not self._cloud:
            return "\n".join(lines)
        return {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": line[:2_000]}]} for line in lines if line],
        }

    def url(self, key: str) -> str:
        return f"{self._base}/browse/{quote(key, safe='')}"

    async def check(self) -> Dict[str, Any]:
        me = _json(await self._call("GET", "/myself"))
        await self._call("GET", f"/project/{quote(str(self._config['project_key']), safe='')}")
        return {"account": _text(me.get("displayName")) or "ok", "project": self._config["project_key"]}

    async def find(self, correlation: str) -> Optional[TicketRef]:
        jql = f'labels = "{correlation}" ORDER BY created ASC'
        path = "/search/jql" if self._cloud else "/search"
        data = _json(await self._call("GET", path, params={"jql": jql, "fields": "status", "maxResults": "1"}))
        issues = data.get("issues") or []
        if not issues or not isinstance(issues[0], Mapping):
            return None
        issue = issues[0]
        key = str(issue.get("key") or "")
        if not key:
            return None
        status = ((issue.get("fields") or {}).get("status") or {}).get("name")
        return TicketRef(key=key, id=str(issue.get("id") or key), url=self.url(key), status=_text(status))

    async def create(self, draft: TicketDraft) -> TicketRef:
        labels = list(dict.fromkeys([*self._config.get("labels", ["lg-sotf"]), draft.correlation]))
        fields: Dict[str, Any] = {
            "project": {"key": self._config["project_key"]},
            "issuetype": {"name": self._config.get("issue_type") or "Task"},
            "summary": draft.summary,
            "description": self._doc(draft.lines),
            "labels": labels,
        }
        priority = (self._config.get("priority_map") or {}).get(draft.severity)
        if priority:
            fields["priority"] = {"name": priority}
        data = _json(await self._call("POST", "/issue", json_body={"fields": fields}, idempotent=False))
        key = str(data.get("key") or "")
        if not key:
            raise DeliveryError("Jira did not return an issue key", retryable=True, code="bad_response")
        return TicketRef(key=key, id=str(data.get("id") or key), url=self.url(key))

    async def comment(self, ticket: ExternalTicket, text: str) -> None:
        await self._call(
            "POST", f"/issue/{quote(ticket.external_key, safe='')}/comment", json_body={"body": self._doc([text])},
            idempotent=False,
        )

    async def resolve(self, ticket: ExternalTicket, text: str) -> Optional[str]:
        wanted = str(self._config.get("resolve_transition") or "").strip()
        if not wanted:
            return None
        key = quote(ticket.external_key, safe="")
        data = _json(await self._call("GET", f"/issue/{key}/transitions"))
        for transition in data.get("transitions") or []:
            if not isinstance(transition, Mapping):
                continue
            if str(transition.get("id")) == wanted or str(transition.get("name", "")).lower() == wanted.lower():
                await self._call("POST", f"/issue/{key}/transitions", json_body={"transition": {"id": str(transition["id"])}})
                target = (transition.get("to") or {}).get("name") if isinstance(transition.get("to"), Mapping) else None
                return _text(target) or _text(transition.get("name"))
        raise DeliveryError(
            f"the transition {wanted[:60]!r} is not available on {ticket.external_key}", retryable=False,
            code="transition_unavailable",
        )

    async def state(self, ticket: ExternalTicket) -> TicketState:
        data = _json(
            await self._call(
                "GET", f"/issue/{quote(ticket.external_key, safe='')}",
                params={"fields": "status,resolution,assignee", "expand": "changelog"},
            )
        )
        fields = data.get("fields") if isinstance(data.get("fields"), Mapping) else {}
        status = (fields or {}).get("status") if isinstance((fields or {}).get("status"), Mapping) else {}
        name = _text((status or {}).get("name")) or "unknown"
        category = (status or {}).get("statusCategory") if isinstance((status or {}).get("statusCategory"), Mapping) else {}
        resolved = str((category or {}).get("key", "")).lower() == "done"
        who: Optional[str] = None
        if resolved:
            changelog = data.get("changelog") if isinstance(data.get("changelog"), Mapping) else {}
            for history in reversed(list((changelog or {}).get("histories") or [])):
                items = history.get("items") if isinstance(history, Mapping) else None
                if any(isinstance(i, Mapping) and i.get("field") == "status" for i in items or []):
                    author = history.get("author") if isinstance(history.get("author"), Mapping) else {}
                    who = _text((author or {}).get("displayName"))
                    break
            if who is None:
                assignee = (fields or {}).get("assignee")
                who = _text(assignee.get("displayName")) if isinstance(assignee, Mapping) else None
        return TicketState(status=name, resolved=resolved, resolved_by=who)


class ServiceNowClient:
    system = "servicenow"

    def __init__(self, http: IntegrationHttp, config: Mapping[str, Any], secret: Mapping[str, str], *, retries: int = 0):
        password = secret.get("password")
        if not password:
            raise IntegrationConfigError("the ServiceNow password is not set")
        self._http = http
        self._config = dict(config)
        self._base = str(config["instance_url"]).rstrip("/")
        self._table = f"{self._base}/api/now/table/incident"
        self._auth = httpx.BasicAuth(str(config["username"]), password)
        self._headers = {"Accept": "application/json"}
        self._verify = tls_verify(config)
        self._retries = retries

    async def _call(self, method: str, url: str, **kwargs: Any) -> HttpResult:
        return await self._http.request(
            method, url, headers=self._headers, auth=self._auth, verify=self._verify, retries=self._retries, **kwargs
        )

    def url(self, sys_id: str) -> str:
        return f"{self._base}/nav_to.do?uri={quote('incident.do?sys_id=' + sys_id, safe='')}"

    def _ref(self, row: Mapping[str, Any]) -> TicketRef:
        sys_id = str(row.get("sys_id") or "")
        number = str(row.get("number") or sys_id)
        if not sys_id:
            raise DeliveryError("ServiceNow did not return a sys_id", retryable=True, code="bad_response")
        state = row.get("state")
        return TicketRef(key=number, id=sys_id, url=self.url(sys_id), status=_text(state) if isinstance(state, str) else None)

    async def check(self) -> Dict[str, Any]:
        await self._call("GET", self._table, params={"sysparm_limit": "1", "sysparm_fields": "sys_id"})
        return {"account": self._config["username"], "table": "incident"}

    async def find(self, correlation: str) -> Optional[TicketRef]:
        data = _json(
            await self._call(
                "GET", self._table,
                params={"sysparm_query": f"correlation_id={correlation}", "sysparm_fields": "sys_id,number,state",
                        "sysparm_limit": "1"},
            )
        )
        rows = data.get("result") or []
        if not rows or not isinstance(rows[0], Mapping):
            return None
        return self._ref(rows[0])

    async def create(self, draft: TicketDraft) -> TicketRef:
        urgency, impact = SERVICENOW_URGENCY.get(draft.severity, ("2", "2"))
        body: Dict[str, Any] = {
            "short_description": draft.summary[:160],
            "description": "\n".join(draft.lines),
            "urgency": urgency,
            "impact": impact,
            "correlation_id": draft.correlation,
            "correlation_display": "LG-SOTF",
        }
        for key in ("assignment_group", "caller_id", "category"):
            if self._config.get(key):
                body[key] = self._config[key]
        data = _json(
            await self._call(
                "POST", self._table, params={"sysparm_fields": "sys_id,number,state"}, json_body=body, idempotent=False
            )
        )
        row = data.get("result")
        if not isinstance(row, Mapping):
            raise DeliveryError("ServiceNow returned no incident", retryable=True, code="bad_response")
        return self._ref(row)

    def _record(self, ticket: ExternalTicket) -> str:
        return f"{self._table}/{quote(ticket.external_id or '', safe='')}"

    async def comment(self, ticket: ExternalTicket, text: str) -> None:
        await self._call(
            "PATCH", self._record(ticket), json_body={self._config.get("comment_field", "work_notes"): text},
            idempotent=False,  # work notes append: a resend adds the note twice
        )

    async def resolve(self, ticket: ExternalTicket, text: str) -> Optional[str]:
        if not self._config.get("resolve_on_decision"):
            return None
        await self._call(
            "PATCH",
            self._record(ticket),
            json_body={
                "state": self._config.get("resolve_state", "6"),
                "close_code": self._config.get("close_code", "Solution provided"),
                "close_notes": text,
            },
        )
        return "Resolved"

    async def state(self, ticket: ExternalTicket) -> TicketState:
        data = _json(
            await self._call(
                "GET", self._record(ticket),
                params={"sysparm_fields": "state,number,resolved_by,closed_by", "sysparm_display_value": "all"},
            )
        )
        row = data.get("result") if isinstance(data.get("result"), Mapping) else {}

        def field(name: str) -> Tuple[Optional[str], Optional[str]]:
            value = (row or {}).get(name)
            if isinstance(value, Mapping):
                return (str(value.get("value")) if value.get("value") is not None else None, _text(value.get("display_value")))
            return (str(value) if value is not None else None, _text(value))

        state_value, state_label = field("state")
        resolved = state_value in SERVICENOW_RESOLVED_STATES
        who = None
        if resolved:
            who = field("resolved_by")[1] or field("closed_by")[1]
        return TicketState(status=state_label or state_value or "unknown", resolved=resolved, resolved_by=who)


def ticket_client(
    integration: Integration, http: IntegrationHttp, secret: Mapping[str, str], *, retries: int = 0
) -> TicketClient:
    if integration.kind == "jira":
        return JiraClient(http, integration.config, secret, retries=retries)
    if integration.kind == "servicenow":
        return ServiceNowClient(http, integration.config, secret, retries=retries)
    raise IntegrationConfigError(f"{integration.kind} is not a ticketing integration")


class TicketService:
    """Opens, updates and polls tickets for one install (API, worker or scheduler)."""

    def __init__(
        self,
        repos: Repositories,
        settings: Settings,
        *,
        http: Optional[IntegrationHttp] = None,
        secret_box: Optional[SecretBox] = None,
        retries: int = 0,
    ) -> None:
        self._repos = repos
        self._settings = settings
        self._http = http or IntegrationHttp(settings)
        self._box = secret_box
        self._retries = retries
        self._audit = AuditLogger(repos)
        self.base_url = ui_base_url(settings)

    def _secret_box(self) -> Optional[SecretBox]:
        if self._box is None and self._settings.security.encryption_keys is not None:
            try:
                self._box = SecretBox.from_settings(self._settings)
            except SecurityConfigError:
                return None
        return self._box

    def secret(self, integration: Integration) -> Dict[str, str]:
        return decrypt_secret(self._secret_box(), integration.tenant_id, integration.id, integration.secret_ciphertext)

    def client(self, integration: Integration) -> TicketClient:
        return ticket_client(integration, self._http, self.secret(integration), retries=self._retries)

    async def alert_event(self, tenant_id: str, alert_id: str, event_type: str) -> Dict[str, Any]:
        """A summary payload for ``alert_id`` (used by the ``create_ticket`` action)."""
        async with self._repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            row = await conn.fetchrow(_ALERT_SQL, tenant_id, alert_id)
        if row is None:
            raise DeliveryError("the alert no longer exists", retryable=False, code="alert_missing")
        return build_event(event_type, tenant_id, alert=alert_summary(dict(row)))

    async def ensure_ticket(
        self,
        integration: Integration,
        payload: Mapping[str, Any],
        *,
        alert_id: str,
        escalation_id: Optional[str] = None,
        action_id: Any = None,
    ) -> Tuple[ExternalTicket, bool]:
        """The ticket of this escalation (or alert) in ``integration``, opened if needed; (ticket, created)."""
        tenant_id = integration.tenant_id
        repo = self._repos.integrations
        existing = await repo.find_ticket(tenant_id, integration.id, alert_id=alert_id, escalation_id=escalation_id)
        if existing is not None:
            if escalation_id and existing.escalation_id is None:
                existing = await repo.link_escalation(tenant_id, existing.id, escalation_id)
            return existing, False
        client = self.client(integration)
        correlation = (
            correlation_token(tenant_id, "escalation", escalation_id)
            if escalation_id
            else correlation_token(tenant_id, "alert", alert_id)
        )
        ref = await client.find(correlation)
        created = ref is None
        if ref is None:
            ref = await client.create(draft_from_event(payload, self.base_url, correlation))
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            ticket = await repo.add_ticket(
                tenant_id,
                integration.id,
                system=client.system,
                alert_id=alert_id,
                escalation_id=escalation_id,
                action_id=action_id,
                external_key=ref.key,
                external_id=ref.id,
                external_url=ref.url,
                external_status=ref.status,
                conn=conn,
            )
            await self._repos.alert_events.append(
                tenant_id,
                alert_id,
                "ticket.created" if created else "ticket.linked",
                actor_type="system",
                actor_id=f"integration:{integration.id}",
                data={
                    "system": client.system,
                    "ticket": ticket.external_key,
                    "url": ticket.external_url,
                    "integration_id": str(integration.id),
                    "escalation_id": escalation_id,
                    "note": f"{'Opened' if created else 'Linked'} {client.system} ticket {ticket.external_key}",
                },
                conn=conn,
            )
            await self._audit.record(
                tenant_id,
                "integration.ticket_created" if created else "integration.ticket_linked",
                "external_ticket",
                str(ticket.id),
                actor_type="system",
                actor_id=f"integration:{integration.id}",
                details={"alert_id": alert_id, "escalation_id": escalation_id, "ticket": ticket.external_key,
                         "system": client.system},
                conn=conn,
            )
        log.info("integrations.ticket_opened", system=client.system, created=created)
        return ticket, created

    async def sync_decision(self, integration: Integration, payload: Mapping[str, Any], *, escalation_id: str) -> Dict[str, Any]:
        """Comment the analyst's decision on the escalation's ticket and resolve it when configured."""
        tenant_id = integration.tenant_id
        alert = payload.get("alert") if isinstance(payload.get("alert"), Mapping) else {}
        # Check for an unfinished create BEFORE looking the ticket up: a create records its ticket before its
        # outbox row is marked sent, so in this order a create finishing concurrently is always seen one way
        # or the other. The reverse order could miss both and drop the decision comment.
        create_pending = await self._repos.integrations.has_pending(
            tenant_id, integration.id, "ticket_create", escalation_id=escalation_id
        )
        ticket = await self._repos.integrations.find_ticket(
            tenant_id, integration.id, alert_id=str((alert or {}).get("id") or ""), escalation_id=escalation_id
        )
        if ticket is None or (ticket.escalation_id not in (None, escalation_id)):
            if create_pending:
                raise DeliveryDeferred("the escalation's ticket is still being opened")
            return {"skipped": "no_ticket"}
        client = self.client(integration)
        text = decision_text(payload, self.base_url)
        result: Dict[str, Any] = {"ticket": ticket.external_key}
        if integration.config.get("comment_on_decision", True):
            await client.comment(ticket, text)
            result["commented"] = True
        esc = payload.get("escalation") if isinstance(payload.get("escalation"), Mapping) else {}
        if (esc or {}).get("decision") in FINAL_DECISIONS and not ticket.resolved:
            status = await client.resolve(ticket, text)
            if status:
                await self._repos.integrations.record_sync(tenant_id, ticket.id, external_status=status)
                result["resolved_status"] = status
        return result


class TicketConnector:
    """The ``create_ticket`` response action through the tenant's ticketing integration (idempotent per alert)."""

    name = TICKET_CONNECTOR

    def __init__(self, service: TicketService, integration: Integration) -> None:
        self._service = service
        self._integration = integration

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        base = {"connector": self.name, "system": self._integration.kind, "integration_id": str(self._integration.id)}
        try:
            payload = await self._service.alert_event(action.tenant_id, action.alert_id, "action.executed")
            ticket, created = await self._service.ensure_ticket(
                self._integration, payload, alert_id=action.alert_id, action_id=action.id
            )
        except (DeliveryError, IntegrationConfigError) as exc:
            code = getattr(exc, "code", "integration_misconfigured")
            log.warning("integrations.create_ticket_failed", error=code)
            return ConnectorResult("failed", {**base, "error": code, "detail": str(exc)[:300]})
        return ConnectorResult(
            "succeeded", {**base, "ticket": ticket.external_key, "url": ticket.external_url, "created": created}
        )
