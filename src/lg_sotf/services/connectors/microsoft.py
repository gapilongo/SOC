"""The direct Microsoft connector: approved ledger actions executed in Microsoft 365, Entra ID and Defender.

It is only another executor of an approved ledger row: planning, guardrails,
protected assets, autonomy, approvals, caps, blast radius, audit and the
outbox all happen in :mod:`lg_sotf.services.response` exactly as for the
webhook. This module picks the capability that executes the action type
(:mod:`lg_sotf.integrations.microsoft.catalog`), gives its handler a
:class:`~lg_sotf.integrations.microsoft.capability.HandlerContext` and maps
the outcome to the ledger.

``execute(action)``:

1. The action's tenant must be the integration's tenant (an
   ``AssertionError`` otherwise, never turned into a result): one tenant's
   Microsoft credentials never act for another tenant.
2. Pinned rows (rollbacks and scheduler-owned rows: retries, re-runs of
   deferred or handed-off executions) use any catalog capability executing
   the type, preferring the one recorded on the row; other rows need an
   *enabled* capability, else ``failed{capability_disabled}``.
3. A cloud the capability does not support: ``failed{unsupported_cloud}``.
4. Enabled but not live, and not a pinned rollback: **rehearsal**. The
   handler resolves the targets with GETs only (a read-only client) and the
   row is recorded ``dry_run`` with ``rehearsal: true``. A row that already
   started (a re-run or a retry whose ``external_ref`` holds checkpoints) is
   never rehearsed: it fails with ``capability_not_live`` (retryable), so
   the ledger never claims that nothing ran.
5. Otherwise the handler executes within the call's deadline and the
   outcome is mapped: token failures to their ledger error
   (``credentials_invalid`` ...); ``throttled``, a transient token failure
   (``token_unavailable``) and ambiguous writes to
   ``deferred`` (re-run by the scheduler, which reconciles) while
   ``attempts < response.max_execution_attempts``, then ``failed``;
   403 to ``permission_denied`` / ``feature_disabled`` / ``not_licensed``;
   invalid targets to ``invalid_target`` / ``unsupported_target``; anything
   else to ``connector_exception``. A database error while the handler
   checkpoints or reads the alert is raised as
   :class:`~lg_sotf.domain.connectors.LedgerUnavailable`, never
   recorded (the row stays ``executing`` and is run again). A failure after
   progress (``requested`` checkpointed, a step done) keeps the checkpointed
   state with ``partial: true``, ``reversible`` per the capability and
   ``retryable: true``, so Retry and Roll back stay available.
6. Every result carries ``connector``, ``capability``, ``integration_id``,
   ``live``, ``summary``, ``changed`` (and ``already``); failures also
   ``error``, ``http_status``, ``ms_code``, ``request_id``, ``retryable`` and
   ``hint``. ``external_ref`` always records the capability and, after a
   change, whether (and until when) it can be rolled back.

``verify(action)`` runs the capability's read-only re-check (errors
propagate to :mod:`lg_sotf.services.verification`, which classifies them).
``probe_all()`` is the connection test.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Mapping, Optional
from uuid import UUID

import httpx

from lg_sotf.db.errors import NotFound
from lg_sotf.domain.actions import ACTION_CATALOG
from lg_sotf.domain.connectors import (
    Connector,
    ConnectorConfigError,
    ConnectorResult,
    LedgerUnavailable,
    MisconfiguredConnector,
    VerificationResult,
    current_deadline,
)
from lg_sotf.integrations.config import IntegrationConfigError, MicrosoftConfig, decrypt_secret, parse_microsoft_config
from lg_sotf.integrations.microsoft.alert_view import AlertView, load_alert_view
from lg_sotf.integrations.microsoft.auth import AppCredentials, MicrosoftAuthError, TokenProvider, fingerprint_of
from lg_sotf.integrations.microsoft.capability import (
    CapabilitySpec,
    CheckpointLost,
    HandlerContext,
    ProtectedLookup,
    action_marker,
)
from lg_sotf.integrations.microsoft.catalog import capabilities, executor, is_live
from lg_sotf.integrations.microsoft.clouds import Api, cloud_profile
from lg_sotf.integrations.microsoft.connection_test import MicrosoftTestReport, ProbeTarget, run_connection_test
from lg_sotf.integrations.microsoft.http import MicrosoftApi, MicrosoftApiError, MicrosoftHttpFactory, ReadOnlyViolation
from lg_sotf.integrations.microsoft.odata import InvalidTarget
from lg_sotf.net.egress import Resolver
from lg_sotf.observability.logging import get_logger, log_failure

if TYPE_CHECKING:
    from lg_sotf.db.repos import ActionsRepo, Integration, Repositories, ResponseAction
    from lg_sotf.security.crypto import SecretBox
    from lg_sotf.settings import Settings

log = get_logger(__name__)

CONNECTOR_NAME = "microsoft"
DEFERRED_AMBIGUOUS_S = 30.0
# Time kept back from the call's deadline for the ledger write after the handler returns.
DEADLINE_MARGIN_S = 2.0
MIN_HANDLER_S = 1.0
MAX_SUMMARY_CHARS = 200
# The category a protected-asset lookup answers when the connector was built without the tenant's list.
PROTECTED_UNAVAILABLE = "unavailable"
# Step statuses (external_ref.steps) showing that a write of a multi-target action may have taken effect.
PROGRESS_STEP_STATUSES = frozenset({"done", "requested", "requesting"})


def _now() -> datetime:
    return datetime.now(UTC)


def started(state: Optional[Mapping[str, Any]]) -> bool:
    """Whether a row's ``external_ref`` holds checkpoints (an earlier attempt got as far as preparing a write)."""
    return isinstance(state, Mapping) and any(key != "capability" for key in state)


def made_progress(state: Optional[Mapping[str, Any]]) -> bool:
    """Whether checkpointed state shows a write that may have reached Microsoft.

    Handlers checkpoint ``requested: true`` before each non-idempotent write;
    multi-target actions keep ``steps``: one done or requested, or one whose
    handles were recorded before its first change.
    """
    if not isinstance(state, Mapping):
        return False
    if state.get("requested") is True:
        return True
    steps = state.get("steps")
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, Mapping):
            continue
        if step.get("status") in PROGRESS_STEP_STATUSES or (step.get("status") in ("pending", "failed") and step.get("items")):
            return True
    return False


def progress_ref(
    action_type: str, state: Optional[Mapping[str, Any]], capability: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """The ``external_ref`` of a failed execution whose state shows progress, else ``None``.

    The checkpointed state with ``partial: true`` and ``reversible`` per the
    executing capability's :class:`~lg_sotf.integrations.microsoft.capability.ActionSupport`
    (``rollback_until`` kept, or set from its window): what was done can be
    rolled back or finished with Retry.
    """
    if state is None or not made_progress(state):
        return None
    catalog = capabilities()
    key = capability or state.get("capability")
    spec = catalog.get(key) if isinstance(key, str) else None
    if spec is None or action_type not in spec.actions:
        spec = next((s for s in catalog.values() if action_type in s.actions), None)
    support = spec.actions.get(action_type) if spec is not None else None
    ref: Dict[str, Any] = {**dict(state), "partial": True}
    if spec is not None:
        ref["capability"] = spec.key
    ref["reversible"] = bool(support is not None and support.reversible)
    if ref["reversible"] and not ref.get("rollback_until") and support is not None and support.rollback_window_s:
        ref["rollback_until"] = (_now() + timedelta(seconds=support.rollback_window_s)).isoformat()
    return ref


def with_progress(action_type: str, result: ConnectorResult, state: Optional[Mapping[str, Any]],
                  capability: Optional[str] = None) -> ConnectorResult:
    """``result`` (a ``failed`` without its own ``external_ref``) keeping the progress ``state`` shows."""
    if result.status != "failed" or result.external_ref is not None:
        return result
    ref = progress_ref(action_type, state, capability)
    if ref is None:
        return result
    detail = {**result.detail, "changed": True, "partial": True, "retryable": True}
    return ConnectorResult("failed", detail, external_ref=ref)


def permission_hint(spec: CapabilitySpec) -> str:
    """What to grant after a 403: Exchange RBAC for Applications for mailbox permissions, else admin consent.

    A mailbox permission granted by tenant-wide admin consent reaches every
    mailbox, so the hint never sends the operator there.
    """
    if any(p.exchange_rbac for p in spec.permissions):
        return ("grant the capability's mailbox permissions through Exchange RBAC for Applications, scoped to "
                "these mailboxes (Test-ServicePrincipalAuthorization shows the scope; see the connection test); "
                "do not consent them tenant-wide")
    return "grant the capability's application permissions and admin consent (see the connection test)"


class MicrosoftConnector:
    """Connector and verifier for one tenant's Microsoft integration (see the module docstring)."""

    name = CONNECTOR_NAME

    def __init__(
        self,
        *,
        integration: Integration,
        config: MicrosoftConfig,
        creds: AppCredentials,
        tokens: TokenProvider,
        http: MicrosoftHttpFactory,
        settings: Settings,
        checkpoints: ActionsRepo,
        repos: Optional[Repositories] = None,
        protected: Optional[ProtectedLookup] = None,
    ) -> None:
        """``protected`` is the tenant's protected-asset lookup (``ProtectedAssets.match``); without it every
        lookup of a write fails closed."""
        if creds.lg_tenant_id != integration.tenant_id or creds.integration_id != integration.id:
            raise AssertionError("Microsoft credentials do not belong to this integration")
        self.integration_id: UUID = integration.id
        self.tenant_id: str = integration.tenant_id
        self.enabled = integration.enabled
        self.config = config
        self._creds = creds
        self._tokens = tokens
        self._http = http
        self._settings = settings
        self._checkpoints = checkpoints
        self._repos = repos
        self._protected = protected

    # ------------------------------------------------------------------ helpers

    def capability_for(self, action_type: str, *, pinned: bool = False, prefer: Optional[str] = None) -> Optional[CapabilitySpec]:
        return executor(self.config, action_type, pinned=pinned, prefer=prefer)

    def live(self, capability_key: str) -> bool:
        return is_live(self.config, capability_key)

    def _check_tenant(self, action: ResponseAction) -> None:
        if action.tenant_id != self.tenant_id:
            # Never a ledger result: a cross-tenant call is a bug that must stop the caller.
            raise AssertionError("an action of another tenant reached this tenant's Microsoft connector")

    @staticmethod
    def _recorded_capability(action: ResponseAction) -> Optional[str]:
        for source in (action.external_ref, action.result):
            if isinstance(source, Mapping) and isinstance(source.get("capability"), str):
                return str(source["capability"])
        return None

    def _spec_for(self, action: ResponseAction) -> Optional[CapabilitySpec]:
        pinned = action.rollback_of is not None or action.execution_owner == "scheduler"
        return self.capability_for(action.action_type, pinned=pinned, prefer=self._recorded_capability(action))

    def _protected_lookup(self, action: Optional[ResponseAction]) -> ProtectedLookup:
        """``ctx.protected`` of one call: the restorative exemption of the guardrails, else the tenant's list."""
        action_spec = ACTION_CATALOG.get(action.action_type) if action is not None else None
        restorative = bool(action is not None and action.rollback_of is not None and action_spec is not None
                           and action_spec.restorative)
        tenant_list = self._protected

        def protected(kind: str, value: str) -> Optional[str]:
            if restorative:
                return None
            if tenant_list is None:
                return PROTECTED_UNAVAILABLE
            return tenant_list(kind, value)

        return protected

    def _options(self, spec: CapabilitySpec) -> Any:
        entry = self.config.capabilities.get(spec.key)
        return spec.options.model_validate(dict(entry.options) if entry is not None else {})

    def context(
        self,
        spec: CapabilitySpec,
        action: Optional[ResponseAction],
        deadline: float,
        *,
        read_only: bool,
        original: Optional[ResponseAction] = None,
        tracked: Optional[Dict[str, Any]] = None,
    ) -> HandlerContext:
        """The handler context of one call (``action=None`` for a connection-test probe)."""
        clients: Dict[str, MicrosoftApi] = {}
        cached_alert: Dict[str, AlertView] = {}
        state = tracked if tracked is not None else {}

        def api(name: Api) -> MicrosoftApi:
            if name == "defender" and not self._creds.cloud.defender_supported:
                raise MicrosoftApiError(
                    "bad_request", f"the Defender API is not supported in the {self._creds.cloud.name} cloud",
                    code="unsupported_cloud", retryable=False,
                )
            if name not in clients:
                clients[name] = self._http.api(self._creds, name, self._tokens, read_only=read_only)
            return clients[name]

        async def alert() -> AlertView:
            if action is None or self._repos is None:
                raise RuntimeError("no alert is available in this context")
            if "view" not in cached_alert:
                try:
                    cached_alert["view"] = await load_alert_view(self._repos, action.tenant_id, action.alert_id)
                except NotFound:
                    raise
                except Exception as exc:
                    raise LedgerUnavailable(f"the alert could not be read ({type(exc).__name__})") from exc
            return cached_alert["view"]

        async def checkpoint(patch: Mapping[str, Any]) -> None:
            if action is None or read_only:
                raise ReadOnlyViolation("checkpoints are only written while executing")
            try:
                written = await self._checkpoints.checkpoint(action.tenant_id, action.id, patch)
            except Exception as exc:
                raise LedgerUnavailable(f"the checkpoint could not be written ({type(exc).__name__})") from exc
            if not written:
                raise CheckpointLost(f"action {action.id} is no longer executing")
            state.update(patch)

        return HandlerContext(
            tenant_id=self.tenant_id,
            integration_id=self.integration_id,
            cloud=self._creds.cloud,
            defender_geo=self.config.defender_geo,
            options=self._options(spec),
            api=api,
            deadline=deadline,
            marker=action_marker(action.id) if action is not None else "",
            alert=alert,
            original=original,
            checkpoint=checkpoint,
            protected=self._protected_lookup(action),
        )

    async def _original(self, action: ResponseAction) -> Optional[ResponseAction]:
        if action.rollback_of is None:
            return None
        try:
            return await self._checkpoints.get(action.tenant_id, action.rollback_of)
        except NotFound:
            raise
        except Exception as exc:
            raise LedgerUnavailable(f"the original action could not be read ({type(exc).__name__})") from exc

    def _base(self, spec: Optional[CapabilitySpec], *, live: bool) -> Dict[str, Any]:
        return {
            "connector": self.name,
            "capability": spec.key if spec is not None else None,
            "integration_id": str(self.integration_id),
            "live": live,
        }

    def _failed(
        self,
        spec: Optional[CapabilitySpec],
        error: str,
        summary: str,
        *,
        live: bool = True,
        exc: Optional[MicrosoftApiError] = None,
        retryable: bool = False,
        hint: str = "",
        **extra: Any,
    ) -> ConnectorResult:
        detail: Dict[str, Any] = {
            **self._base(spec, live=live),
            "summary": summary[:MAX_SUMMARY_CHARS],
            "changed": False,
            "error": error,
            "http_status": exc.status if exc is not None and exc.status else None,
            "ms_code": exc.code if exc is not None and exc.code else None,
            "request_id": exc.request_id if exc is not None and exc.request_id else None,
            "retryable": exc.retryable if exc is not None else retryable,
            "hint": hint or None,
            **extra,
        }
        return ConnectorResult("failed", detail)

    def _deferred(self, spec: CapabilitySpec, action: ResponseAction, reason: str, retry_after_s: float,
                  exc: Optional[MicrosoftApiError] = None) -> ConnectorResult:
        limit = int(self._settings.response.max_execution_attempts)
        if action.attempts >= limit:
            return self._failed(
                spec, reason if reason in ("throttled", "token_unavailable") else "attempts_exhausted",
                f"{spec.title}: gave up after {action.attempts} attempts ({reason})", exc=exc, retryable=True,
                attempts=action.attempts,
            )
        detail = {
            **self._base(spec, live=True),
            "summary": f"{spec.title}: {reason}, will run again in about {int(retry_after_s)} s"[:MAX_SUMMARY_CHARS],
            "changed": False,
            "deferred": reason,
            "http_status": exc.status if exc is not None and exc.status else None,
            "ms_code": exc.code if exc is not None and exc.code else None,
            "request_id": exc.request_id if exc is not None and exc.request_id else None,
            "attempts": action.attempts,
        }
        return ConnectorResult("deferred", detail, retry_after_s=max(retry_after_s, DEFERRED_AMBIGUOUS_S))

    def _deadline(self) -> float:
        loop = asyncio.get_running_loop()
        outer = current_deadline(float(self._settings.response.background_deadline_s))
        return max(loop.time() + MIN_HANDLER_S, outer - DEADLINE_MARGIN_S)

    # ------------------------------------------------------------------ execute

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        self._check_tenant(action)
        spec = self._spec_for(action)
        if spec is None:
            return self._failed(
                None, "capability_disabled",
                f"no enabled Microsoft capability executes {action.action_type}", live=False,
                hint="enable the capability that executes this action type in the Microsoft integration",
            )
        if self._creds.cloud.name not in spec.clouds:
            return self._failed(spec, "unsupported_cloud", f"{spec.title} is not available in the "
                                f"{self._creds.cloud.name} cloud", live=False)
        live = self.live(spec.key)
        rollback = action.rollback_of is not None
        deadline = self._deadline()
        if not live and not rollback:
            if started(action.external_ref):
                # A re-run or retry of a row that already started: never recorded as "nothing ran".
                return with_progress(action.action_type, self._failed(
                    spec, "capability_not_live", f"{spec.title} is no longer live: not run again", retryable=True,
                    hint="make the capability live again and Retry, or Roll back what was done",
                ), action.external_ref, spec.key)
            return await self._rehearse(spec, action, deadline)
        tracked: Dict[str, Any] = dict(action.external_ref or {})
        outcome = await self._execute(spec, action, deadline, tracked)
        return with_progress(action.action_type, outcome, tracked, spec.key)

    async def _execute(
        self, spec: CapabilitySpec, action: ResponseAction, deadline: float, tracked: Dict[str, Any]
    ) -> ConnectorResult:
        try:
            original = await self._original(action)
            handler = spec.handler(
                self.context(spec, action, deadline, read_only=False, original=original, tracked=tracked)
            )
            result = await handler.execute(action)
        except LedgerUnavailable:
            raise
        except CheckpointLost:
            return self._failed(spec, "lease_lost", f"{spec.title}: the action was settled elsewhere; stopped")
        except MicrosoftAuthError as exc:
            if exc.ledger_error == "token_unavailable":
                # Microsoft's token endpoint is briefly unavailable: like throttling, run again later.
                return self._deferred(spec, action, "token_unavailable", exc.retry_after_s or DEFERRED_AMBIGUOUS_S, exc)
            return self._failed(
                spec, exc.ledger_error, f"{spec.title}: Microsoft sign-in failed ({exc.ledger_error})", exc=exc,
                hint=exc.hint, aadsts=exc.aadsts, trace_id=exc.trace_id or None,
            )
        except MicrosoftApiError as exc:
            return self._api_failure(spec, action, exc)
        except InvalidTarget as exc:
            return self._failed(spec, exc.code, f"{spec.title}: {exc}")
        except Exception as exc:  # noqa: BLE001 - any handler failure is recorded on the ledger
            log_failure(
                log, "microsoft.handler_failed", exc, level="warning", capability=spec.key,
                error_type=type(exc).__name__,
            )
            return self._failed(spec, "connector_exception", f"{spec.title} failed ({type(exc).__name__})",
                                error_type=type(exc).__name__)
        return self._finalize(spec, action, result, tracked)

    def _api_failure(self, spec: CapabilitySpec, action: ResponseAction, exc: MicrosoftApiError) -> ConnectorResult:
        if exc.kind == "throttled":
            return self._deferred(spec, action, "throttled", exc.retry_after_s or DEFERRED_AMBIGUOUS_S, exc)
        if exc.ambiguous:
            return self._deferred(spec, action, "outcome_unknown", DEFERRED_AMBIGUOUS_S, exc)
        error = exc.ledger_error
        hints = {
            "permission_denied": permission_hint(spec),
            "feature_disabled": "the feature is disabled in the Microsoft tenant",
            "not_licensed": "the Microsoft tenant lacks the licence this capability needs",
        }
        return self._failed(spec, error, f"{spec.title}: {exc}", exc=exc, hint=hints.get(error, ""))

    async def _rehearse(self, spec: CapabilitySpec, action: ResponseAction, deadline: float) -> ConnectorResult:
        base = {**self._base(spec, live=False), "rehearsal": True, "would_execute": action.action_type,
                "target": action.target, "changed": False}
        try:
            handler = spec.handler(self.context(spec, action, deadline, read_only=True))
            resolved = await handler.rehearse(action)
        except LedgerUnavailable:
            raise
        except MicrosoftApiError as exc:
            error = exc.ledger_error
            return ConnectorResult("dry_run", {
                **base, "summary": f"rehearsal of {spec.title}: could not resolve the target ({error})"[:200],
                "resolved": None, "rehearsal_error": error, "http_status": exc.status or None,
                "ms_code": exc.code or None,
            })
        except InvalidTarget as exc:
            return ConnectorResult("dry_run", {
                **base, "summary": f"rehearsal of {spec.title}: {exc}"[:200], "resolved": None,
                "rehearsal_error": exc.code,
            })
        except Exception as exc:  # noqa: BLE001 - a rehearsal never fails the ledger row
            log_failure(
                log, "microsoft.rehearsal_failed", exc, level="warning", capability=spec.key,
                error_type=type(exc).__name__,
            )
            return ConnectorResult("dry_run", {
                **base, "summary": f"rehearsal of {spec.title} failed ({type(exc).__name__})"[:200],
                "resolved": None, "rehearsal_error": "connector_exception",
            })
        summary = resolved.get("summary") if isinstance(resolved, Mapping) else None
        return ConnectorResult("dry_run", {
            **base,
            "summary": str(summary or f"rehearsal: {spec.title} would run {action.action_type} on {action.target}")[:200],
            "resolved": dict(resolved) if isinstance(resolved, Mapping) else {},
        })

    def _finalize(
        self, spec: CapabilitySpec, action: ResponseAction, result: Any, tracked: Dict[str, Any]
    ) -> ConnectorResult:
        if not isinstance(result, ConnectorResult) or result.status not in ("succeeded", "failed", "deferred"):
            return self._failed(spec, "connector_exception", f"{spec.title} returned an invalid result")
        if result.status == "deferred":
            deferred = self._deferred(spec, action, str(result.detail.get("deferred") or "deferred"),
                                      float(result.retry_after_s or DEFERRED_AMBIGUOUS_S))
            if deferred.status == "deferred":
                merged = {**deferred.detail, **dict(result.detail), **self._base(spec, live=True)}
                return ConnectorResult("deferred", merged, external_ref=result.external_ref,
                                       retry_after_s=deferred.retry_after_s)
            return deferred
        detail: Dict[str, Any] = dict(result.detail)
        detail.update(self._base(spec, live=True))
        changed = detail.get("changed")
        detail["changed"] = bool(changed) if changed is not None else result.status == "succeeded"
        detail.setdefault("summary", f"{spec.title}: {action.action_type} {result.status}")
        detail["summary"] = str(detail["summary"])[:MAX_SUMMARY_CHARS]
        if result.status == "failed":
            detail.setdefault("error", "connector_exception")
            detail.setdefault("retryable", False)
        ref = dict(result.external_ref) if result.external_ref is not None else dict(tracked)
        ref["capability"] = spec.key
        support = spec.actions.get(action.action_type)
        partial = bool(ref.get("partial"))
        if result.status == "succeeded" or partial:
            if "reversible" not in ref:
                ref["reversible"] = bool(support and support.reversible and (detail["changed"] or partial))
            if ref.get("reversible") and "rollback_until" not in ref and support and support.rollback_window_s:
                ref["rollback_until"] = (_now() + timedelta(seconds=support.rollback_window_s)).isoformat()
        verify = result.verify if result.status == "succeeded" else None
        return ConnectorResult(result.status, detail, external_ref=ref, verify=verify)

    # ------------------------------------------------------------------- verify

    async def verify(self, action: ResponseAction) -> VerificationResult:
        """Re-read what the action changed (read-only). Microsoft and ledger errors propagate to the verification service."""
        self._check_tenant(action)
        spec = self.capability_for(action.action_type, pinned=True, prefer=self._recorded_capability(action))
        if spec is None:
            return VerificationResult("inconclusive", {"reason": "no_verifier"})
        if self._creds.cloud.name not in spec.clouds:
            return VerificationResult("inconclusive", {"reason": "unsupported_cloud"})
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(MIN_HANDLER_S, float(self._settings.response.verify_check_timeout_s) - 1.0)
        original = await self._original(action)
        handler = spec.handler(self.context(spec, action, deadline, read_only=True, original=original))
        return await handler.verify(action)

    async def probe_all(self) -> MicrosoftTestReport:
        """The connection test of this integration (token requests and GETs only)."""
        target = ProbeTarget(
            creds=self._creds,
            config=self.config,
            context_for=lambda spec, deadline: self.context(spec, None, deadline, read_only=True),
        )
        return await run_connection_test(target, self._tokens)


@dataclass(frozen=True)
class MicrosoftClients:
    """The process-wide HTTP factory and token cache (one per service container)."""

    http: MicrosoftHttpFactory
    tokens: TokenProvider

    @classmethod
    def create(
        cls,
        settings: Settings,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        resolver: Optional[Resolver] = None,
        sleep: Optional[Callable[[float], Awaitable[None]]] = None,
    ) -> MicrosoftClients:
        """``transport``/``resolver``/``sleep`` are test hooks (a fake Microsoft)."""
        http = MicrosoftHttpFactory(settings, transport=transport, resolver=resolver, sleep=sleep or asyncio.sleep)
        return cls(http=http, tokens=TokenProvider(http))


def build_microsoft_connector(
    repos: Optional[Repositories],
    settings: Settings,
    box: Optional[SecretBox],
    integration: Integration,
    *,
    tokens: TokenProvider,
    http: MicrosoftHttpFactory,
    checkpoints: ActionsRepo,
    protected: Optional[ProtectedLookup] = None,
) -> MicrosoftConnector:
    """A connector for ``integration`` whether enabled or not (the connection test); ``ConnectorConfigError`` otherwise.

    ``protected`` is the tenant's protected-asset lookup; a connector built without it (the connection test)
    refuses every write that checks a resolved target.
    """
    if integration.kind != CONNECTOR_NAME:
        raise ConnectorConfigError(f"integration {integration.id} is not a Microsoft integration")
    try:
        config = parse_microsoft_config(integration.config)
    except IntegrationConfigError as exc:
        raise ConnectorConfigError(f"invalid Microsoft integration config: {exc}") from None
    if box is None:
        raise ConnectorConfigError("Microsoft credentials cannot be decrypted: encryption keys are not configured")
    try:
        secret = decrypt_secret(box, integration.tenant_id, integration.id, integration.secret_ciphertext)
    except IntegrationConfigError as exc:
        raise ConnectorConfigError(str(exc)) from None
    needed = "private_key_pem" if config.credential == "certificate" else "client_secret"
    if not secret.get(needed):
        raise ConnectorConfigError(f"the Microsoft integration has no {needed} for credential={config.credential}")
    creds = AppCredentials(
        lg_tenant_id=integration.tenant_id,
        integration_id=integration.id,
        cloud=cloud_profile(config.cloud),
        directory_tenant_id=config.directory_tenant_id,
        client_id=config.client_id,
        fingerprint=fingerprint_of(integration.secret_ciphertext),
        client_secret=secret.get("client_secret") if config.credential == "client_secret" else None,
        private_key_pem=secret.get("private_key_pem") if config.credential == "certificate" else None,
        certificate_pem=config.certificate_pem if config.credential == "certificate" else None,
        defender_geo=config.defender_geo,
    )
    return MicrosoftConnector(
        integration=integration, config=config, creds=creds, tokens=tokens, http=http, settings=settings,
        checkpoints=checkpoints, repos=repos, protected=protected,
    )


async def microsoft_connector_for(
    repos: Repositories,
    settings: Settings,
    box: Optional[SecretBox],
    tenant_id: str,
    *,
    tokens: TokenProvider,
    http: MicrosoftHttpFactory,
    checkpoints: ActionsRepo,
    integration: Optional[Integration] = None,
    protected: Optional[ProtectedLookup] = None,
) -> Optional[Connector]:
    """The tenant's Microsoft connector; ``None`` when the tenant has no Microsoft integration.

    A disabled integration, undecryptable credentials or an invalid config
    give a :class:`MisconfiguredConnector` that fails every action visibly.
    Database errors propagate.
    """
    if integration is None:
        found = await repos.integrations.list(tenant_id, kinds=[CONNECTOR_NAME])
        if not found:
            return None
        integration = found[0]
    if integration.tenant_id != tenant_id:
        raise AssertionError("an integration of another tenant was offered to this tenant")
    if not integration.enabled:
        return MisconfiguredConnector(CONNECTOR_NAME, "the Microsoft integration is disabled")
    try:
        return build_microsoft_connector(
            repos, settings, box, integration, tokens=tokens, http=http, checkpoints=checkpoints,
            protected=protected,
        )
    except ConnectorConfigError as exc:
        log.warning("microsoft.connector_misconfigured", reason=str(exc)[:200])
        return MisconfiguredConnector(CONNECTOR_NAME, str(exc))


__all__ = [
    "CONNECTOR_NAME",
    "MicrosoftClients",
    "MicrosoftConnector",
    "build_microsoft_connector",
    "made_progress",
    "microsoft_connector_for",
    "progress_ref",
    "started",
    "with_progress",
]
