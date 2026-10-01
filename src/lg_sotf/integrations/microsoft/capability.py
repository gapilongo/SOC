"""The capability seam: how the mail, Entra and Defender packages plug into the Microsoft connector.

A **capability** is one switchable unit of direct response (``mail.remediate``,
``entra.account``, ``defender.isolation``, ...). Each package's
``__init__.py`` exports ``CAPABILITIES: Tuple[CapabilitySpec, ...]``;
:mod:`lg_sotf.integrations.microsoft.catalog` merges them and checks the
invariants. Nothing else registers: packages add no migration, setting,
route, event or UI code (the UI renders the catalog).

A :class:`CapabilitySpec` declares what the capability executes (forward and
inverse action types, with reversibility), the exact application
permissions it needs (and any Entra directory role or Exchange RBAC role
that tokens cannot show), its option schema, the clouds it supports and the
factory of its :class:`CapabilityHandler`.

Handlers
--------

The connector builds one handler per call with a :class:`HandlerContext`
and calls exactly one of:

* ``rehearse(action)`` (capability enabled but not live): resolve the
  targets with GETs only and return what *would* happen; recorded as
  ``dry_run`` with ``rehearsal: true``.
* ``execute(action)``: perform the change and return a
  :class:`~lg_sotf.services.connectors.base.ConnectorResult` with status
  ``succeeded``, ``failed`` or ``deferred``.
* ``verify(action)``: re-read the state after ``succeeded`` (GETs only) and
  return a :class:`~lg_sotf.services.connectors.base.VerificationResult`.
* ``probe()``: GETs that show whether the permissions and licences work,
  for the connection test (no action; ``ctx.marker`` is empty).

Read-only calls get a client that refuses anything but GET.

Rules every handler follows (``docs/microsoft.md``):

* **Idempotent per action id.** Read before writing; tag every object it
  creates with ``ctx.marker`` (``"LG-SOTF action <uuid>"``) so a re-run finds
  it; call ``await ctx.checkpoint({...})`` *before* each non-idempotent write
  (it merges into ``response_actions.external_ref`` and raises
  :class:`CheckpointLost` when the row is no longer executing); on a re-run
  adopt a pending operation or an existing object instead of creating
  another.
* **Untrusted input** (targets, alert fields) goes through
  :mod:`lg_sotf.integrations.microsoft.odata` only.
* **Deadline.** Every request passes ``deadline=ctx.deadline``; long
  operations return ``deferred`` or ``succeeded`` with a pending
  :class:`~lg_sotf.services.connectors.base.VerifyPlan` rather than wait.
* **Results.** ``detail`` is small (at most 8 KiB, no secrets, no Microsoft
  free text) with ``summary`` (one line), ``changed`` and ``already``;
  ``external_ref`` holds ids, per-target ``steps``, ``partial``,
  ``reversible`` and ``rollback_until``. For an inverse type, ``ctx.original``
  is the row being rolled back.
* Errors: raise :class:`~lg_sotf.integrations.microsoft.http.MicrosoftApiError`
  (the connector maps it to the ledger error codes) or
  :class:`~lg_sotf.integrations.microsoft.odata.InvalidTarget`; return
  ``failed`` with a ledger code for outcomes such as ``privileged_target_refused``.
"""

from __future__ import annotations

import asyncio
import typing
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    List,
    Literal,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    Type,
    Union,
)
from uuid import UUID

from annotated_types import Ge, Le, MaxLen
from pydantic import BaseModel, ConfigDict

from lg_sotf.integrations.microsoft.alert_view import AlertView
from lg_sotf.integrations.microsoft.clouds import Api, Cloud, CloudProfile
from lg_sotf.integrations.microsoft.http import MicrosoftApi
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

Package = Literal["mail", "entra", "defender"]
ProbeStatus = Literal["ok", "forbidden", "not_licensed", "not_found", "error", "skipped"]
MARKER_PREFIX = "LG-SOTF action"


def action_marker(action_id: Union[UUID, str]) -> str:
    """The marker every object created for an action carries: ``LG-SOTF action <uuid>``."""
    return f"{MARKER_PREFIX} {action_id}"


ProtectedLookup = Callable[[str, str], Optional[str]]
"""``protected(kind, value)``: the tenant's protected-asset category ``value`` matches (``user``, ``host`` ...), or ``None``."""


def nothing_protected(kind: str, value: str) -> Optional[str]:
    """The :data:`ProtectedLookup` of a context that never writes (probes) or has no protected assets."""
    return None


class CheckpointLost(RuntimeError):
    """The action is no longer ``executing`` (another run settled it): stop without writing."""


class CapabilityOptions(BaseModel):
    """Base of a capability's options (stored in the integration config, validated on every save).

    Every field has a default. Allowed field types: ``bool``; ``int`` with
    ``ge``/``le``; ``str`` with ``max_length`` (a ``Literal`` of strings
    renders as a select); ``List[str]`` with ``max_length``. Override
    :meth:`problems` for cross-field or per-cloud checks.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    def problems(self, cloud: Cloud) -> List[str]:
        """Problems that forbid enabling the capability with these options in ``cloud`` (empty: fine)."""
        return []


class NoOptions(CapabilityOptions):
    """A capability without options."""


@dataclass(frozen=True)
class Permission:
    """One permission a capability needs.

    ``role`` is the exact application permission (app role value, e.g.
    ``User.EnableDisableAccount.All`` or ``Machine.Isolate``) on ``api``.
    ``when`` names the option condition under which it is needed
    (``"recipient_source=message_trace"``): the permission is then required
    exactly when the condition holds, whatever ``required`` says.
    ``directory_role`` is an Entra role the service principal must also
    hold, ``exchange_rbac`` an Exchange RBAC for Applications role: neither
    shows in tokens, so the connection test reports them as ``unknown``
    (and ``role`` itself as ``unknown`` when the token lacks it: with
    ``exchange_rbac`` it is meant to be granted there, not by consent).
    """

    api: Api
    role: str
    purpose: str
    required: bool = True
    when: str = ""
    directory_role: Optional[str] = None
    exchange_rbac: Optional[str] = None


@dataclass(frozen=True)
class ActionSupport:
    """How a capability supports one action type.

    ``reversible``: this capability also executes the type's inverse
    (``ACTION_CATALOG[type].inverse``), so a succeeded action can be rolled
    back. ``rollback_window_s``: default time a rollback stays possible (the
    handler may set ``external_ref.rollback_until`` itself).
    """

    reversible: bool = False
    rollback_window_s: Optional[int] = None
    note: str = ""


@dataclass(frozen=True)
class ProbeCheck:
    """One connection-test check. ``detail`` is safe to store (at most 300 characters)."""

    name: str
    status: ProbeStatus
    permission: Optional[str] = None
    detail: str = ""


@dataclass
class HandlerContext:
    """Everything a handler may use for one call (built by the connector; never shared between tenants).

    ``api(name)`` returns the client for ``graph`` or ``defender`` (read-only
    for rehearse, verify and probe). ``deadline`` is the ``loop.time()`` by
    which the call must return. ``alert()`` reads the action's alert once
    (cached). ``checkpoint(patch)`` merges ``patch`` into the row's
    ``external_ref`` and raises :class:`CheckpointLost` when the row is no
    longer executing. ``original`` is the row being rolled back (inverse
    types only).

    ``protected(kind, value)`` checks a value the handler *resolved* against
    the tenant's protected assets (``ProtectedAssets.match``): the
    guardrails only saw the literal ledger target, so a handler that turns
    it into another identity (an alias or an object id resolved to a user)
    checks that identity's names before any write and refuses with
    ``protected_asset``. It answers ``None`` for a rollback of a restorative
    type (the guardrails' restorative exemption) and fails closed (a
    category) when the connector has no protected-asset list.
    """

    tenant_id: str
    integration_id: UUID
    cloud: CloudProfile
    defender_geo: Optional[str]
    options: CapabilityOptions
    api: Callable[[Api], MicrosoftApi]
    deadline: float
    marker: str
    alert: Callable[[], Awaitable[AlertView]]
    original: Optional[ResponseAction]
    checkpoint: Callable[[Mapping[str, Any]], Awaitable[None]]
    protected: ProtectedLookup = nothing_protected

    def remaining_s(self) -> float:
        """Seconds left before :attr:`deadline` (never negative)."""
        return max(0.0, self.deadline - asyncio.get_running_loop().time())


class CapabilityHandler(Protocol):
    """What a capability implements (see the module docstring for the rules)."""

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]: ...

    async def execute(self, action: ResponseAction) -> ConnectorResult: ...

    async def verify(self, action: ResponseAction) -> VerificationResult: ...

    async def probe(self) -> List[ProbeCheck]: ...


@dataclass(frozen=True)
class CapabilitySpec:
    """The declaration of one capability (``key`` is ``"<package>.<name>"``).

    ``actions`` lists every action type the capability executes, forward
    and inverse. ``excludes`` names capabilities that may not be enabled at
    the same time (two ways to execute the same type).
    ``live_confirmation`` is an extra sentence in the UI's "go live" dialog.
    """

    key: str
    package: Package
    api: Api
    title: str
    description: str
    actions: Mapping[str, ActionSupport]
    permissions: Tuple[Permission, ...]
    options: Type[CapabilityOptions]
    handler: Callable[[HandlerContext], CapabilityHandler]
    clouds: FrozenSet[Cloud]
    licence: str = ""
    live_confirmation: str = ""
    excludes: Tuple[str, ...] = field(default_factory=tuple)


def _metadata(info: Any, kind: type) -> Optional[Any]:
    return next((m for m in info.metadata if isinstance(m, kind)), None)


def option_problems(model: Type[CapabilityOptions]) -> List[str]:
    """Why an options model breaks the allowed field types (empty: it is fine)."""
    problems: List[str] = []
    if not issubclass(model, CapabilityOptions):
        return ["options must subclass CapabilityOptions"]
    for name, info in model.model_fields.items():
        annotation = info.annotation
        origin = typing.get_origin(annotation)
        args = typing.get_args(annotation)
        if info.is_required():
            problems.append(f"option {name} has no default")
        if annotation is bool:
            continue
        if annotation is int:
            if _metadata(info, Ge) is None or _metadata(info, Le) is None:
                problems.append(f"option {name}: int options need ge and le bounds")
            continue
        if annotation is str:
            if _metadata(info, MaxLen) is None:
                problems.append(f"option {name}: str options need max_length")
            continue
        if origin is Literal and args and all(isinstance(a, str) for a in args):
            continue
        if origin in (list, List) and args == (str,):
            if _metadata(info, MaxLen) is None:
                problems.append(f"option {name}: List[str] options need max_length")
            continue
        problems.append(f"option {name}: type {annotation!r} is not allowed (bool, int, str, Literal, List[str])")
    return problems


__all__ = [
    "MARKER_PREFIX",
    "ActionSupport",
    "CapabilityHandler",
    "CapabilityOptions",
    "CapabilitySpec",
    "CheckpointLost",
    "HandlerContext",
    "NoOptions",
    "Package",
    "Permission",
    "ProbeCheck",
    "ProbeStatus",
    "ProtectedLookup",
    "action_marker",
    "nothing_protected",
    "option_problems",
]
