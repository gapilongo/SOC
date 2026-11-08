"""``lg-sotf shadow-run``: replay recent alerts through a candidate model profile, then report agreement.

A platform-admin operation (AI-E1.5b), never driven by alert content: the
operator names the tenant, the time window and a candidate profile file;
the command replays the tenant's alerts that production decided in that
window through :class:`~lg_sotf.core.shadow_replay.ShadowReplay`, in
shadow mode, and returns the agreement report built from the stored rows.

**Gate.** Shadow runs read the database on the runtime role, behind the
statement guard and read-only transactions of AI-E1.5a. A separate
SELECT-only database role for them (AI-E1.5c, issue #309) is not built yet,
and no shadow entry point may ship before it. Until it is, the command
refuses to run unless the operator passes ``--i-understand-no-shadow-role``,
and refuses that flag outright in staging and production
(:func:`check_shadow_gate`). AI-E1.5c replaces the flag with its setting.

**Candidate profile.** A YAML file: ``name`` (the report's label; default:
the file name) and the ``llm`` and ``agents`` sections to use instead of
the configured ones (deep-merged, ``${VAR}`` references expanded as in the
main configuration file). Nothing else can differ: routing thresholds,
tenant policy and services stay production's. A profile that moves to
another provider or ``base_url`` never inherits production's API key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

import yaml
from pydantic import ValidationError

from lg_sotf.core.shadow import ShadowRunner
from lg_sotf.core.shadow_replay import Progress, ShadowReplay
from lg_sotf.core.workflow import build_node_deps
from lg_sotf.db.pool import Database
from lg_sotf.db.repos.shadow_verdicts import MAX_REPORT_ALERTS
from lg_sotf.db.tenancy import is_valid_tenant_id
from lg_sotf.domain.shadow_agreement import ShadowAgreementReport
from lg_sotf.errors import OperationError
from lg_sotf.queue.redis import create_redis
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.shadow_reports import stored_report
from lg_sotf.settings import SELF_HOSTED_PROVIDERS, LLMSettings, Settings, _expand_env

NO_SHADOW_ROLE_FLAG = "--i-understand-no-shadow-role"
MAX_WINDOW = timedelta(days=90)
PROFILE_KEYS = frozenset({"name", "llm", "agents"})
MAX_PROFILE_BYTES = 64 * 1024
_WINDOW = re.compile(r"^([1-9][0-9]{0,4})([hd])$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,127}$")


@dataclass(frozen=True)
class ShadowRunOptions:
    tenant_id: str
    candidate: Path
    window: timedelta
    limit: int = 200
    no_shadow_role_acknowledged: bool = False


def check_shadow_gate(settings: Settings, acknowledged: bool) -> None:
    """Refuse to run shadow replays until the shadow database role exists (AI-E1.5c), except on request in dev."""
    if settings.is_production:
        raise OperationError(
            "shadow-run is not available in staging or production yet: it needs the SELECT-only shadow "
            "database role (AI-E1.5c, issue #309)"
        )
    if not acknowledged:
        raise OperationError(
            "shadow-run needs the SELECT-only shadow database role (AI-E1.5c, issue #309), which is not built "
            f"yet. On a development or test database, pass {NO_SHADOW_ROLE_FLAG} to run it on the runtime role."
        )


def parse_window(text: str) -> timedelta:
    """``24h`` or ``7d`` (at most 90 days)."""
    match = _WINDOW.fullmatch(text.strip())
    if match is None:
        raise OperationError("--window is a number of hours or days, e.g. 24h or 7d")
    amount, unit = int(match.group(1)), match.group(2)
    window = timedelta(hours=amount) if unit == "h" else timedelta(days=amount)
    if window > MAX_WINDOW:
        raise OperationError("--window may be at most 90 days")
    return window


def _merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        merged[key] = _merge(current, value) if isinstance(current, Mapping) and isinstance(value, Mapping) else value
    return merged


def load_candidate(settings: Settings, path: Path) -> Tuple[str, Settings]:
    """The candidate's label and the settings it runs with (production's, with the profile's llm and agents)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise OperationError(f"cannot read the candidate profile {path}: {exc.strerror}") from exc
    if len(raw) > MAX_PROFILE_BYTES:
        raise OperationError("the candidate profile is larger than 64 KiB")
    try:
        profile = _expand_env(yaml.safe_load(raw) or {})
    except yaml.YAMLError as exc:
        raise OperationError(f"the candidate profile is not valid YAML: {exc}") from exc
    if not isinstance(profile, dict) or not set(profile) <= PROFILE_KEYS:
        raise OperationError(f"a candidate profile is a mapping with only these keys: {', '.join(sorted(PROFILE_KEYS))}")
    label = str(profile.get("name") or path.stem)
    if not _LABEL.fullmatch(label):
        raise OperationError("the candidate name is 1-128 letters, digits, spaces and ._:/+- characters")
    llm, agents = profile.get("llm") or {}, profile.get("agents") or {}
    if not isinstance(llm, dict) or not isinstance(agents, dict):
        raise OperationError("the candidate profile's llm and agents sections are mappings")
    return label, settings.model_copy(update={"llm": _candidate_llm(settings, llm), "agents": _merge(settings.agents, agents)})


def _candidate_llm(settings: Settings, override: Mapping[str, Any]) -> LLMSettings:
    """Production's ``llm`` with the profile's on top; production's API key never goes to another endpoint."""
    merged = _merge(settings.llm.model_dump(), override)
    moved = any(key in override and override[key] != getattr(settings.llm, key) for key in ("provider", "base_url"))
    if moved and "api_key" not in override:
        merged["api_key"] = None
    try:
        candidate = LLMSettings.model_validate(merged)
    except ValidationError as exc:
        raise OperationError(f"the candidate profile's llm section is invalid: {exc.error_count()} error(s)") from exc
    if moved and candidate.api_key is None and candidate.provider not in (*SELF_HOSTED_PROVIDERS, "fake"):
        raise OperationError(
            "the candidate profile changes the LLM provider or base_url: set its own llm.api_key "
            "(e.g. api_key: ${CANDIDATE_API_KEY})"
        )
    return candidate


async def run_shadow_replay(
    settings: Settings, options: ShadowRunOptions, *, secret_box: Optional[SecretBox] = None,
    progress: Optional[Progress] = None, now: Optional[datetime] = None,
) -> ShadowAgreementReport:
    """Replay the window's decided alerts through the candidate and return the report (the gate must pass)."""
    check_shadow_gate(settings, options.no_shadow_role_acknowledged)
    if not is_valid_tenant_id(options.tenant_id):
        raise OperationError(f"invalid tenant id {options.tenant_id!r}")
    if not 1 <= options.limit <= MAX_REPORT_ALERTS:
        raise OperationError(f"--limit is between 1 and {MAX_REPORT_ALERTS}")
    label, candidate_settings = load_candidate(settings, options.candidate)
    db = Database(settings.database, application_name="lg-sotf-shadow-run", min_size=1, max_size=2)
    redis = create_redis(settings)
    await db.open()
    try:
        deps = await build_node_deps(
            settings=candidate_settings, db=db, redis=redis, events=None, secret_box=secret_box
        )
        try:
            since = (now or datetime.now(UTC)) - options.window
            alert_ids = await deps.repos.shadow_verdicts.replayable_alerts(
                options.tenant_id, since, limit=options.limit
            )
            if not alert_ids:
                raise OperationError(f"tenant {options.tenant_id!r} has no decided alerts in that window")
            replay = ShadowReplay(ShadowRunner(deps), deps.repos, candidate=label)
            report_id = await replay.run(options.tenant_id, alert_ids, progress=progress)
            report = await stored_report(deps.repos, options.tenant_id, report_id)
        finally:
            await deps.agents.cleanup()
    finally:
        await redis.aclose()
        await db.close()
    if report is None:
        raise OperationError("no alert was replayed (the selected alerts were deleted meanwhile)")
    return report
