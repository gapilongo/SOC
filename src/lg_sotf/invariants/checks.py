"""Runtime checks behind ``lg-sotf verify-invariants`` (SEC9.1).

Each check proves one part of an invariant (:mod:`lg_sotf.invariants.registry`)
on the install it runs on: its database catalog and grants, its settings and
the code it ships. Every check is read-only. The database checks run in one
read-only transaction scoped to a synthetic tenant (:data:`PROBE_TENANT`) that
owns no data, so any row they can see belongs to someone else; the settings
checks treat that tenant as a dry-run tenant (:data:`PROBE_TENANT_SETTINGS`).
Nothing is written, no connector is called and no secret is logged.

A check answers ``pass``, ``fail`` or ``skip`` (it does not apply to this
install, for example the runtime-role checks on a single-role install).
"""

from __future__ import annotations

import secrets
import string
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Tuple

from lg_sotf.compliance.canonical import optional_signing_key, seal, verify
from lg_sotf.db.migrate import schema_is_current
from lg_sotf.db.pool import Database
from lg_sotf.db.posture import (
    AUDIT_TRIGGERS,
    RoleAttributes,
    TableSecurity,
    audit_triggers,
    bypass_honoured,
    current_role_attributes,
    privileges_on,
    tables_with_visible_rows,
    tenant_table_security,
)
from lg_sotf.domain.routing import RoutingThresholds, decide, route_after_triage
from lg_sotf.models.vocabulary import HIGH_SEVERITIES
from lg_sotf.observability.logging import is_configured
from lg_sotf.security.redaction import redact, redact_text
from lg_sotf.services.connectors.registry import ConnectorRegistry
from lg_sotf.settings import Settings

__all__ = [
    "CHECKS",
    "DATABASE_CHECKS",
    "PROBE_TENANT",
    "PROBE_TENANT_SETTINGS",
    "CheckResult",
    "run_checks",
]

Outcome = Literal["pass", "fail", "skip"]

PROBE_TENANT = "lgsotf-invariants-probe"
PROBE_TENANT_SETTINGS: Dict[str, Any] = {"response": {"dry_run": True}}
MUTATING_PRIVILEGES: Tuple[str, ...] = ("UPDATE", "DELETE", "TRUNCATE")
# The probe reads a table only while its estimated size is below this: RLS hides every row, so each read is a scan.
PROBE_MAX_ROWS = 200_000
SINGLE_ROLE = (
    "single-role install: database.url connects as the schema owner, which may bypass RLS by design; "
    "use a separate runtime role (docs/deployment.md) for this guarantee"
)


@dataclass(frozen=True)
class CheckResult:
    check: str
    invariant: str
    outcome: Outcome
    detail: str

    def as_dict(self) -> Dict[str, str]:
        return asdict(self)


# check name -> the invariant it proves. The CI gate keeps this and the registry in step.
CHECKS: Dict[str, str] = {
    "rls_catalog": "INV-01",
    "runtime_role": "INV-01",
    "rls_probe": "INV-01",
    "kill_switch": "INV-02",
    "routing_policy": "INV-03",
    "audit_append_only": "INV-06",
    "log_redaction": "INV-07",
    "evidence_seal": "INV-08",
}
DATABASE_CHECKS: Tuple[str, ...] = ("rls_catalog", "runtime_role", "rls_probe", "audit_append_only")


def _result(check: str, ok: Optional[bool], detail: str) -> CheckResult:
    outcome: Outcome = "skip" if ok is None else ("pass" if ok else "fail")
    return CheckResult(check, CHECKS[check], outcome, detail)


# ------------------------------------------------------------------ settings and code


def check_kill_switch(settings: Settings) -> CheckResult:
    """A dry-run tenant is always in dry run, and the install switch overrides every tenant."""
    registry = ConnectorRegistry(settings)
    problems: List[str] = []
    if not registry.forced_dry_run(PROBE_TENANT_SETTINGS) or registry.selected_name(PROBE_TENANT_SETTINGS) != "dry_run":
        problems.append("a tenant with response.dry_run=true is not routed to the dry-run connector")
    if settings.response.dry_run and not registry.forced_dry_run({"response": {"dry_run": False}}):
        problems.append("a tenant's dry_run=false overrides the install-wide kill switch")
    auto = sorted(risk for risk, level in settings.response.default_autonomy.items() if level == "auto")
    state = "on: every action is rehearsed" if settings.response.dry_run else "off: tenants not in dry run act"
    detail = "; ".join(problems) or (
        f"install kill switch {state}; the dry-run tenant is rehearsed; default 'auto' autonomy: {', '.join(auto) or 'none'}"
    )
    return _result("kill_switch", not problems, detail)


def _benign_state(severity: str, rule_threat: int) -> Dict[str, Any]:
    """A synthetic alert the model calls benign with full confidence, with five false-positive signals."""
    triage = {"confidence": 0, "rule_confidence": rule_threat, "rule_fp": ["r"] * 5, "llm_fp": ["l"] * 5,
              "rule_tp": [], "llm_tp": []}
    analysis = {"threat_score": 0, "rule_threat_score": rule_threat, "verdict": "benign"}
    return {"severity": severity, "confidence": 0, "triage": triage, "correlation": {}, "analysis": analysis}


def check_routing_policy(settings: Settings) -> CheckResult:
    """With this install's thresholds, a benign verdict never closes a high alert, nor an uncorroborated one."""
    thresholds = RoutingThresholds.from_settings(settings.routing)
    closed: List[str] = []
    for severity in sorted(HIGH_SEVERITIES):
        state = _benign_state(severity, rule_threat=0)
        if route_after_triage(state, thresholds) == "close" or decide(state, thresholds).route == "close":
            closed.append(f"{severity} alert closed on a benign verdict")
    uncorroborated = _benign_state("low", rule_threat=100)
    uncorroborated["triage"].update(rule_fp=[], rule_confidence=100)
    if decide(uncorroborated, thresholds).route == "close":
        closed.append("low alert closed on the model's verdict without rule corroboration")
    return _result("routing_policy", not closed, "; ".join(closed) or "a benign model verdict closes no high, critical or uncorroborated alert")


def _synthetic_secrets() -> List[Tuple[str, str, str]]:
    """``(label, text, secret)`` credential-shaped samples, made fresh on every run (never a real value)."""
    word = secrets.token_hex(10)
    bearer = secrets.token_urlsafe(24)
    github = "ghp_" + secrets.token_hex(18)
    aws = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return [
        ("a connection string", f"postgresql://svc:{word}@db.internal:5432/app", word),
        ("a password field", f"password={word}", word),
        ("a bearer token", f"Authorization: Bearer {bearer}", bearer),
        ("a GitHub token", f"token {github}", github),
        ("an AWS access key", f"key {aws} used", aws),
    ]


def check_log_redaction(settings: Settings) -> CheckResult:
    """The log pipeline redacts, and redaction removes every known credential shape."""
    del settings
    problems: List[str] = []
    if not is_configured():
        problems.append("logging is not configured with the redaction processors")
    for label, text, secret in _synthetic_secrets():
        if secret in redact_text(text)[0]:
            problems.append(f"{label} is not redacted")
    value = secrets.token_hex(8)
    if value in str(redact({"password": value})[0]):
        problems.append("a 'password' field is not masked")
    return _result("log_redaction", not problems, "; ".join(problems) or "log records and known credentials are redacted")


def check_evidence_seal(settings: Settings) -> CheckResult:
    """A synthetic pack sealed with this install's key verifies, and a changed one does not."""
    key = optional_signing_key(settings)
    pack = seal({"kind": "verify-invariants", "tenant": PROBE_TENANT, "nonce": secrets.token_hex(8)}, key)
    first = verify(pack, key)
    tampered = verify({**pack, "tenant": "someone-else"}, key)
    problems: List[str] = []
    if not first.digest_ok or (key is not None and not first.signed_ok):
        problems.append(f"a freshly sealed pack does not verify ({first.signature})")
    if tampered.digest_ok or tampered.signed_ok:
        problems.append("a changed pack still verifies")
    signing = "signed (HMAC-SHA256)" if key is not None else "unsigned: security.indicator_hmac_key is not set"
    return _result("evidence_seal", not problems, "; ".join(problems) or f"digest verified; packs are {signing}")


SETTINGS_CHECKS: Tuple[Callable[[Settings], CheckResult], ...] = (
    check_kill_switch,
    check_routing_policy,
    check_log_redaction,
    check_evidence_seal,
)


# ------------------------------------------------------------------ database


def _single_role(settings: Settings) -> bool:
    return settings.database.runtime_role is None and settings.database.migration_url is None


def check_rls_catalog(tables: Sequence[TableSecurity]) -> CheckResult:
    names = {t.name for t in tables}
    missing = sorted({"tenants", "alerts", "audit_log", "users"} - names)
    weak = sorted(t.name for t in tables if not t.isolated)
    problems = [f"tables not found: {', '.join(missing)}"] if missing else []
    problems += [f"without forced RLS and a policy: {', '.join(weak)}"] if weak else []
    if problems:
        return _result("rls_catalog", False, "; ".join(problems))
    partitions = sum(t.partition for t in tables)
    return _result("rls_catalog", True, f"{len(tables)} tenant tables ({partitions} partitions) under forced RLS")


def check_runtime_role(role: RoleAttributes, settings: Settings) -> CheckResult:
    if not role.can_bypass_rls:
        return _result("runtime_role", True, f"{role.name!r}: no superuser, no BYPASSRLS, not in the schema owner role")
    if _single_role(settings):
        return _result("runtime_role", None, SINGLE_ROLE)
    flags = [n for n, on in (("superuser", role.superuser), ("BYPASSRLS", role.bypassrls),
                             ("member of the schema owner", role.owner_member)) if on]
    return _result("runtime_role", False, f"the runtime connection's role {role.name!r} is {', '.join(flags)}")


def check_rls_probe(leaked: Sequence[str], probed: int, skipped: int, role: RoleAttributes, bypass: bool) -> CheckResult:
    problems = [f"the probe tenant sees rows of other tenants in: {', '.join(leaked)}"] if leaked else []
    if bypass and not role.can_bypass_rls:
        problems.append(f"app.bypass_rls is honoured for {role.name!r}")
    if problems:
        return _result("rls_probe", False, "; ".join(problems))
    how = "app.bypass_rls not requested: this role may bypass RLS" if role.can_bypass_rls else (
        "even with app.bypass_rls set"
    )
    large = f"; {skipped} large tables not read (rls_catalog covers them)" if skipped else ""
    return _result("rls_probe", True, f"the probe tenant sees no row in {probed} tables ({how}){large}")


def check_audit_append_only(
    triggers: Dict[str, bool], privileges: Dict[str, bool], role: RoleAttributes, settings: Settings
) -> CheckResult:
    off = [name for name in AUDIT_TRIGGERS if not triggers.get(name)]
    if off:
        return _result("audit_append_only", False, f"audit_log triggers missing or disabled: {', '.join(off)}")
    if role.can_bypass_rls:
        if _single_role(settings):
            return _result("audit_append_only", None, "triggers in place; " + SINGLE_ROLE)
        return _result("audit_append_only", False, f"{role.name!r} can bypass the audit_log triggers")
    held = [p for p, on in privileges.items() if on]
    if held:
        return _result("audit_append_only", False, f"the runtime role holds {', '.join(held)} on audit_log")
    return _result("audit_append_only", True, "the runtime role may only SELECT and INSERT audit_log; triggers enabled")


async def database_checks(db: Database, settings: Settings) -> List[CheckResult]:
    """The catalog, grant and isolation checks, in one read-only transaction of the probe tenant."""
    if not await schema_is_current(db):
        detail = "the database schema is not at this release's head; run `lg-sotf migrate`"
        return [_result(name, False, detail) for name in DATABASE_CHECKS]
    async with db.tenant_tx(PROBE_TENANT, readonly=True) as conn:
        tables = await tenant_table_security(conn)
        role = await current_role_attributes(conn)
        triggers = await audit_triggers(conn)
        privileges = await privileges_on(conn, "audit_log", MUTATING_PRIVILEGES)
        readable = [t for t in tables if t.readable and not t.partition]
        probed = [t.name for t in readable if t.estimated_rows < PROBE_MAX_ROWS]
        bypass = False if role.can_bypass_rls else await bypass_honoured(conn)
        leaked = await tables_with_visible_rows(conn, probed)
    return [
        check_rls_catalog(tables),
        check_runtime_role(role, settings),
        check_rls_probe(leaked, len(probed), len(readable) - len(probed), role, bypass),
        check_audit_append_only(triggers, privileges, role, settings),
    ]


async def run_checks(settings: Settings, *, db: Optional[Database] = None) -> List[CheckResult]:
    """Every runtime check, ordered by invariant. ``db`` defaults to a one-connection pool on ``database.url``."""
    results = [check(settings) for check in SETTINGS_CHECKS]
    database = db or Database(settings.database, application_name="lg-sotf-verify-invariants", min_size=0, max_size=1)
    if db is None:
        await database.open()
    try:
        results += await database_checks(database, settings)
    finally:
        if db is None:
            await database.close()
    order = list(CHECKS)
    return sorted(results, key=lambda r: (r.invariant, order.index(r.check)))
