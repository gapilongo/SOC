"""The runtime checks of ``lg-sotf verify-invariants``: every pass, skip and fail branch without a database."""

from __future__ import annotations

import io
import logging
from typing import Any, Callable, Dict, Iterator, List

import pytest
import structlog
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.db.posture import RoleAttributes, TableSecurity
from lg_sotf.domain.routing import Decision, RoutingThresholds, decide, route_after_triage
from lg_sotf.invariants import checks
from lg_sotf.invariants.checks import (
    CHECKS,
    DATABASE_CHECKS,
    check_audit_append_only,
    check_evidence_seal,
    check_kill_switch,
    check_log_redaction,
    check_rls_catalog,
    check_rls_probe,
    check_routing_policy,
    check_runtime_role,
    probe_plan,
    run_checks,
)
from lg_sotf.observability.logging import clear_context, configure_logging
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit

APP = RoleAttributes("lgsotf_app", superuser=False, bypassrls=False, owner_member=False)
OWNER = RoleAttributes("soc", superuser=False, bypassrls=False, owner_member=True)
TWO_ROLE = {"runtime_role": "lgsotf_app", "migration_url": "postgresql://owner@db/x"}


def table(name: str, *, forced: bool = True, partition: bool = False) -> TableSecurity:
    return TableSecurity(name, partition=partition, rls=True, forced=forced, policy=True, readable=not partition)


CORE = [table(n) for n in ("tenants", "alerts", "audit_log", "users")] + [table("audit_log_default", partition=True)]


@pytest.fixture
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    clear_context()
    structlog.reset_defaults()
    root.handlers[:] = handlers
    root.setLevel(level)
    logging.captureWarnings(False)


# ------------------------------------------------------------------ settings and code


def test_kill_switch_on_and_off(make_settings: Callable[..., Settings]) -> None:
    on = check_kill_switch(make_settings())
    assert on.outcome == "pass" and on.detail.startswith("install kill switch on")
    off = check_kill_switch(make_settings(response={"dry_run": False, "default_autonomy": {"low": "auto"}}))
    assert off.outcome == "pass" and "off: tenants not in dry run act" in off.detail and off.detail.endswith(": low")


def test_kill_switch_fails_when_a_dry_run_tenant_would_act(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(checks.ConnectorRegistry, "forced_dry_run", lambda self, tenant: False)
    result = check_kill_switch(make_settings())
    assert result.outcome == "fail"
    assert "not routed to the dry-run connector" in result.detail and "overrides the install-wide" in result.detail


def test_routing_policy(make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch) -> None:
    assert check_routing_policy(make_settings()).outcome == "pass"
    monkeypatch.setattr(
        checks, "decide", lambda state, t, tier="off": Decision("close", "x", "benign", "model_closed")
    )
    result = check_routing_policy(make_settings())
    assert result.outcome == "fail"
    assert result.detail.split("; ") == [
        "critical alert closed on a benign verdict",
        "high alert closed on a benign verdict",
        "low alert closed on the models' verdict with model-led closure off",
        "credential access alert closed on the models' verdict",
        "alert closed on the models' verdict next to a different detection on its entities",
        "low alert closed on benign evidence despite rule evidence of a threat",
    ]


@pytest.mark.usefixtures("restore_logging")
def test_log_redaction_needs_the_configured_pipeline(make_settings: Callable[..., Settings]) -> None:
    structlog.reset_defaults()
    assert check_log_redaction(make_settings()).detail == "logging is not configured with the redaction processors"
    configure_logging(make_settings(), stream=io.StringIO())
    assert check_log_redaction(make_settings()).outcome == "pass"


def test_log_redaction_reports_each_unredacted_shape(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(checks, "redact_text", lambda text: (text, 0))
    monkeypatch.setattr(checks, "redact", lambda obj: (obj, 0))
    problems = [p for p in check_log_redaction(make_settings()).detail.split("; ") if not p.startswith("logging ")]
    assert problems == [
        "a connection string is not redacted",
        "a password field is not redacted",
        "a bearer token is not redacted",
        "a GitHub token is not redacted",
        "an AWS access key is not redacted",
        "a 'password' field is not masked",
    ]


def test_synthetic_secrets_are_fresh_and_recognised() -> None:
    first, second = checks._synthetic_secrets(), checks._synthetic_secrets()
    assert all(secret in text for _, text, secret in first)
    assert {s for _, _, s in first}.isdisjoint({s for _, _, s in second})


def test_evidence_seal_signed_and_unsigned(make_settings: Callable[..., Settings]) -> None:
    signed = check_evidence_seal(make_settings())
    assert signed.outcome == "pass" and signed.detail.endswith("signed (HMAC-SHA256)")
    unsigned = check_evidence_seal(make_settings(security={"indicator_hmac_key": None}))
    assert unsigned.outcome == "pass" and "unsigned: security.indicator_hmac_key is not set" in unsigned.detail


def test_evidence_seal_fails_when_verification_is_broken(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(checks, "verify", lambda document, key: _Always())
    result = check_evidence_seal(make_settings())
    assert result.outcome == "fail" and result.detail == "a changed pack still verifies"
    monkeypatch.setattr(checks, "verify", lambda document, key: _Always(digest_ok=False, signature="invalid"))
    assert check_evidence_seal(make_settings()).detail.startswith("a freshly sealed pack does not verify (invalid)")


class _Always:
    def __init__(self, digest_ok: bool = True, signature: str = "valid") -> None:
        self.digest_ok, self.signature = digest_ok, signature
        self.signed_ok = digest_ok and signature == "valid"


# ------------------------------------------------------------------ database checks (pure parts)


def test_rls_catalog() -> None:
    ok = check_rls_catalog(CORE)
    assert ok.outcome == "pass" and ok.detail == "5 tenant tables (1 partitions) under forced RLS"
    weak = check_rls_catalog([*CORE[1:], table("tenants", forced=False)])
    assert weak.outcome == "fail" and weak.detail == "without forced RLS and a policy: tenants"
    empty = check_rls_catalog([])
    assert empty.detail == "tables not found: alerts, audit_log, tenants, users"


def test_runtime_role(make_settings: Callable[..., Settings]) -> None:
    assert check_runtime_role(APP, make_settings()).outcome == "pass"
    single = check_runtime_role(OWNER, make_settings())
    assert single.outcome == "skip" and single.detail.startswith("single-role install")
    flagged = RoleAttributes("root", superuser=True, bypassrls=True, owner_member=False)
    result = check_runtime_role(flagged, make_settings(database=TWO_ROLE))
    assert result.outcome == "fail" and result.detail.endswith("'root' is superuser, BYPASSRLS")


PLAN = checks.ProbePlan(read=("alerts", "users", "tenants"), large=0, no_statistics=0)
SUPERUSER = RoleAttributes("postgres", superuser=True, bypassrls=False, owner_member=True)


def test_rls_probe(make_settings: Callable[..., Settings]) -> None:
    single, two = make_settings(), make_settings(database=TWO_ROLE)
    leak = check_rls_probe(["alerts"], PLAN, APP, True, two)
    assert leak.outcome == "fail"
    assert leak.detail == "the probe tenant sees rows of other tenants in: alerts; app.bypass_rls is honoured for 'lgsotf_app'"
    assert check_rls_probe([], PLAN, APP, False, two).detail.endswith("3 tables (even with app.bypass_rls set)")
    unread = checks.ProbePlan(read=("tenants",), large=2, no_statistics=1)
    owner = check_rls_probe([], unread, OWNER, False, single)
    assert owner.outcome == "pass" and "not requested" in owner.detail
    assert owner.detail.endswith(
        "; 2 large tables not read, 1 tables without statistics (never analyzed) not read (rls_catalog covers them)"
    )
    assert check_rls_probe(["alerts"], PLAN, OWNER, False, single).outcome == "fail"


def test_a_role_that_ignores_rls_skips_the_probe_only_on_a_single_role_install(
    make_settings: Callable[..., Settings],
) -> None:
    single = check_rls_probe([], PLAN, SUPERUSER, False, make_settings())
    assert single.outcome == "skip" and single.detail.startswith("'postgres' is a superuser or has BYPASSRLS; single-role")
    for role in (SUPERUSER, OWNER):
        split = check_rls_probe([], PLAN, role, False, make_settings(database=TWO_ROLE))
        assert split.outcome == "fail" and split.detail.endswith("can bypass RLS; the probe proves nothing"), role


def test_probe_plan_reads_only_small_tables_and_unanalyzed_tiny_ones() -> None:
    def t(name: str, rows: Any, size: int = 8192, **kw: Any) -> TableSecurity:
        base = {"partition": False, "rls": True, "forced": True, "policy": True, "readable": True, **kw}
        return TableSecurity(name, estimated_rows=rows, size_bytes=size, **base)

    plan = probe_plan([
        t("small", 10),
        t("big", checks.PROBE_MAX_ROWS),
        t("fresh", None),
        t("loaded_never_analyzed", None, size=checks.PROBE_UNKNOWN_MAX_BYTES + 1),
        t("alerts_p2026_11", 5, partition=True, readable=False),
        t("no_select", 5, readable=False),
    ])
    assert plan == checks.ProbePlan(read=("small", "fresh"), large=1, no_statistics=1)


def test_the_synthetic_routing_states_are_ones_the_policy_would_otherwise_close() -> None:
    """Guards check_routing_policy against passing vacuously: the same benign states close at low severity (with
    evidence at any tier; without it, through a model-led close at auto_full_audit when no never-close class)."""
    t = RoutingThresholds()
    low = checks._benign_state("low")
    assert route_after_triage(low, t) == "close" and decide(low, t).route == "close"
    assert decide(checks._benign_state("high"), t, "auto_full_audit").code == "false_positive_review"
    assert decide(checks._benign_state("low", evidence=False), t, "auto_full_audit").code == "model_closed"
    credential = checks._benign_state("low", evidence=False, tactic="Credential Access")
    assert decide(credential, t, "auto_full_audit").code == "false_positive_review"
    repeats = checks._benign_state("low", evidence=False)
    repeats["correlation"] = {"related_count": 1, "related_rule_repeats": 1, "related_complete": True,
                             "related_threats": 0, "related_dispositions": {"benign": 1}}
    assert decide(repeats, t, "auto_full_audit").code == "model_closed"  # the same rule repeating closes
    repeats["correlation"]["related_rule_repeats"] = 0
    assert decide(repeats, t, "auto_full_audit").code == "false_positive_review"
    corroborated = checks._benign_state("low")
    corroborated["analysis"].update(rule_corroborated=True)
    assert decide(corroborated, t).code == "false_positive_review"


def test_audit_append_only(make_settings: Callable[..., Settings]) -> None:
    triggers = dict.fromkeys(("audit_log_immutable", "audit_log_no_truncate"), True)
    none_held = dict.fromkeys(checks.MUTATING_PRIVILEGES, False)
    single, two = make_settings(), make_settings(database=TWO_ROLE)
    assert check_audit_append_only(triggers, none_held, APP, two).outcome == "pass"
    off = check_audit_append_only({**triggers, "audit_log_no_truncate": False}, none_held, APP, two)
    assert off.detail == "audit_log triggers missing or disabled: audit_log_no_truncate"
    assert check_audit_append_only(triggers, none_held, OWNER, single).outcome == "skip"
    assert check_audit_append_only(triggers, none_held, OWNER, two).detail == "'soc' can bypass the audit_log triggers"
    held = check_audit_append_only(triggers, {**none_held, "DELETE": True}, APP, two)
    assert held.outcome == "fail" and held.detail == "the runtime role holds DELETE on audit_log"


class _FakeDb:
    opened: List[str] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def open(self) -> None:
        self.opened.append("open")

    async def close(self) -> None:
        self.opened.append("close")


async def test_an_unmigrated_database_fails_every_database_check(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def not_current(db: Any) -> bool:
        return False

    monkeypatch.setattr(checks, "Database", _FakeDb)
    monkeypatch.setattr(checks, "schema_is_current", not_current)
    results = await run_checks(make_settings())
    assert _FakeDb.opened == ["open", "close"]
    assert [r.check for r in results] == list(CHECKS)
    by_check: Dict[str, Any] = {r.check: r for r in results}
    for name in DATABASE_CHECKS:
        assert by_check[name].outcome == "fail" and "run `lg-sotf migrate`" in by_check[name].detail


async def test_an_unreachable_database_fails_the_database_checks(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(database={"url": "postgresql://nobody@127.0.0.1:1/none", "command_timeout_s": 2.0})
    results = {r.check: r for r in await run_checks(settings)}
    for name in DATABASE_CHECKS:
        assert results[name].outcome == "fail" and results[name].detail.startswith("database unavailable"), name
    assert results["kill_switch"].outcome == "pass"


def test_verify_invariants_exits_1_without_a_traceback_when_the_database_is_down(
    settings_env: Callable[..., Settings],
) -> None:
    settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL="postgresql://nobody@127.0.0.1:1/none",
    )
    result = CliRunner().invoke(cli, ["verify-invariants"])
    assert result.exit_code == 1 and isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    failed = [line.split()[2] for line in result.stdout.splitlines() if line.startswith("FAIL")]
    assert failed == ["rls_catalog", "runtime_role", "rls_probe", "audit_append_only"]
