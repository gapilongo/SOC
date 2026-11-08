"""The runtime checks of ``lg-sotf verify-invariants``: every pass, skip and fail branch without a database."""

from __future__ import annotations

import io
import logging
from typing import Any, Callable, Dict, Iterator, List

import pytest
import structlog

from lg_sotf.db.posture import RoleAttributes, TableSecurity
from lg_sotf.domain.routing import Decision
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
    monkeypatch.setattr(checks, "decide", lambda state, t: Decision("close", "x", "benign", "rule_corroborated_benign"))
    result = check_routing_policy(make_settings())
    assert result.outcome == "fail"
    assert result.detail.split("; ") == [
        "critical alert closed on a benign verdict",
        "high alert closed on a benign verdict",
        "low alert closed on the model's verdict without rule corroboration",
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


def test_rls_probe() -> None:
    leak = check_rls_probe(["alerts"], 3, 0, APP, bypass=True)
    assert leak.outcome == "fail"
    assert leak.detail == "the probe tenant sees rows of other tenants in: alerts; app.bypass_rls is honoured for 'lgsotf_app'"
    assert check_rls_probe([], 3, 0, APP, bypass=False).detail.endswith("(even with app.bypass_rls set)")
    owner = check_rls_probe([], 3, 2, OWNER, bypass=False)
    assert owner.outcome == "pass" and "not requested" in owner.detail
    assert owner.detail.endswith("; 2 large tables not read (rls_catalog covers them)")


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
