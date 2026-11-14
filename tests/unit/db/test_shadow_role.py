"""The shadow role's settings, grants and safety check (AI-E1.5c); the database side is in tests/integration/db."""

from __future__ import annotations

from typing import Any, Callable, List, Tuple

import pytest

from lg_sotf.db.migrate import RUNTIME_TABLE_PRIVILEGES, SHADOW_TABLES, shadow_grant_statements
from lg_sotf.db.pool import Database
from lg_sotf.db.shadow_role import shadow_dsn, shadow_role_configured, unsafe_role_reasons
from lg_sotf.llm.endpoint import candidate_llm_host
from lg_sotf.llm.errors import LLMUnavailable
from lg_sotf.runtime import ops
from lg_sotf.security.shadow import ShadowEgressRefused, ShadowRun, shadow_scope
from lg_sotf.settings import DatabaseSettings, Settings

pytestmark = pytest.mark.unit


def test_shadow_role_configured(make_settings: Callable[..., Settings]) -> None:
    assert not shadow_role_configured(make_settings())
    assert not shadow_role_configured(make_settings(database={"shadow_url": "  "}))
    configured = make_settings(database={"shadow_url": "postgresql://lgsotf_shadow:x@db/lgsotf"})
    assert shadow_role_configured(configured)
    assert shadow_dsn(configured.database) == "postgresql://lgsotf_shadow:x@db/lgsotf"
    assert make_settings().database.shadow_pool_max == 4
    with pytest.raises(ValueError):
        make_settings(database={"shadow_pool_max": 0})


def test_unsafe_role_reasons() -> None:
    assert unsafe_role_reasons((False, False, False, [], []), "r") == []
    assert unsafe_role_reasons(None, "r") == ["database role 'r' does not exist"]
    assert unsafe_role_reasons((True, True, True, ["alerts", "lgsotf_create_tenant"], ["lgsotf_owner"]), "r") == [
        "is a superuser",
        "has BYPASSRLS",
        "is a member of the schema owner",
        "may write to alerts, lgsotf_create_tenant",
        "is a member of lgsotf_owner",
    ]
    # Review of #323: a member of any other role could SET ROLE into it, whatever that role may do today.
    assert unsafe_role_reasons((False, False, False, [], ["pg_read_all_data"]), "r") == [
        "is a member of pg_read_all_data"
    ]


def test_shadow_grants_are_select_only_and_skip_the_credentials() -> None:
    text = [str(s.as_string(None)) for s in shadow_grant_statements("lgsotf_shadow")]  # type: ignore[arg-type]
    assert text[:4] == [
        'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "lgsotf_shadow"',
        'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "lgsotf_shadow"',
        'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM "lgsotf_shadow"',
        'GRANT USAGE ON SCHEMA public TO "lgsotf_shadow"',
    ]
    grants = text[4:]
    assert all(g.startswith("GRANT SELECT ON TABLE ") for g in grants) and len(grants) == len(SHADOW_TABLES)
    assert set(SHADOW_TABLES) == set(RUNTIME_TABLE_PRIVILEGES) - {"users", "user_mfa", "refresh_tokens", "api_keys"}
    assert {"alerts", "tenants", "shadow_effects"} <= set(SHADOW_TABLES)


async def test_a_shadow_transaction_without_the_shadow_pool_is_refused() -> None:
    db = Database(DatabaseSettings(shadow_url="postgresql://lgsotf_shadow:x@db/x"))  # type: ignore[arg-type]
    with shadow_scope(ShadowRun("shadow/unit")) as run:
        with pytest.raises(ShadowEgressRefused):
            async with db.tenant_tx("tenant-a"):
                pass
        with pytest.raises(ShadowEgressRefused):
            await db.open_shadow()  # never opened inside a run
    assert [e.outcome for e in run.sink.effects] == ["refused", "refused"]


async def test_migrate_grants_the_shadow_role(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    s = make_settings(database={"migration_url": "postgresql://own:y@h/db", "shadow_role": "lgsotf_shadow"})
    granted: List[Tuple[str, str]] = []

    class Stop(Exception):
        pass

    async def nothing(*args: Any) -> None:
        return None

    async def stop(self: Database) -> None:
        raise Stop

    monkeypatch.setattr(ops, "upgrade_head", lambda url, database: None)
    monkeypatch.setattr(ops, "setup_checkpointer", nothing)
    monkeypatch.setattr(ops, "grant_shadow_privileges", lambda role, url, database: granted.append((role, url)))
    monkeypatch.setattr(Database, "open", stop)
    with pytest.raises(Stop):
        await ops.migrate(s)
    assert granted == [("lgsotf_shadow", "postgresql://own:y@h/db")]

    # Review of #323: a missing or unsafe role is an operator error with its fix, not a traceback.
    def refuse(role: str, url: str, database: Any) -> None:
        raise ValueError(f"shadow role {role!r} must be SELECT-only, but it database role {role!r} does not exist")

    monkeypatch.setattr(ops, "grant_shadow_privileges", refuse)
    with pytest.raises(ops.OperationError, match="schema is up to date.*does not exist.*lg-sotf migrate"):
        await ops.migrate(s)


def test_a_shadow_candidate_calls_only_production_s_llm_host_or_an_allowed_one(
    make_settings: Callable[..., Settings],
) -> None:
    """#315 review F6: an explicit allow-list of candidate LLM hosts, read from production's settings only."""
    production = make_settings(
        llm={"provider": "anthropic", "api_key": "k"},
        security={"shadow_candidate_llm_hosts": ["LLM-GW.example.com", "*.vllm.internal"]},
    )
    same = make_settings(llm={"provider": "anthropic", "api_key": "k2", "deep": {"model": "claude-haiku-4-5"}})
    assert candidate_llm_host(production, same) == "api.anthropic.com"
    assert candidate_llm_host(production, make_settings(llm={"provider": "fake", "allow_fake": True})) == ""
    listed = make_settings(llm={"provider": "openai_compatible", "base_url": "https://llm-gw.example.com/v1"})
    assert candidate_llm_host(production, listed) == "llm-gw.example.com"
    wildcard = make_settings(llm={"provider": "openai_compatible", "base_url": "http://a.vllm.internal:8000/v1"})
    assert candidate_llm_host(production, wildcard) == "a.vllm.internal"
    other = make_settings(
        llm={"provider": "openai", "api_key": "k"},
        security={"shadow_candidate_llm_hosts": ["api.openai.com"]},  # the candidate's own list does not count
    )
    with pytest.raises(LLMUnavailable, match="shadow_candidate_llm_hosts"):
        candidate_llm_host(production, other)
