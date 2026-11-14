from __future__ import annotations

from typing import Any

import pytest
from click.testing import CliRunner

from lg_sotf import __version__
from lg_sotf.cli import cli


@pytest.fixture
def env(settings_env: Any) -> Any:
    return settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL="postgresql://nobody:x@127.0.0.1:1/none_test",
    )


def test_version() -> None:
    result = CliRunner().invoke(cli, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_help_lists_roles_and_ops_commands() -> None:
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for name in ("api", "worker", "scheduler", "migrate", "create-admin", "enqueue", "dlq", "version"):
        assert name in result.output


def test_break_glass_credential_prints_a_credential_and_the_hash_that_verifies_it() -> None:
    from lg_sotf.security.hashing import verify_password

    result = CliRunner().invoke(cli, ["break-glass-credential"])
    assert result.exit_code == 0
    first, second = result.output.strip().splitlines()
    credential = first.rpartition(": ")[2]
    name, _, stored = second.partition("=")
    assert name == "LG_SOTF_AUTH__BREAK_GLASS_CREDENTIAL_HASH" and len(credential) >= 43
    assert verify_password(stored.strip("'"), credential)


def test_create_admin_rejects_short_password_before_touching_db(env: Any) -> None:
    result = CliRunner().invoke(
        cli, ["create-admin", "--tenant", "default", "--email", "a@example.com", "--password-stdin"], input="short\n"
    )
    assert result.exit_code != 0
    assert "at least" in result.output


def test_create_admin_requires_password_on_stdin(env: Any) -> None:
    result = CliRunner().invoke(
        cli, ["create-admin", "--tenant", "default", "--email", "a@example.com", "--password-stdin"], input=""
    )
    assert result.exit_code != 0
    assert "no password" in result.output


def test_unsafe_production_config_refuses_to_start(settings_env: Any) -> None:
    settings_env(LG_SOTF_ENVIRONMENT="production", LG_SOTF_LLM__PROVIDER="fake")
    result = CliRunner().invoke(cli, ["migrate"])
    assert result.exit_code != 0
    assert "Unsafe production configuration" in result.output


def test_database_unavailable_is_a_clean_error(env: Any) -> None:
    result = CliRunner().invoke(cli, ["enqueue", "--tenant", "tenant-a", "--alert", "a1"])
    assert result.exit_code != 0
    assert "database unavailable" in result.output
    assert "Traceback" not in result.output
