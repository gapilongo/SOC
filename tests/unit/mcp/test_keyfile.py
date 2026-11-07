"""``LG_SOTF_MCP__API_KEY_FILE``: the key read from a file only its owner can read or write."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.mcp.client import ApiConfigError
from lg_sotf.mcp.command import MAX_KEY_FILE_BYTES, read_api_key_file, resolve_api_key
from lg_sotf.settings import MCPSettings, Settings
from tests.unit.mcp._support import fake_key

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")


def _key_file(tmp_path: Path, content: str, mode: int = 0o600) -> Path:
    path = tmp_path / "qa-01.key"
    path.write_text(content)
    path.chmod(mode)
    return path


def _settings(**mcp: Any) -> Settings:
    return Settings(_env_file=None, mcp=MCPSettings(**mcp))


@pytest.mark.parametrize("mode", [0o600, 0o400, 0o700, 0o710], ids=oct)
def test_owner_only_key_file_is_read_without_the_newline(tmp_path: Path, mode: int) -> None:
    key = fake_key()
    assert read_api_key_file(str(_key_file(tmp_path, key + "\n", mode))) == key


# Readable: another user could take the key. Writable: another user could swap in a key of their own tenant,
# so notes and test alerts would land there and every alert the model reads would be theirs.
@pytest.mark.parametrize("mode", [0o640, 0o644, 0o604, 0o660, 0o666, 0o620, 0o602, 0o622, 0o420], ids=oct)
def test_key_file_its_group_or_other_users_can_read_or_write_is_refused(tmp_path: Path, mode: int) -> None:
    key = fake_key()
    path = _key_file(tmp_path, key, mode)
    with pytest.raises(ApiConfigError) as caught:
        read_api_key_file(str(path))
    message = str(caught.value)
    assert "readable or writable by its group or by other users" in message and f"chmod 600 {path}" in message
    assert key not in message


def test_key_file_path_expands_the_home_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = fake_key()
    _key_file(tmp_path, key)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert read_api_key_file("~/qa-01.key") == key


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("", "is empty"),
        ("  \n", "is empty"),
        ("first second", "must contain the API key only"),
        ("x" * (MAX_KEY_FILE_BYTES + 1), "is larger than"),
    ],
)
def test_malformed_key_files_are_refused(tmp_path: Path, content: str, expected: str) -> None:
    with pytest.raises(ApiConfigError, match=expected):
        read_api_key_file(str(_key_file(tmp_path, content)))


def test_key_file_saved_with_a_byte_order_mark_is_read(tmp_path: Path) -> None:
    """PowerShell 5.1 ``Set-Content -Encoding UTF8`` and Notepad's "UTF-8 with BOM" start the file with U+FEFF."""
    key = fake_key()
    path = tmp_path / "bom.key"
    path.write_bytes(b"\xef\xbb\xbf" + key.encode() + b"\r\n")
    path.chmod(0o600)
    assert read_api_key_file(str(path)) == key


@pytest.mark.parametrize(
    ("before", "after"),
    [("", "\u200b"), ("\x00", ""), ("\u201c", "\u201d"), ("", "\x1b"), ("\ufeff", "")],
    ids=["zero-width", "nul", "smart-quotes", "escape", "second-bom"],
)
def test_key_file_with_a_character_no_key_holds_is_refused_naming_the_file(
    tmp_path: Path, before: str, after: str
) -> None:
    key = fake_key()
    path = tmp_path / "odd.key"
    path.write_bytes(b"\xef\xbb\xbf" + (before + key + after).encode())
    path.chmod(0o600)
    with pytest.raises(ApiConfigError) as caught:
        read_api_key_file(str(path))
    message = str(caught.value)
    assert message.startswith(f"LG_SOTF_MCP__API_KEY_FILE: {path} ") and "characters" in message
    assert key not in message


def test_binary_key_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "bin.key"
    path.write_bytes(b"\xff\xfe\x00key")
    path.chmod(0o600)
    with pytest.raises(ApiConfigError, match="not UTF-8"):
        read_api_key_file(str(path))


def test_missing_file_and_directory_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ApiConfigError, match="does not exist"):
        read_api_key_file(str(tmp_path / "nope.key"))
    folder = tmp_path / "dir"
    folder.mkdir(mode=0o700)
    with pytest.raises(ApiConfigError, match="not a regular file"):
        read_api_key_file(str(folder))


@pytest.mark.parametrize("value", ["{key}", " {key}\n", "~/{key}", "/run/secrets/{key}"], ids=repr)
def test_a_key_pasted_in_place_of_the_path_is_refused_without_echoing_it(tmp_path: Path, value: str) -> None:
    """Mixing up LG_SOTF_MCP__API_KEY and _FILE: the error reaches the MCP client's log, never the key."""
    key = fake_key()
    with pytest.raises(ApiConfigError) as caught:
        read_api_key_file(value.format(key=key))
    message = str(caught.value)
    assert message.startswith("LG_SOTF_MCP__API_KEY_FILE holds an API key, not a file path") and key not in message
    assert key[4:36] not in message and key[37:] not in message


def test_command_refuses_a_key_in_the_key_file_variable_without_echoing_it(settings_env: Any) -> None:
    key = fake_key()
    settings_env(LG_SOTF_MCP__API_KEY=None, LG_SOTF_MCP__API_KEY_FILE=key, LG_SOTF_MCP__API_URL="https://soc.example.com")
    result = CliRunner().invoke(cli, ["mcp"], input="")
    assert result.exit_code == 2 and "holds an API key, not a file path" in result.output
    assert key not in result.output and key[37:] not in result.output


def test_resolve_prefers_neither_source_when_both_are_set(tmp_path: Path) -> None:
    key = fake_key()
    path = _key_file(tmp_path, key)
    with pytest.raises(ApiConfigError, match="not both"):
        resolve_api_key(_settings(api_key=key, api_key_file=str(path)))
    assert resolve_api_key(_settings(api_key_file=str(path))) == key
    assert resolve_api_key(_settings(api_key=key)) == key
    with pytest.raises(ApiConfigError) as caught:
        resolve_api_key(_settings())
    assert "LG_SOTF_MCP__API_KEY is not set" in str(caught.value) and "LG_SOTF_MCP__API_KEY_FILE" in str(caught.value)


def test_command_refuses_a_readable_key_file_with_exit_code_2(settings_env: Any, tmp_path: Path) -> None:
    key = fake_key()
    path = _key_file(tmp_path, key, 0o644)
    settings_env(LG_SOTF_MCP__API_KEY=None, LG_SOTF_MCP__API_KEY_FILE=str(path),
                 LG_SOTF_MCP__API_URL="https://soc.example.com")
    result = CliRunner().invoke(cli, ["mcp"], input="")
    assert result.exit_code == 2 and "chmod 600" in result.output and key not in result.output


def test_command_takes_the_key_from_the_file(settings_env: Any, tmp_path: Path) -> None:
    key = fake_key()
    path = _key_file(tmp_path, key)
    # The key file is accepted; the plain-http remote URL is then refused (exit 2), before any connection.
    settings_env(LG_SOTF_MCP__API_KEY=None, LG_SOTF_MCP__API_KEY_FILE=str(path),
                 LG_SOTF_MCP__API_URL="http://soc.example.com")
    result = CliRunner().invoke(cli, ["mcp"], input="")
    assert result.exit_code == 2 and "https" in result.output and key not in result.output


def test_command_refuses_both_variables(settings_env: Any, tmp_path: Path) -> None:
    key = fake_key()
    path = _key_file(tmp_path, key)
    settings_env(LG_SOTF_MCP__API_KEY=key, LG_SOTF_MCP__API_KEY_FILE=str(path),
                 LG_SOTF_MCP__API_URL="https://soc.example.com")
    result = CliRunner().invoke(cli, ["mcp"], input="")
    assert result.exit_code == 2 and "not both" in result.output and key not in result.output


def test_help_names_the_key_file_variable() -> None:
    result = CliRunner().invoke(cli, ["mcp", "--help"])
    assert result.exit_code == 0 and "LG_SOTF_MCP__API_KEY_FILE" in result.output
