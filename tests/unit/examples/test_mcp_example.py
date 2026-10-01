"""examples/mcp/.mcp.json: the committed Claude Code entry holds no URL, no credential and a pinned release image,
and every committed ``*.mcp.json`` has a code owner."""

from __future__ import annotations

import json
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Tuple

from lg_sotf import __version__

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "examples" / "mcp" / ".mcp.json"
DOC = ROOT / "docs" / "mcp.md"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"


def _entry() -> Dict[str, Any]:
    config = json.loads(EXAMPLE.read_text())
    assert list(config) == ["mcpServers"] and list(config["mcpServers"]) == ["lg-sotf"]
    entry: Dict[str, Any] = config["mcpServers"]["lg-sotf"]
    return entry


def _options(args: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for flag, value in zip(args, args[1:], strict=False):  # neighbours: the lengths differ by one
        if flag in ("-e", "-v", "--user"):
            out.setdefault(flag, []).append(value)
    return out


def test_runs_the_pinned_release_image_over_stdio() -> None:
    entry = _entry()
    assert entry["type"] == "stdio" and entry["command"] == "docker"
    args = entry["args"]
    assert args[:3] == ["run", "-i", "--rm"] and args[-1] == "mcp"
    image = args[-2]
    assert re.fullmatch(r"ghcr\.io/gapilongo/lg-sotf:v\d+\.\d+\.\d+", image), image
    assert image.endswith(f":v{__version__}"), "the example pins the image of the current release"
    assert {"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"} <= set(args)


def test_the_key_comes_from_a_read_only_mounted_file_and_nothing_has_a_default() -> None:
    entry = _entry()
    options = _options(entry["args"])
    assert options["-e"] == ["LG_SOTF_MCP__API_URL=${LG_SOTF_MCP_URL}",
                             "LG_SOTF_MCP__API_KEY_FILE=/run/secrets/lg-sotf.key"]
    assert options["-v"] == ["${LG_SOTF_MCP_KEY_PATH}:/run/secrets/lg-sotf.key:ro"]
    assert options["--user"] == ["${LG_SOTF_MCP_UID:-1000}"]
    text = EXAMPLE.read_text()
    assert "LG_SOTF_MCP__API_KEY=" not in text and "lgk_" not in text and "env" not in entry
    assert "${LG_SOTF_MCP_URL:-" not in text and "https://" not in text  # no URL default


def test_the_docs_show_the_committed_file() -> None:
    doc = DOC.read_text()
    for line in EXAMPLE.read_text().strip().splitlines():
        assert line in doc, line


def test_the_docs_pull_the_pinned_image_before_the_first_session() -> None:
    """Claude Code gives a server MCP_TIMEOUT (30 s) to start: a first ``docker run`` that pulls the image fails."""
    image = _entry()["args"][-2]
    doc = DOC.read_text()
    docker_section = doc.split("### Claude Code (committed `.mcp.json`, docker, key file)", 1)[1].split("\n### ", 1)[0]
    assert f"docker pull {image}\n" in docker_section and "MCP_TIMEOUT" in docker_section
    troubleshooting = doc.split("\n## Troubleshooting\n", 1)[1]
    assert f"docker pull {image}" in troubleshooting and "MCP_TIMEOUT=300000" in troubleshooting


def test_the_docs_tell_windows_users_to_keep_the_key_file_in_wsl() -> None:
    """Docker Desktop shows a file bind-mounted from a Windows drive as mode 777, which no chmod changes and the
    server refuses: on Windows the entry works only from WSL 2 with the key in its Linux filesystem."""
    doc = DOC.read_text()
    docker_section = doc.split("### Claude Code (committed `.mcp.json`, docker, key file)", 1)[1].split("\n### ", 1)[0]
    windows = docker_section.split("**On Windows, run `claude` inside WSL 2**", 1)[1].split("\n\n", 1)[0]
    assert "chmod" in windows and "/mnt/c" in windows and "777" in windows and "natively on Windows" in windows
    troubleshooting = doc.split("\n## Troubleshooting\n", 1)[1]
    mode_entry = troubleshooting.split("readable or writable by its group or by other users", 1)[1].split("\n* ", 1)[0]
    mode_entry = " ".join(mode_entry.split())
    assert "Docker Desktop on Windows" in mode_entry and "WSL 2" in mode_entry and "/mnt/c" in mode_entry


def _audited(router: str) -> List[str]:
    """The audit actions a REST router records (``AuditLogger(...).record(tenant, "<action>", ...)``)."""
    text = (ROOT / "src" / "lg_sotf" / "api" / "routers" / router).read_text()
    return re.findall(r'AuditLogger\(ctx\.repos\)\.record\(\s*[\w.]+,\s*"([a-z_.]+)"', text)


def test_the_docs_claim_audit_only_for_the_writes_the_api_audits() -> None:
    """Notes and evidence exports are audited; an ingest call is not (only a quota refusal is), so test alerts are
    traced by their source id instead. If ingestion gains an audit entry, say so in docs/mcp.md."""
    assert "alert.note_added" in _audited("alerts.py") and "alert.evidence_exported" in _audited("compliance.py")
    assert _audited("ingest.py") == ["tenant.quota_exceeded"]
    bullet = " ".join(DOC.read_text().split("* **audit**:", 1)[1].split("\n\n", 1)[0].split())
    assert "notes and evidence exports are recorded in the tenant's hash-chained audit log" in bullet
    assert "test alerts are not audited" in bullet.lower() and "`api:<key id>`" in bullet and "`:<run_handle>`" in bullet


def _codeowners() -> List[Tuple[str, List[str]]]:
    rules = []
    for line in CODEOWNERS.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            pattern, *owners = line.split()
            rules.append((pattern, owners))
    return rules


def _owners(path: str) -> List[str]:
    """The owners of ``path``: the last matching rule wins, as on GitHub (only the pattern forms used here)."""
    owners: List[str] = []
    for pattern, who in _codeowners():
        if pattern.endswith("/"):
            matched = path.startswith(pattern.lstrip("/"))
        elif pattern.startswith("/"):
            matched = path == pattern[1:]
        else:
            matched = fnmatch(path.rsplit("/", 1)[-1], pattern)
        if matched:
            owners = who
    return owners


def test_codeowners_guard_every_committed_mcp_entry_and_its_pinning_test() -> None:
    """A PR that redirects testers' keys (image, URL, mounts) must get the security owner's review (threat #5)."""
    for pattern, owners in _codeowners():
        assert "/" not in pattern.strip("/") or pattern.startswith("/"), pattern  # forms _owners understands
        assert "*" not in pattern or "/" not in pattern, pattern
        assert owners and all(re.fullmatch(r"@[A-Za-z0-9-]+(/[A-Za-z0-9_.-]+)?", o) for o in owners), pattern
    for path in (
        "examples/mcp/.mcp.json",
        ".mcp.json",
        "deploy/qa/.mcp.json",
        "examples/mcp/README.md",
        "tests/unit/examples/test_mcp_example.py",
        "docs/mcp.md",
        "src/lg_sotf/mcp/server.py",
        ".github/CODEOWNERS",
    ):
        assert _owners(path), f"{path} has no code owner"
    assert not _owners("src/lg_sotf/api/app.py")  # the rules are scoped, not a catch-all
