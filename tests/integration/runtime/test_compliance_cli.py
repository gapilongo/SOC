"""``lg-sotf tenant-export``, ``tenant-erase`` and ``evidence-verify``."""

from __future__ import annotations

import asyncio
import json
import stat
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.compliance.evidence import build_evidence_pack
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.settings import Settings, get_settings
from tests.integration.conftest import truncate_all
from tests.integration.db._support import TENANT_A, TENANT_B, db_settings, make_alert

pytestmark = pytest.mark.integration

HOME = "acme"


async def _with_repos(url: str, fn: Callable[[Repositories], Any]) -> Any:
    db = Database(db_settings(url), application_name="lg-sotf-tests")
    await db.open()
    try:
        return await fn(Repositories.create(db))
    finally:
        await db.close()


@pytest.fixture
def cli_env(
    settings_env: Callable[..., Settings], migrated_database_url: str, redis_url: str, unique_prefix: str
) -> str:
    async def seed(repos: Repositories) -> None:
        await truncate_all(repos.db)
        for tenant_id, name in ((HOME, "Acme"), (TENANT_A, "A"), (TENANT_B, "B")):
            await repos.tenants.create(tenant_id, name)
        for tenant_id in (TENANT_A, TENANT_B):
            alert_id = await make_alert(repos, tenant_id, title=f"alert of {tenant_id}")
            await repos.alert_events.append(tenant_id, alert_id, "note", data={"text": "n"})
            await repos.audit.append(tenant_id, "system", None, "seed", "alert", alert_id)

    asyncio.run(_with_repos(migrated_database_url, seed))
    settings_env(
        LG_SOTF_ENVIRONMENT="test",
        LG_SOTF_LLM__PROVIDER="fake",
        LG_SOTF_DATABASE__URL=migrated_database_url,
        LG_SOTF_REDIS__URL=redis_url,
        LG_SOTF_REDIS__KEY_PREFIX=unique_prefix,
        LG_SOTF_AUTH__BOOTSTRAP_TENANT_ID=HOME,
        LG_SOTF_SECURITY__INDICATOR_HMAC_KEY="lg-sotf-test-suite-only-indicator-hmac-key",
    )
    return migrated_database_url


def _actions(url: str, tenant_id: str) -> List[str]:
    async def read(repos: Repositories) -> List[str]:
        return [e.action for e in (await repos.audit.list(tenant_id)).items]

    return list(asyncio.run(_with_repos(url, read)))


def test_tenant_export_writes_a_private_zip(cli_env: str, tmp_path: Path) -> None:
    runner = CliRunner()
    output = tmp_path / "b.zip"

    result = runner.invoke(cli, ["tenant-export", "--tenant", TENANT_B, "--output", str(output)])

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with zipfile.ZipFile(output) as archive:
        alerts = [json.loads(line) for line in archive.read("alerts.jsonl").splitlines()]
        manifest = json.loads(archive.read("manifest.json"))
    assert [a["title"] for a in alerts] == [f"alert of {TENANT_B}"]
    assert manifest["exported_by"] == {"actor_type": "system", "actor_id": "cli"}
    again = runner.invoke(cli, ["tenant-export", "--tenant", TENANT_B, "--output", str(output)])
    assert again.exit_code != 0 and "--force" in again.output
    assert runner.invoke(cli, ["tenant-export", "--tenant", TENANT_B, "--output", str(output), "--force"]).exit_code == 0
    assert "tenant.data_exported" in _actions(cli_env, TENANT_B)
    assert "platform.tenant_exported" in _actions(cli_env, HOME)
    missing = runner.invoke(cli, ["tenant-export", "--tenant", "nope", "--output", str(tmp_path / "n.zip")])
    assert missing.exit_code != 0 and "does not exist" in missing.output


def test_tenant_erase_needs_suspension_and_confirmation(cli_env: str) -> None:
    runner = CliRunner()
    mismatch = runner.invoke(cli, ["tenant-erase", "--tenant", TENANT_B, "--confirm", TENANT_A, "--yes"])
    assert mismatch.exit_code == 2 and "--confirm" in mismatch.output
    active = runner.invoke(cli, ["tenant-erase", "--tenant", TENANT_B, "--confirm", TENANT_B, "--yes"])
    assert active.exit_code != 0 and "suspended" in active.output

    asyncio.run(_with_repos(cli_env, lambda r: r.tenants.set_status(TENANT_B, "suspended")))
    declined = runner.invoke(cli, ["tenant-erase", "--tenant", TENANT_B, "--confirm", TENANT_B], input="n\n")
    assert declined.exit_code != 0
    erased = runner.invoke(cli, ["tenant-erase", "--tenant", TENANT_B, "--confirm", TENANT_B], input="y\n")

    assert erased.exit_code == 0, erased.output
    start = erased.output.index('{\n  "audit_entries_retained"')
    report, _ = json.JSONDecoder().raw_decode(erased.output[start:])
    assert report["deleted"] == {"alert_events": 1, "alerts": 1} and report["audit_entries_retained"] >= 2

    async def counts(repos: Repositories) -> Dict[str, int]:
        async with repos.db.system_tx() as conn:
            return {
                t: int(await conn.fetchval("SELECT count(*) FROM alerts WHERE tenant_id = $1", t))
                for t in (TENANT_A, TENANT_B)
            }

    assert asyncio.run(_with_repos(cli_env, counts)) == {TENANT_A: 1, TENANT_B: 0}
    assert {"tenant.erasure_started", "tenant.erased"} <= set(_actions(cli_env, TENANT_B))
    assert {"platform.tenant_erasure_started", "platform.tenant_erased"} <= set(_actions(cli_env, HOME))


def test_evidence_verify_checks_digest_and_signature(cli_env: str, tmp_path: Path) -> None:
    async def pack(repos: Repositories) -> Dict[str, Any]:
        alert_id = (await repos.alerts.list(TENANT_A)).items[0].id
        return await build_evidence_pack(
            repos, get_settings(), TENANT_A, alert_id, generated_by={"actor_type": "system", "actor_id": "t"}
        )

    document = asyncio.run(_with_repos(cli_env, pack))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(document), encoding="utf-8")
    runner = CliRunner()

    ok = runner.invoke(cli, ["evidence-verify", str(good)])
    assert ok.exit_code == 0, ok.output
    assert "matches" in ok.output and "signature: valid" in ok.output

    tampered = dict(document, tenant_id=TENANT_B)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(tampered), encoding="utf-8")
    result = runner.invoke(cli, ["evidence-verify", str(bad)])
    assert result.exit_code == 1 and "MISMATCH" in result.output and "signature: invalid" in result.output

    unsigned = dict(document, integrity={**document["integrity"], "signature": None})
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(unsigned), encoding="utf-8")
    assert runner.invoke(cli, ["evidence-verify", str(path)]).exit_code == 1
    assert runner.invoke(cli, ["evidence-verify", str(path), "--allow-unsigned"]).exit_code == 0
    junk = tmp_path / "junk.json"
    junk.write_text("[1, 2]", encoding="utf-8")
    assert runner.invoke(cli, ["evidence-verify", str(junk)]).exit_code == 1
