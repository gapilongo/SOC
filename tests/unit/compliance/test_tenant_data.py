"""Tenant export helpers that need no database: secret stripping, zip streaming, keyset SQL."""

from __future__ import annotations

import io
import os
import zipfile
from typing import Any, Callable

from lg_sotf.compliance import tenant_data
from lg_sotf.compliance.tenant_data import EXPORT_TABLES, _page_sql, _Sink, strip_secrets
from lg_sotf.llm.client import get_chat_model
from lg_sotf.llm.fake import FakeChatModel
from lg_sotf.llm.provenance import merge_model_provenance, model_provenance
from lg_sotf.llm.structured import usage_model_id
from lg_sotf.settings import Settings


def test_strip_secrets_removes_ciphertexts_and_credential_values() -> None:
    marker = "cipher-" + "x" * 30
    settings = {
        "response": {"connector": "webhook", "webhook_secret_ciphertext": marker, "webhook_url": "https://soar/x"},
        "tools": {"vt": {"enabled": True, "api_key_ciphertext": marker}, "empty": {"api_key_ciphertext": ""}},
        "other": [{"password": "p-" + "y" * 20}],
    }
    out = strip_secrets(settings)
    assert marker not in repr(out) and "yyyy" not in repr(out)
    assert out["response"] == {"connector": "webhook", "webhook_secret_configured": True, "webhook_url": "https://soar/x"}
    assert out["tools"]["vt"] == {"enabled": True, "api_key_configured": True}
    assert out["tools"]["empty"] == {}


def test_users_are_exported_from_an_allow_list() -> None:
    users = next(t for t in EXPORT_TABLES if t.table == "users")
    columns = {c.strip() for c in users.columns.split(",")}
    assert "password_hash" not in columns and "*" not in columns
    assert all("*" not in t.columns for t in EXPORT_TABLES if t.table in ("users", "api_keys", "sources"))
    sources = next(t for t in EXPORT_TABLES if t.table == "sources")
    assert "secret_ciphertext IS NOT NULL" in sources.columns and "secret_ciphertext," not in sources.columns


def test_keyset_sql_uses_the_tenant_filter_and_composite_keys() -> None:
    events = next(t for t in EXPORT_TABLES if t.table == "alert_events")
    sql = _page_sql(events)
    assert "WHERE tenant_id = $1 AND ($2 OR (alert_id, ts, id) > ($3::text, $4::timestamptz, $5::bigint))" in sql
    assert sql.endswith("ORDER BY alert_id, ts, id LIMIT $6")


def test_zip_written_through_the_sink_streams_and_is_valid() -> None:
    sink = _Sink()
    drained = []
    with zipfile.ZipFile(sink, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        with archive.open("rows.jsonl", mode="w", force_zip64=True) as member:
            for i in range(2_000):
                member.write(f'{{"i": {i}, "pad": "{os.urandom(32).hex()}"}}\n'.encode())
                if sink.pending > 1_024:
                    drained.append(sink.drain())
    drained.append(sink.drain())
    assert len([c for c in drained if c]) > 1
    with zipfile.ZipFile(io.BytesIO(b"".join(drained))) as archive:
        assert len(archive.read("rows.jsonl").splitlines()) == 2_000


def test_export_filename_is_safe() -> None:
    assert tenant_data.export_filename("acme-1").startswith("lg-sotf-tenant-acme-1-")


def test_model_provenance_is_bounded_and_merged(make_settings: Callable[..., Settings]) -> None:
    model: Any = FakeChatModel(model_name="fake-" + "m" * 300)
    entry = model_provenance(model, "deep")
    assert entry["provider"] == "fake" and len(entry["model"]) == 128 and entry["tier"] == "deep"
    merged = merge_model_provenance(
        {"triage": {"provider": "anthropic", "model": "old"}, "bad": "x", "n": {"model": 5}},
        {"triage": {"provider": "fake", "model": "new", "tier": "fast"}, "analysis": entry},
    )
    assert merged["triage"] == {"provider": "fake", "model": "new", "tier": "fast"}
    assert "bad" not in merged and merged["n"] == {} and merged["analysis"] == entry
    assert merge_model_provenance(None, {}) == {}


def test_model_provenance_uses_the_usage_model_id(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"provider": "ollama", "fast": {"model": "qwen3:8b", "max_tokens": 900}})
    model = get_chat_model("fast", s)
    entry = model_provenance(model, "fast")
    assert entry == {"provider": "ollama", "model": usage_model_id(model), "tier": "fast"}
    assert entry["model"] == "local/qwen3:8b"
