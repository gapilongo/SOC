"""Database helpers that need no server: tenancy, cursors, URLs, SSL and partition math."""

from __future__ import annotations

import ssl
from datetime import UTC, date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from lg_sotf.db.errors import InvalidCursor, InvalidTenantId
from lg_sotf.db.pagination import (
    Page,
    check_limit,
    decode_cursor,
    decode_cursor_bigint,
    decode_cursor_text,
    decode_cursor_uuid,
    decode_text_cursor,
    encode_cursor,
    encode_text_cursor,
    escape_like,
    paginate,
)
from lg_sotf.db.partitions import (
    add_months,
    create_partition_sql,
    month_start,
    parse_partition_name,
    partition_bounds,
    partition_name,
)
from lg_sotf.db.pool import build_ssl_arg, json_dumps, sanitize_text
from lg_sotf.db.repos.actions import ACTION_TRANSITIONS
from lg_sotf.db.repos.alerts import ALERT_STATUSES, ALERT_TRANSITIONS
from lg_sotf.db.tenancy import is_valid_tenant_id, parse_thread_id, thread_id_for, validate_tenant_id
from lg_sotf.db.urls import redact_url, to_libpq_url, to_sqlalchemy_url, with_query_params


class TestTenancy:
    @pytest.mark.parametrize("good", ["default", "acme", "a1", "tenant-b", "t_2", "0abc", "a" * 63])
    def test_valid(self, good: str) -> None:
        assert validate_tenant_id(good) == good and is_valid_tenant_id(good)

    @pytest.mark.parametrize("bad", ["", "a", "A1", "-x", "_x", "a b", "a" * 64, "t'--", None, 5])
    def test_invalid(self, bad: object) -> None:
        assert not is_valid_tenant_id(bad)
        with pytest.raises(InvalidTenantId):
            validate_tenant_id(bad)

    def test_thread_ids(self) -> None:
        assert thread_id_for("acme", "a:1") == "acme:a:1"
        assert parse_thread_id("acme:a:1") == ("acme", "a:1")
        with pytest.raises(ValueError):
            parse_thread_id("acme")
        with pytest.raises(InvalidTenantId):
            thread_id_for("BAD", "x")


class TestCursors:
    def test_round_trip(self) -> None:
        ts = datetime(2026, 9, 1, 12, 0, 0, 123456, tzinfo=UTC)
        assert decode_cursor(encode_cursor(ts, "abc")) == (ts, "abc")
        assert decode_cursor(encode_cursor(ts, 42)) == (ts, 42)
        local = ts.astimezone(timezone(timedelta(hours=5)))
        assert decode_cursor(encode_cursor(local, "k"))[0] == ts

    @pytest.mark.parametrize("bad", ["", "!!!", "e30", "eyJ2IjoxfQ", "x" * 600])
    def test_malformed(self, bad: str) -> None:
        with pytest.raises(InvalidCursor):
            decode_cursor(bad)

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_cursor(datetime(2026, 1, 1), "k")

    def test_paginate_and_limits(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        rows = [(ts, str(i)) for i in range(4)]
        page = paginate(rows, 3, lambda r: r)
        items, cursor = page
        assert items == rows[:3] and decode_cursor(cursor) == (ts, "2")
        assert paginate(rows, 4, lambda r: r) == Page(items=rows, next_cursor=None)
        for bad in (0, 501, True, "10"):
            with pytest.raises(ValueError):
                check_limit(bad)  # type: ignore[arg-type]

    def test_typed_keys(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        key = uuid4()
        assert decode_cursor_bigint(encode_cursor(ts, 2**63 - 1)) == (ts, 2**63 - 1)
        assert decode_cursor_uuid(encode_cursor(ts, str(key))) == (ts, key)
        assert decode_cursor_text(encode_cursor(ts, "a-1")) == (ts, "a-1")
        for bad in (2**63, -(2**63) - 1, "12"):
            with pytest.raises(InvalidCursor):
                decode_cursor_bigint(encode_cursor(ts, bad))
        for bad in ("not-a-uuid", 12):
            with pytest.raises(InvalidCursor):
                decode_cursor_uuid(encode_cursor(ts, bad))
        for bad in (12, "", "x" * 257, "a\x00"):
            with pytest.raises(InvalidCursor):
                decode_cursor_text(encode_cursor(ts, bad))

    def test_text_keyset(self) -> None:
        email = "a" * 64 + "@" + "b" * 255
        key = str(uuid4())
        assert decode_text_cursor(encode_text_cursor(email, key)) == (email, key)
        timestamped = encode_cursor(datetime(2026, 1, 1, tzinfo=UTC), key)
        for bad in (encode_text_cursor("", key), encode_text_cursor(email + "c", key), encode_text_cursor("a\x00", key),
                    encode_text_cursor(email, ""), timestamped, "x" * 1_100):
            with pytest.raises(InvalidCursor):
                decode_text_cursor(bad)

    def test_escape_like(self) -> None:
        assert escape_like("50%_off\\") == "50\\%\\_off\\\\"


class TestUrlsAndSsl:
    def test_url_conversion(self) -> None:
        assert to_libpq_url("postgres://u:p@h/db") == "postgresql://u:p@h/db"
        assert to_libpq_url("postgresql+asyncpg://u:p@h/db") == "postgresql://u:p@h/db"
        assert to_sqlalchemy_url("postgresql://u:p@h:5432/db") == "postgresql+psycopg://u:p@h:5432/db"
        with pytest.raises(ValueError):
            to_libpq_url("mysql://u@h/db")
        with pytest.raises(ValueError):
            to_libpq_url("not a url")

    def test_query_params_and_redaction(self) -> None:
        url = with_query_params("postgresql://u:p@h/db?sslmode=disable", {"sslmode": "require", "sslrootcert": "/ca"})
        assert "sslmode=disable" in url and "sslrootcert=%2Fca" in url
        forced = with_query_params(
            "postgresql://u:p@h/db?sslmode=disable", {"sslmode": "verify-full", "sslrootcert": None}, override=True
        )
        assert "sslmode=verify-full" in forced and "disable" not in forced
        assert with_query_params("postgresql://h/db", {"sslmode": None}) == "postgresql://h/db"
        assert redact_url("postgresql://soc:s3cret@h:5432/db") == "postgresql://soc:***@h:5432/db"
        assert redact_url("postgresql://h/db") == "postgresql://h/db"
        leaky = "postgresql://soc@db:5432/soc?password=hunter2&sslmode=require&sslpassword=k3y&PassFile=/p"
        redacted = redact_url(leaky)
        assert "hunter2" not in redacted and "k3y" not in redacted and "/p" not in redacted
        assert "password=***" in redacted and "sslmode=require" in redacted
        assert "s3cret" not in redact_url("postgresql://u:s3cret@h/db?password=s3cret")

    def test_migration_url_follows_configured_tls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from lg_sotf.db import migrate
        from lg_sotf.settings import DatabaseSettings

        class _Settings:
            database = DatabaseSettings(ssl_mode="verify-full", ssl_root_cert="/etc/ca.pem")

        monkeypatch.setattr(migrate, "get_settings", lambda: _Settings())
        url = migrate.libpq_url("postgresql://u:p@h/db?sslmode=require&sslrootcert=/other")
        assert "sslmode=verify-full" in url and "sslrootcert=%2Fetc%2Fca.pem" in url
        assert "require" not in url and "other" not in url

    def test_ssl_modes(self) -> None:
        assert build_ssl_arg(None, None) is None
        assert build_ssl_arg("disable", None) is False
        assert build_ssl_arg("prefer", None) == "prefer"
        assert build_ssl_arg("require", None) == "require"
        ca = build_ssl_arg("verify-ca", None)
        assert isinstance(ca, ssl.SSLContext) and not ca.check_hostname and ca.verify_mode == ssl.CERT_REQUIRED
        full = build_ssl_arg("verify-full", None)
        assert isinstance(full, ssl.SSLContext) and full.check_hostname

    def test_json_encoder(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        assert json_dumps({"t": ts, "d": date(2026, 1, 2)}) == '{"t":"2026-01-01T00:00:00+00:00","d":"2026-01-02"}'
        with pytest.raises(TypeError):
            json_dumps({"x": object()})

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("a\x00b", "a\ufffdb"),
            ("\\u0000", "\\u0000"),
            ("\\\x00", "\\\ufffd"),
            ("\x00\x00", "\ufffd\ufffd"),
            ("x\ud800y", "x?y"),
            ("plain é", "plain é"),
        ],
    )
    def test_json_encoder_makes_text_storable(self, value: str, expected: str) -> None:
        import json

        assert json.loads(json_dumps({value: [value]})) == {expected: [expected]}
        assert "\\u0000" not in json_dumps(value).replace("\\\\", "")
        assert sanitize_text(value) == expected


class TestPartitionMath:
    def test_months(self) -> None:
        assert month_start(date(2026, 12, 31)) == date(2026, 12, 1)
        assert month_start(datetime(2026, 3, 31, 23, 30, tzinfo=timezone(timedelta(hours=-5)))) == date(2026, 4, 1)
        assert add_months(date(2026, 11, 1), 2) == date(2027, 1, 1)
        assert add_months(date(2026, 1, 1), -1) == date(2025, 12, 1)
        lo, hi = partition_bounds(date(2026, 12, 1))
        assert (lo, hi) == (
            datetime(2026, 12, 1, tzinfo=UTC),
            datetime(2027, 1, 1, tzinfo=UTC),
        )

    def test_names(self) -> None:
        assert partition_name("audit_log", date(2026, 2, 1)) == "audit_log_p2026_02"
        assert parse_partition_name("audit_log_p2026_02") == ("audit_log", date(2026, 2, 1))
        assert parse_partition_name("audit_log_default") is None
        with pytest.raises(ValueError):
            partition_name("alerts", date(2026, 1, 1))

    def test_partition_ddl_is_utc_and_secured(self) -> None:
        stmts = create_partition_sql("audit_log", date(2026, 2, 1))
        assert "FROM ('2026-02-01 00:00:00+00') TO ('2026-03-01 00:00:00+00')" in stmts[0]
        joined = " ".join(stmts)
        assert "FORCE ROW LEVEL SECURITY" in joined and "audit_log_no_truncate" in joined
        assert "audit_log_no_truncate" not in " ".join(create_partition_sql("alert_events", date(2026, 2, 1)))


class TestStateMachines:
    def test_alert_transitions_reference_known_statuses(self) -> None:
        for source, targets in ALERT_TRANSITIONS.items():
            assert source in ALERT_STATUSES and targets <= set(ALERT_STATUSES)
        assert set(ALERT_TRANSITIONS) == set(ALERT_STATUSES)

    def test_action_transitions(self) -> None:
        assert ACTION_TRANSITIONS["proposed"] >= {"awaiting_approval", "approved", "blocked", "dry_run"}
        assert ACTION_TRANSITIONS["awaiting_approval"] >= {"approved", "rejected"}
        assert "executing" in ACTION_TRANSITIONS["approved"]
        assert ACTION_TRANSITIONS["executing"] >= {"succeeded", "failed"}
