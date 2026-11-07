"""Secret redaction for alert data, prompts and logs."""

from __future__ import annotations

import time
from typing import Callable

import pytest

from lg_sotf.security.redaction import REDACTED, is_secret_key, looks_high_entropy, redact, redact_text
from lg_sotf.settings import Settings


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Bearer abcdefghijklmnop.qrstu", "abcdefghijklmnop.qrstu"),
        ("curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==' https://x", "dXNlcjpwYXNzd29yZDEyMw=="),
        ("token sent as bearer eyJ0eXAiOiJKV1QiLCJhbGciOi1234567", "eyJ0eXAiOiJKV1QiLCJhbGciOi1234567"),
        ("postgresql://soc:s3cr3tP@db.internal:5432/soc", "s3cr3tP"),
        ("redis://:hunter2@cache:6379/0", "hunter2"),
        ("mongodb+srv://admin:Pa55w0rd!@cluster0.example.net/db", "Pa55w0rd!"),
        ("mysql --password=hunter2 -u root", "hunter2"),
        ("psexec.exe -password Winter2024! \\\\host cmd", "Winter2024!"),
        ("tool --api-key sk_live_abcdefghijklmnop1234", "sk_live_abcdefghijklmnop1234"),
        ("net user backdoor P@ssw0rd123 /add", "P@ssw0rd123"),
        ("$p = ConvertTo-SecureString 'Sup3rS3cret' -AsPlainText -Force", "Sup3rS3cret"),
        ("db_password=hunter2; host=x", "hunter2"),
        ('{"password": "hunter2", "user": "bob"}', "hunter2"),
        ("client_secret: 'abc123xyz'", "abc123xyz"),
        ("https://api.example.com/v1?token=abc123&x=1", "abc123"),
        ("X-Api-Key: abcdef123456", "abcdef123456"),
        ("AKIAIOSFODNN7EXAMPLE used from 1.2.3.4", "AKIAIOSFODNN7EXAMPLE"),
        ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        (
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEA"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk (truncated", "b3BlbnNzaC1rZXk"),
        ("key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("slack xoxb-123456789012-abcdefghij", "xoxb-123456789012-abcdefghij"),
        ("api key=Zx9fQ2hR7tL0pW3kM8vB", "Zx9fQ2hR7tL0pW3kM8vB"),
    ],
)
def test_secrets_are_removed(text: str, secret: str) -> None:
    redacted, count = redact_text(text)
    assert secret not in redacted
    assert count >= 1
    assert "REDACTED" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "token_type=Bearer token_count=5 password_last_set=2024-01-01",
        "net user bob /domain",
        "key=monkey registry key=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "md5 d41d8cd98f00b204e9800998ecf8427e sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Failed logon for user alice from 10.0.0.5 (Logon Type: 3)",
        "https://example.com/path?q=1",
        "process C:\\Windows\\System32\\lsass.exe accessed by mimikatz.exe",
        "guid 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    ],
)
def test_indicators_and_benign_text_are_kept(text: str) -> None:
    assert redact_text(text) == (text, 0)


def test_auth_header_counted_once() -> None:
    redacted, count = redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
    assert redacted == "Authorization: Bearer [REDACTED]"
    assert count == 1


def test_redact_is_idempotent() -> None:
    once, first = redact_text("password=hunter2 Authorization: Bearer abcdefghijklmnop postgres://u:p@h/db")
    twice, second = redact_text(once)
    assert first == 3
    assert twice == once and second == 0


def test_structured_redaction_by_key() -> None:
    event = {
        "user": "bob",
        "password": "x",
        "apiKey": "abc",
        "clientSecret": "zz",
        "Authorization": "Bearer abcdefghijklmnop",
        "registry_key": "HKLM\\SOFTWARE\\Microsoft",
        "token_type": "Bearer",
        "password_last_set": "2024-01-01",
        "has_credentials": True,
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "sig": "aB3dE5fG7hI9jK1lM3nO",
        "signature_name": "Trojan.Generic",
        "empty_password": "",
    }
    redacted, count = redact(event)
    assert redacted["password"] == REDACTED
    assert redacted["apiKey"] == REDACTED
    assert redacted["clientSecret"] == REDACTED
    assert redacted["Authorization"] == REDACTED
    assert redacted["sig"] == REDACTED
    for kept in ("user", "registry_key", "token_type", "password_last_set", "has_credentials", "file_hash", "signature_name"):
        assert redacted[kept] == event[kept]
    assert redacted["empty_password"] == ""
    assert count == 5


def test_nested_structures_and_input_untouched() -> None:
    original = {
        "events": [
            {"cmd": "mysql --password bar", "ok": 1},
            ("tuple", "Authorization: Bearer abcdefghijklmnop"),
        ],
        "meta": {"session_token": "abc", "count": 3, "ratio": 0.5, "none": None},
    }
    snapshot = repr(original)
    redacted, count = redact(original)
    assert repr(original) == snapshot
    assert redacted["events"][0]["cmd"] == "mysql --password [REDACTED]"
    assert isinstance(redacted["events"][1], tuple)
    assert redacted["events"][1][1] == "Authorization: Bearer [REDACTED]"
    assert redacted["meta"] == {"session_token": REDACTED, "count": 3, "ratio": 0.5, "none": None}
    assert count == 3


def test_key_classification() -> None:
    assert is_secret_key("db_password")
    assert is_secret_key("X-Api-Key")
    assert is_secret_key("accessToken")
    assert is_secret_key("ntlm_hash")
    assert not is_secret_key("token_expires")
    assert not is_secret_key("password_policy")
    assert not is_secret_key("key", "HKLM\\Run")
    assert is_secret_key("key", "Zx9fQ2hR7tL0pW3kM8vB")


def test_entropy_heuristic() -> None:
    assert looks_high_entropy("Zx9fQ2hR7tL0pW3kM8vB")
    assert not looks_high_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert not looks_high_entropy("short1A")
    assert not looks_high_entropy("C:\\Program Files\\App\\x.exe")


@pytest.mark.parametrize("payload", ["a." * 200_000, "x" * 1_000_000, "password=" * 50_000, "A1+/" * 100_000])
def test_large_inputs_are_linear(payload: str) -> None:
    start = time.perf_counter()
    redact_text(payload)
    assert time.perf_counter() - start < 3.0


# --------------------------------------------------------------------------
# Private keys: linear-time scan (regression: a lazy regex was quadratic)
# --------------------------------------------------------------------------


def test_many_unterminated_private_key_headers_are_linear() -> None:
    payload = "-----BEGIN PRIVATE KEY-----\n" * 8_000  # 224 KB
    start = time.perf_counter()
    redacted, count = redact({"cmdline": payload})
    assert time.perf_counter() - start < 0.5
    assert redacted == {"cmdline": "[REDACTED:private_key]"}
    assert count == 1


@pytest.mark.parametrize(
    "payload",
    [
        "-----BEGIN RSA PRIVATE KEY----- -----END " * 20_000,
        "-----BEGIN " * 50_000,
        "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 500_000,
    ],
)
def test_private_key_pathological_inputs(payload: str) -> None:
    start = time.perf_counter()
    redact_text(payload)
    assert time.perf_counter() - start < 0.5


def test_private_key_blocks_keep_surrounding_text() -> None:
    text = (
        "before -----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY----- middle "
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK----- after "
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    )
    redacted, count = redact_text(text)
    assert redacted == (
        "before [REDACTED:private_key] middle [REDACTED:private_key] after "
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    )
    assert count == 2


def test_unterminated_key_after_terminated_key_runs_to_end() -> None:
    text = "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY----- ok -----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl"
    assert redact_text(text) == ("[REDACTED:private_key] ok [REDACTED:private_key]", 2)


def test_text_beyond_scan_limit_is_not_passed_through() -> None:
    from lg_sotf.security.redaction import MAX_TEXT_CHARS

    text = "x" * MAX_TEXT_CHARS + " password=hunter2"
    redacted, count = redact_text(text)
    assert "hunter2" not in redacted
    assert redacted.endswith("[REDACTED: 17 chars beyond the redaction scan limit]")
    assert count == 1


# --------------------------------------------------------------------------
# Structural gaps (secret-labelled containers, pairs, depth, CLI forms)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"password": ["hunter2xyz"]},
        {"credentials": {"username": "bob", "pass": "hunter2xyz"}},
        {"api_key": 12345678},
        {"secrets": ("hunter2xyz",)},
    ],
)
def test_secret_labelled_values_of_any_type_are_masked(payload: dict) -> None:
    redacted, count = redact(payload)
    assert "hunter2xyz" not in repr(redacted) and "12345678" not in repr(redacted)
    assert list(redacted.values()) == [REDACTED]
    assert count == 1


def test_secret_labels_keep_none_bool_and_empty() -> None:
    payload = {"password": None, "has_token": True, "token": False, "credentials": {}, "secret": ""}
    assert redact(payload) == (payload, 0)


def test_name_value_pairs() -> None:
    event = {
        "headers": [
            {"name": "Authorization", "value": "Basic dXNlcjpwYXNz"},
            {"name": "Host", "value": "example.com"},
            {"Name": "X-Api-Key", "Value": "abc"},
            ["Cookie", "session=abc123"],
            ["Accept", "text/html"],
        ],
        "env": [{"name": "DB_PASSWORD", "value": "S3cret"}, {"key": "registry_key", "value": "HKLM\\Run"}],
        "aws_waf": {"httpRequest": {"headers": [["authorization", "Basic dXNlcjpwYXNz"]]}},
    }
    redacted, count = redact(event)
    headers = redacted["headers"]
    assert headers[0] == {"name": "Authorization", "value": REDACTED}
    assert headers[1] == {"name": "Host", "value": "example.com"}
    assert headers[2] == {"Name": "X-Api-Key", "Value": REDACTED}
    assert headers[3] == ["Cookie", REDACTED]
    assert headers[4] == ["Accept", "text/html"]
    assert redacted["env"] == [{"name": "DB_PASSWORD", "value": REDACTED}, {"key": "registry_key", "value": "HKLM\\Run"}]
    assert redacted["aws_waf"]["httpRequest"]["headers"] == [["authorization", REDACTED]]
    assert count == 5


def test_nesting_beyond_the_limit_fails_closed() -> None:
    from lg_sotf.security.redaction import MAX_DEPTH, TOO_DEEP

    deep: dict = {"password": "hunter2", "note": "AKIAIOSFODNN7EXAMPLE"}
    for _ in range(MAX_DEPTH + 6):
        deep = {"d": [deep]}
    redacted, count = redact(deep)
    text = repr(redacted)
    assert "hunter2" not in text and "AKIAIOSFODNN7EXAMPLE" not in text
    assert TOO_DEEP in text
    assert count == 1


def test_sets_are_scanned() -> None:
    redacted, count = redact({"tags": {"password=hunter2", "ok"}})
    assert sorted(redacted["tags"]) == ["ok", "password=[REDACTED]"]
    assert count == 1


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mysql -u root -pS3cretPass db", "mysql -u root -p[REDACTED] db"),
        ("mysqldump.exe --host db -p'S3cret Pass' shop", "mysqldump.exe --host db -p'[REDACTED]' shop"),
        ("sshpass -p 'S3cretPass' ssh admin@host", "sshpass -p '[REDACTED]' ssh admin@host"),
        ("sshpass -pS3cretPass ssh admin@host", "sshpass -p[REDACTED] ssh admin@host"),
        ("curl -u admin:S3cretPass https://x", "curl -u admin:[REDACTED] https://x"),
        ("curl -s --user 'admin:S3cret Pass' https://x", "curl -s --user 'admin:[REDACTED]' https://x"),
        ("curl.exe -uadmin:S3cretPass https://x", "curl.exe -uadmin:[REDACTED] https://x"),
        ("smbclient //dc/c$ -U 'CORP\\bob%S3cretPass'", "smbclient //dc/c$ -U 'CORP\\bob%[REDACTED]'"),
        ("wget --http-password=S3cret https://x", "wget --http-password=[REDACTED] https://x"),
        ("app --db-password S3cret --verbose", "app --db-password [REDACTED] --verbose"),
    ],
)
def test_cli_credentials(text: str, expected: str) -> None:
    assert redact_text(text) == (expected, 1)


@pytest.mark.parametrize(
    "text",
    [
        "mysql -u root -p db",
        "mysql -P 3306 -h db.internal",
        "sshpass -f /run/secrets/pw ssh host",
        "curl -u admin https://x",
        "psql --no-password --dbname x",
        "Basic Information",
        "basic authentication failed for user alice",
    ],
)
def test_cli_and_basic_false_positives(text: str) -> None:
    assert redact_text(text) == (text, 0)


@pytest.mark.parametrize("text", ["Basic dXNlcjpwYXNz", "  basic YWxpY2U6d29uZGVybGFuZA==  ", "Basic YTpi"])
def test_standalone_basic_header_values(text: str) -> None:
    redacted, count = redact_text(text)
    assert "[REDACTED]" in redacted and count == 1


def test_usage_token_counts_are_not_secrets() -> None:
    payload = {"input_tokens": 900, "cache_read_tokens": 5, "total_tokens": 905, "tokens": ["abc"]}
    assert redact(payload) == ({**payload, "tokens": REDACTED}, 1)


@pytest.mark.parametrize(
    "payload",
    [
        "mysql " * 100_000,
        "curl -u " * 100_000,
        "sshpass " * 100_000,
        "smbclient -U " * 60_000,
        "Basic dXNlcjpwYXNz " * 30_000,
        "a://u:" * 100_000,
        "--x-y-z-" * 100_000,
        "password" + " " * 500_000,
        "net use " * 100_000,
        "net user /a " * 60_000,
        "psexec -u " * 80_000,
        "a/b:" * 150_000,
        "/p:" * 150_000,
        "ConvertTo-SecureString -a " * 30_000,
        "schtasks /rp " * 60_000,
        "echo x | " * 80_000,
    ],
)
def test_new_rules_stay_linear(payload: str) -> None:
    start = time.perf_counter()
    redact_text(payload)
    assert time.perf_counter() - start < 3.0


def test_rule_gates_cover_case_folded_labels() -> None:
    assert redact_text("\u017fecret=abc123") == ("\u017fecret=[REDACTED]", 1)
    assert redact_text("PASSWORD=Hunter2") == ("PASSWORD=[REDACTED]", 1)


def test_every_rule_has_a_trigger_present_in_its_matches() -> None:
    from lg_sotf.security.redaction import _RULES

    samples = [
        "AKIAIOSFODNN7EXAMPLE", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk", "sk-ant-api03-abcdefghijklmnop",
        "sk-" + "a" * 40, "ghp_" + "a" * 36, "xoxb-1234567890-abc", "sk_live_" + "a" * 20, "AIza" + "a" * 35,
        "lgk_" + "0" * 32 + "_" + "a" * 20, "Authorization: Bearer abcdef", "bearer abcdefghijklmnop",
        "Basic dXNlcjpwYXNz", "postgres://u:p@h/db", "--password x", "mysql -px", "sshpass -p x", "curl -u a:b",
        "smbclient -U a%b", "ConvertTo-SecureString 'x'", "net user bob pw",
        r"net use \\srv\c$ pw", r"net use \\srv\c$ /user:u pw", "psexec -p pw", "sqlcmd -P pw", "plink -pw pw",
        "ldapsearch -w pw", "7z a -ppw", "/pass:pw", "schtasks /rp pw", "DefaultPassword /d pw", "dom/user:pw@host",
        "wmiexec.py user:pw@host", "echo pw | sudo -S id", "?sig=abc", "hooks.slack.com/services/T/B/x",
        "glpat-" + "a" * 20, "db_password=x",
    ]
    for rule, sample in zip(_RULES, samples, strict=True):
        assert rule.pattern.search(sample), (rule.pattern.pattern, sample)
        assert any(t in sample.casefold() for t in rule.triggers), (rule.triggers, sample)


LATERAL_MOVEMENT_CREDENTIALS = [
    r"psexec.exe \\ws-01 -u CORP\admin -p Winter2026! cmd.exe",
    r'PsExec64.exe -accepteula \\10.0.0.5 -u admin -p "Winter2026! x" cmd',
    r"paexec \\host -u admin -p Winter2026! cmd",
    r"net use \\fs01\c$ /user:CORP\admin Winter2026!",
    r"net use Z: \\fs01\share Winter2026! /user:CORP\admin",
    r"schtasks /create /tn x /tr c:\x.exe /ru CORP\admin /rp Winter2026!",
    r"schtasks /query /s srv /u admin /p Winter2026!",
    r"xfreerdp /v:10.0.0.5 /u:admin /p:Winter2026!",
    r"cmdkey /add:srv01 /user:admin /pass:Winter2026!",
    r'sqlcmd -S db01 -U sa -P Winter2026! -Q "select 1"',
    r"ldapsearch -x -D cn=admin,dc=corp -w Winter2026! -H ldap://dc01",
    r"7z.exe a -pWinter2026! out.7z c:\data",
    r"rar a -hpWinter2026! out.rar c:\data",
    r"zip -P Winter2026! out.zip data",
    r"echo Winter2026! | sudo -S id",
    r"impacket-secretsdump corp/admin:Winter2026!@10.0.0.5",
    r"wmiexec.py admin:Winter2026!@10.0.0.5",
    r"evil-winrm -i 10.0.0.5 -u admin -p Winter2026!",
    r"crackmapexec smb 10.0.0.0/24 -u admin -p Winter2026!",
    r"nxc smb 10.0.0.5 -u admin -p Winter2026!",
    r"hydra -l admin -p Winter2026! ssh://10.0.0.5",
    r"docker login -u admin -p Winter2026! registry",
    r"az login --service-principal -u appid -p Winter2026! --tenant t",
    r"plink.exe -ssh admin@10.0.0.5 -pw Winter2026!",
    r"pscp -pw Winter2026! file admin@host:/tmp",
    r"rdesktop -u admin -p Winter2026! 10.0.0.5",
    r'New-Object PSCredential("admin",(ConvertTo-SecureString -String Winter2026! -AsPlainText -Force))',
    r'ConvertTo-SecureString -AsPlainText "Winter2026!" -Force',
    r"net user /add bob Winter2026!",
    r"net user /domain /add bob Winter2026!",
    r"reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v DefaultPassword /t REG_SZ /d Winter2026!",
    r'mimikatz "sekurlsa::pth /user:admin /domain:corp /ntlm:Winter2026!"',
]


@pytest.mark.parametrize("text", LATERAL_MOVEMENT_CREDENTIALS)
def test_lateral_movement_tool_passwords_are_removed(text: str) -> None:
    """LLM-W6-03: short/slash password flags of common admin and attack tools."""
    redacted, count = redact_text(text)
    assert "Winter2026" not in redacted, redacted
    assert count >= 1


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (
            "https://acct.blob.core.windows.net/c?sv=2021-06-08&sp=r&sig=AbCdEfGhIjKlMnOp0123456789%2B%2F%3D",
            "AbCdEfGh",
        ),
        # Assembled at run time so the secret scanner (gitleaks) does not flag the fake values.
        ("https://hooks.slack.com/" + "services/T0123ABCD/B0123ABCD/" + "abcdefghijklmnopqrstuvwx", "abcdefghijklmnop"),
        ("token " + "glpat-" + "abcdefghijklmnopqrst used", "glpat-abc"),
        ("npm_" + "abcdefghijklmnopqrstuvwxyz0123456789", "npm_abc"),
        ("SG." + "abcdefghijklmnopqrstuv." + "abcdefghijklmnopqrstuvwxyz0123456789abcdefg", "SG.abc"),
    ],
)
def test_signed_urls_webhooks_and_vendor_tokens_are_removed(text: str, secret: str) -> None:
    redacted, _ = redact_text(text)
    assert secret not in redacted


def test_net_user_add_masks_the_password_not_the_user() -> None:
    assert redact_text("net user /add bob Winter2026!") == ("net user /add bob [REDACTED]", 1)


@pytest.mark.parametrize(
    "text",
    [
        r"net use Z: \\fs01\share /persistent:yes",
        r"net use \\srv\ipc$ /user:bob",
        r"net use \\srv\ipc$ /delete",
        "docker run -p 8080:80 nginx",
        "7z a out.7z data",
        "zip -r out.zip data",
        "xcopy /p a b",
        r"psexec \\host -s cmd",
        "git@github.com:org/repo.git",
        "net user /domain bob",
        "schtasks /create /tn x /sc daily /ru SYSTEM",
        "ConvertTo-SecureString $enc -Key $k",
        "https://x.example/a/p:1",
    ],
)
def test_tool_rules_keep_benign_command_lines(text: str) -> None:
    assert redact_text(text) == (text, 0)


def test_tool_passwords_never_reach_the_prompt(make_settings: Callable[..., Settings]) -> None:
    from lg_sotf.llm.prompting import build_prompt

    bundle = build_prompt(
        "system",
        "task",
        {"command_lines": LATERAL_MOVEMENT_CREDENTIALS, "raw": {"process": LATERAL_MOVEMENT_CREDENTIALS[0]}},
        settings=make_settings(),
    )
    text = "".join(str(m.content) for m in bundle.messages)
    assert "Winter2026" not in text
    assert bundle.redactions >= len(LATERAL_MOVEMENT_CREDENTIALS)
