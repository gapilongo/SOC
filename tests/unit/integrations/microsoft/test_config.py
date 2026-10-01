"""Microsoft integration config and credential validation, and the credential binding."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterator

import pytest

from lg_sotf.integrations.config import (
    IntegrationConfigError,
    certificate_details,
    check_secret_binding,
    parse_microsoft_config,
    secret_fields,
    validate_config,
    validate_events,
    validate_secret,
)
from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.integrations.outbox import operation_for
from tests.fixtures.microsoft import fake_config, fake_secret, make_certificate
from tests.unit.integrations.microsoft._support import FAKE_SPECS

ISO = "defender.fake_isolation"


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


def check(config: Dict[str, Any]) -> Dict[str, Any]:
    return validate_config("microsoft", config, require_https=True)


def test_valid_secret_and_certificate_configs() -> None:
    config, secret = fake_config(capabilities={ISO: {"enabled": True, "live": True, "options": {"limit": 3}}})
    normalised = check(config)
    assert normalised["capabilities"][ISO] == {
        "enabled": True, "live": True, "options": {"mode": "normal", "limit": 3, "note": "", "tags": []},
    }
    assert validate_secret("microsoft", secret, require_https=True, config=normalised) == secret
    cert_config, cert_secret = fake_config(credential="certificate")
    normalised = check(cert_config)
    validated = validate_secret("microsoft", cert_secret, require_https=True, config=normalised)
    assert validated == {"private_key_pem": cert_secret["private_key_pem"].strip()}
    assert parse_microsoft_config(normalised).credential == "certificate"
    assert secret_fields("microsoft") == ("client_secret", "private_key_pem")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"directory_tenant_id": "common"}, "must be a GUID"),
        ({"directory_tenant_id": "contoso.onmicrosoft.com"}, "must be a GUID"),
        ({"client_id": "not-a-guid"}, "must be a GUID"),
        ({"cloud": "china"}, "cloud"),
        ({"cloud": "usgov_dod", "defender_geo": "eu"}, "global cloud only"),
        ({"defender_geo": "moon"}, "defender_geo"),
        ({"graph_url": "https://evil.example"}, "graph_url"),
        ({"capabilities": {"defender.nope": {"enabled": True}}}, "unknown capability"),
        ({"capabilities": {ISO: {"live": True}}}, "live requires enabled"),
        ({"capabilities": {ISO: {"enabled": True, "options": {"limit": 99}}}}, "limit"),
        ({"capabilities": {ISO: {"enabled": True, "options": {"bogus": 1}}}}, "bogus"),
        ({"capabilities": {ISO: {"enabled": True, "options": {"mode": "strict"}}}}, "strict mode needs a note"),
        ({"cloud": "usgov_gcc_high", "capabilities": {ISO: {"enabled": True}}}, "not supported in the usgov_gcc_high"),
    ],
)
def test_config_problems(change: Dict[str, Any], message: str) -> None:
    config, _ = fake_config()
    config.update(change)
    with pytest.raises(IntegrationConfigError) as exc:
        check(config)
    assert message in str(exc.value)


def test_disabled_capabilities_may_hold_problem_options() -> None:
    config, _ = fake_config(capabilities={ISO: {"enabled": False, "options": {"mode": "strict"}}})
    assert check(config)["capabilities"][ISO]["options"]["mode"] == "strict"


def test_certificate_rules() -> None:
    config, _ = fake_config(credential="certificate")
    config.pop("certificate_pem")
    with pytest.raises(IntegrationConfigError, match="certificate_pem is required"):
        check(config)
    expired, _ = make_certificate(days=-1)
    config["certificate_pem"] = expired
    with pytest.raises(IntegrationConfigError, match="expired"):
        check(config)
    config["certificate_pem"] = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"
    with pytest.raises(IntegrationConfigError, match="PEM X.509"):
        check(config)
    small, _ = make_certificate(bits=1024)
    config["certificate_pem"] = small
    with pytest.raises(IntegrationConfigError, match="2048"):
        check(config)
    details = certificate_details(make_certificate()[0])
    assert len(details["thumbprint_sha1"]) == 40 and details["days_left"] >= 29


def test_secret_rules() -> None:
    config, _ = fake_config(credential="certificate")
    normalised = check(config)
    _, other_key = make_certificate()
    with pytest.raises(IntegrationConfigError, match="does not match"):
        validate_secret("microsoft", {"private_key_pem": other_key}, require_https=True, config=normalised)
    with pytest.raises(IntegrationConfigError, match="private_key_pem is required"):
        validate_secret("microsoft", {}, require_https=True, config=normalised)
    with pytest.raises(IntegrationConfigError, match="not used"):
        validate_secret("microsoft", {"private_key_pem": other_key, "client_secret": fake_secret()},
                        require_https=True, config=normalised)
    with pytest.raises(IntegrationConfigError, match="unencrypted"):
        validate_secret("microsoft", {"private_key_pem": "garbage"}, require_https=True, config=normalised)
    secret_config, _ = fake_config()
    with pytest.raises(IntegrationConfigError, match="not used with credential=client_secret"):
        validate_secret("microsoft", {"client_secret": fake_secret(), "private_key_pem": other_key},
                        require_https=True, config=check(secret_config))
    with pytest.raises(IntegrationConfigError, match="validated against its config"):
        validate_secret("microsoft", {"client_secret": fake_secret()}, require_https=True)


def test_credential_binding_follows_the_credential_type() -> None:
    current, _ = fake_config()
    moved = {**current, "directory_tenant_id": str(uuid.uuid4())}
    with pytest.raises(IntegrationConfigError, match="secret.client_secret"):
        check_secret_binding("microsoft", current, moved, {})
    check_secret_binding("microsoft", current, moved, {"client_secret": fake_secret()})
    switched = {**current, "credential": "certificate"}
    with pytest.raises(IntegrationConfigError, match="secret.private_key_pem"):
        check_secret_binding("microsoft", current, switched, {"client_secret": fake_secret()})
    # Capabilities are not bound to the credential.
    check_secret_binding("microsoft", current, {**current, "capabilities": {ISO: {"enabled": True}}}, {})


def test_no_events_for_microsoft() -> None:
    assert validate_events("microsoft", []) == []
    with pytest.raises(IntegrationConfigError):
        validate_events("microsoft", ["action.failed"])
    assert operation_for({"kind": "microsoft", "events": ["action.failed"]}, "action.failed", "high", None) is None
