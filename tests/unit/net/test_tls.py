"""TLS verification settings for outbound connections."""

from __future__ import annotations

import datetime as dt
import ssl
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from lg_sotf.errors import SourceConfigError
from lg_sotf.net.tls import build_verify


def _self_signed_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime(2024, 1, 1))
        .not_valid_after(dt.datetime(2034, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_build_verify() -> None:
    assert build_verify({}, production=True) is True
    assert build_verify({"tls_verify": False}, production=False) is False
    with pytest.raises(SourceConfigError):
        build_verify({"tls_verify": False}, production=True)
    with pytest.raises(SourceConfigError):
        build_verify({"tls_verify": "no"}, production=False)
    ctx = build_verify({"ca_cert_pem": _self_signed_pem()}, production=True)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    with pytest.raises(SourceConfigError):
        build_verify({"ca_bundle": "/nonexistent/ca.pem"}, production=False)
    with pytest.raises(SourceConfigError):
        build_verify({"ca_cert_pem": "not a pem"}, production=False)


def test_ca_bundle_paths_are_refused_in_production_and_errors_are_generic(tmp_path: Any) -> None:
    pem = tmp_path / "ca.pem"
    pem.write_text(_self_signed_pem())
    assert isinstance(build_verify({"ca_bundle": str(pem)}, production=False), ssl.SSLContext)
    with pytest.raises(SourceConfigError, match="not allowed in staging or production"):
        build_verify({"ca_bundle": str(pem)}, production=True)
    messages = set()
    for path in ("/nonexistent/ca.pem", "/etc/shadow", str(tmp_path)):
        with pytest.raises(SourceConfigError) as info:
            build_verify({"ca_bundle": path}, production=False)
        messages.add(str(info.value))
    assert messages == {"invalid CA certificate"}
