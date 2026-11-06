"""TLS verification settings for outbound connections."""

from __future__ import annotations

import ssl
from typing import Any, List

import pytest

from lg_sotf.errors import SourceConfigError
from lg_sotf.net.tls import TlsContexts, build_verify
from tests.unit.net._support import self_signed_pem


def test_build_verify() -> None:
    assert build_verify({}, production=True) is True
    assert build_verify({"tls_verify": False}, production=False) is False
    with pytest.raises(SourceConfigError):
        build_verify({"tls_verify": False}, production=True)
    with pytest.raises(SourceConfigError):
        build_verify({"tls_verify": "no"}, production=False)
    ctx = build_verify({"ca_cert_pem": self_signed_pem()}, production=True)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    with pytest.raises(SourceConfigError):
        build_verify({"ca_bundle": "/nonexistent/ca.pem"}, production=False)
    with pytest.raises(SourceConfigError):
        build_verify({"ca_cert_pem": "not a pem"}, production=False)


def test_ca_bundle_paths_are_refused_in_production_and_errors_are_generic(tmp_path: Any) -> None:
    pem = tmp_path / "ca.pem"
    pem.write_text(self_signed_pem())
    assert isinstance(build_verify({"ca_bundle": str(pem)}, production=False), ssl.SSLContext)
    with pytest.raises(SourceConfigError, match="not allowed in staging or production"):
        build_verify({"ca_bundle": str(pem)}, production=True)
    messages = set()
    for path in ("/nonexistent/ca.pem", "/etc/shadow", str(tmp_path)):
        with pytest.raises(SourceConfigError) as info:
            build_verify({"ca_bundle": path}, production=False)
        messages.add(str(info.value))
    assert messages == {"invalid CA certificate"}


# ------------------------------------------------------------ cached contexts (D3)


def test_default_context_is_built_once() -> None:
    built: List[ssl.SSLContext] = []

    def create() -> ssl.SSLContext:
        built.append(ssl.create_default_context())
        return built[-1]

    contexts = TlsContexts(create_default=create)
    assert built == []  # nothing is loaded until a client needs it
    first = contexts.default()
    assert contexts.default() is first and contexts.resolve(True) is first
    assert len(built) == 1
    assert contexts.resolve(False) is False
    custom = ssl.create_default_context()
    assert contexts.resolve(custom) is custom


def test_custom_ca_contexts_are_keyed_by_the_ca_text() -> None:
    contexts = TlsContexts()
    pem_a, pem_b = self_signed_pem("ca-a"), self_signed_pem("ca-b")
    a = contexts.custom_ca(pem_a)
    assert contexts.custom_ca(pem_a) is a
    b = contexts.custom_ca(pem_b)
    assert b is not a
    assert a is not contexts.default() and b is not contexts.default()
    # Same verification as build_verify: hostname checked, and only the configured CA is trusted.
    for ctx, pem in ((a, pem_a), (b, pem_b)):
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
        (ca,) = ctx.get_ca_certs(binary_form=True)
        assert ca == ssl.PEM_cert_to_DER_cert(pem)


def test_custom_ca_cache_is_a_bounded_lru() -> None:
    contexts = TlsContexts(max_custom=2)
    pem_a, pem_b, pem_c = self_signed_pem("a"), self_signed_pem("b"), self_signed_pem("c")
    a = contexts.custom_ca(pem_a)
    b = contexts.custom_ca(pem_b)
    assert contexts.custom_ca(pem_a) is a  # a is now the most recently used
    contexts.custom_ca(pem_c)  # evicts b
    assert contexts.custom_ca(pem_a) is a
    assert contexts.custom_ca(pem_b) is not b


def test_invalid_custom_ca_is_refused_and_not_cached() -> None:
    contexts = TlsContexts()
    for _ in range(2):
        with pytest.raises(SourceConfigError, match="^invalid CA certificate$"):
            contexts.custom_ca("not a pem")
    assert contexts._custom == {}


def test_build_verify_takes_ca_contexts_from_the_cache() -> None:
    contexts = TlsContexts()
    pem = self_signed_pem()
    first = build_verify({"ca_cert_pem": pem}, production=True, contexts=contexts)
    assert build_verify({"ca_cert_pem": pem}, production=True, contexts=contexts) is first
    assert build_verify({"ca_cert_pem": pem}, production=True) is not first  # no cache: a new context
    assert build_verify({}, production=True, contexts=contexts) is True
    assert build_verify({"tls_verify": False}, production=False, contexts=contexts) is False
    with pytest.raises(SourceConfigError, match="invalid CA certificate"):
        build_verify({"ca_cert_pem": "not a pem"}, production=True, contexts=contexts)


def test_ca_bundle_paths_are_never_cached(tmp_path: Any) -> None:
    contexts = TlsContexts()
    path = tmp_path / "ca.pem"
    path.write_text(self_signed_pem())
    first = build_verify({"ca_bundle": str(path)}, production=False, contexts=contexts)
    assert isinstance(first, ssl.SSLContext)
    assert build_verify({"ca_bundle": str(path)}, production=False, contexts=contexts) is not first
