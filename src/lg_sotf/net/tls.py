"""TLS verification settings for outbound connections.

Verification is on by default. A config may add a CA certificate
(``ca_cert_pem`` PEM text; ``ca_bundle``, a server file path, only in
development); ``tls_verify: false`` is refused in staging/production.
"""

from __future__ import annotations

import ssl
from typing import Any, Mapping, Union

from lg_sotf.errors import SourceConfigError

Verify = Union[bool, ssl.SSLContext]


def build_verify(config: Mapping[str, Any], *, production: bool) -> Verify:
    """TLS verification setting for a source config (see module docstring)."""
    verify = config.get("tls_verify", True)
    if verify is False:
        if production:
            raise SourceConfigError("tls_verify=false is not allowed in staging or production")
        return False
    if verify is not True:
        raise SourceConfigError("tls_verify must be true or false")
    ca_pem = config.get("ca_cert_pem")
    ca_file = config.get("ca_bundle")
    if ca_pem is None and ca_file is None:
        return True
    if ca_file is not None and production:
        # A server path from tenant config would let a tenant probe the server's filesystem.
        raise SourceConfigError("ca_bundle is not allowed in staging or production; use ca_cert_pem")
    if ca_pem is not None and not isinstance(ca_pem, str):
        raise SourceConfigError("ca_cert_pem must be PEM text")
    if ca_file is not None and not isinstance(ca_file, str):
        raise SourceConfigError("ca_bundle must be a file path")
    try:
        return ssl.create_default_context(cafile=ca_file, cadata=ca_pem)
    except (ssl.SSLError, OSError, ValueError) as exc:
        raise SourceConfigError("invalid CA certificate") from exc
