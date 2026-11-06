"""TLS verification settings for outbound connections.

Verification is on by default. A config may add a CA certificate
(``ca_cert_pem`` PEM text; ``ca_bundle``, a server file path, only in
development); ``tls_verify: false`` is refused in staging/production.

Building an ``ssl.SSLContext`` loads a CA bundle synchronously, so clients
that open a connection per request take their contexts from
:class:`TlsContexts` instead of letting ``httpx`` build one each time.
"""

from __future__ import annotations

import hashlib
import ssl
import threading
from collections import OrderedDict
from typing import Any, Callable, Mapping, Optional, Union

import httpx

from lg_sotf.errors import SourceConfigError

Verify = Union[bool, ssl.SSLContext]

MAX_CUSTOM_CONTEXTS = 256


class TlsContexts:
    """Client ``SSLContext`` cache: one verify-on default plus an LRU of custom-CA contexts.

    * :meth:`default` is ``httpx.create_ssl_context()``, what
      ``httpx.AsyncHTTPTransport(verify=True)`` would build (certifi, or
      ``SSL_CERT_FILE``/``SSL_CERT_DIR``), created on first use.
    * :meth:`custom_ca` trusts exactly one ``ca_cert_pem`` (the same
      context :func:`build_verify` builds), keyed by ``sha256(pem)``: two
      configs share a context only when their CA text is identical, and a
      custom-CA context is never the default one.

    ``verify=False`` is never cached (it is a development-only setting).
    The contexts are shared between clients, so nothing may modify one
    after it is returned (``httpx`` only sets the same ALPN list on it).
    """

    def __init__(
        self,
        *,
        max_custom: int = MAX_CUSTOM_CONTEXTS,
        create_default: Callable[[], ssl.SSLContext] = httpx.create_ssl_context,
    ) -> None:
        self._max_custom = max(1, max_custom)
        self._create_default = create_default
        self._default: Optional[ssl.SSLContext] = None
        self._custom: OrderedDict[str, ssl.SSLContext] = OrderedDict()
        self._lock = threading.Lock()

    def default(self) -> ssl.SSLContext:
        with self._lock:
            if self._default is None:
                self._default = self._create_default()
            return self._default

    def custom_ca(self, pem: str) -> ssl.SSLContext:
        """A context trusting only ``pem``; raises :class:`SourceConfigError` for an unreadable CA."""
        key = hashlib.sha256(pem.encode("utf-8")).hexdigest()
        with self._lock:
            cached = self._custom.get(key)
            if cached is not None:
                self._custom.move_to_end(key)
                return cached
            context = _ca_context(None, pem)
            self._custom[key] = context
            while len(self._custom) > self._max_custom:
                self._custom.popitem(last=False)
            return context

    def resolve(self, verify: Verify) -> Verify:
        """``True`` becomes the shared default context; ``False`` and explicit contexts pass through."""
        return self.default() if verify is True else verify


# The process's contexts. Clients take a ``tls`` argument so tests (and a composition root) can pass their own.
PROCESS_TLS = TlsContexts()


def build_verify(
    config: Mapping[str, Any], *, production: bool, contexts: Optional[TlsContexts] = None
) -> Verify:
    """TLS verification setting for a source config (see module docstring).

    With ``contexts``, a ``ca_cert_pem`` context comes from that cache
    instead of being built on every call.
    """
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
    if contexts is not None and ca_file is None and ca_pem is not None:
        return contexts.custom_ca(ca_pem)
    return _ca_context(ca_file, ca_pem)


def _ca_context(ca_file: Optional[str], ca_pem: Optional[str]) -> ssl.SSLContext:
    try:
        return ssl.create_default_context(cafile=ca_file, cadata=ca_pem)
    except (ssl.SSLError, OSError, ValueError) as exc:
        raise SourceConfigError("invalid CA certificate") from exc
