"""Where the LLM client may connect: ``llm.base_url`` policy and self-hosted providers.

``llm.base_url`` is operator configuration, not tenant input, but it decides
where every prompt (alert data included) is sent, so it is checked before a
model is built and by :meth:`Settings.production_problems`:

* the scheme is ``https``, or ``http`` when the host is internal: a loopback
  or private address (RFC 1918, CGNAT, unique-local IPv6), ``localhost``, a
  single-label name (a docker compose service such as ``ollama`` or ``vllm``)
  or a name under ``.internal`` (``host.docker.internal``). Plain HTTP to
  anything else would put alert data on the wire in clear text;
* link-local, cloud metadata, multicast, unspecified and reserved addresses
  are refused whatever the scheme (the address classes
  :class:`~lg_sotf.net.egress.DestinationPolicy` refuses);
* credentials in the URL are refused (``llm.api_key`` is the secret's place);
* when the install sets an egress allow-list
  (``ingestion.allowed_destination_hosts``), the endpoint's host, or the
  provider SDK's default host, must be on it.

Names are classified by their spelling, not resolved: the check runs at
configuration time and a DNS answer is not proof of where a later request goes.

The self-hosted providers (``ollama``, ``openai_compatible``) speak the
OpenAI chat completions API to a server the operator runs; ``ollama`` defaults
to the ``ollama`` service of ``docker/docker-compose.ollama.yml``.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

import httpx

from lg_sotf.llm.errors import LLMUnavailable
from lg_sotf.net.egress import DestinationPolicy, allowed_hosts, host_on_list, ip_literal
from lg_sotf.settings import SELF_HOSTED_PROVIDERS, Settings

OLLAMA_DEFAULT_BASE_URL = "http://ollama:11434/v1"
# Where each provider SDK connects when llm.base_url is unset (checked against the egress allow-list).
PROVIDER_DEFAULT_HOSTS = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "gemini": "generativelanguage.googleapis.com",
}
_INTERNAL_NAMES = ("localhost",)
_INTERNAL_SUFFIXES = (".localhost", ".internal")


def is_self_hosted(provider: str) -> bool:
    return provider in SELF_HOSTED_PROVIDERS


def effective_base_url(settings: Settings) -> Optional[str]:
    """``llm.base_url``, or the provider's default endpoint (``ollama`` only), or None (SDK default)."""
    url = (settings.llm.base_url or "").strip()
    if url:
        return url
    if settings.llm.provider == "ollama":
        return OLLAMA_DEFAULT_BASE_URL
    return None


def is_internal_host(host: str) -> bool:
    """Whether plain HTTP to ``host`` stays inside the installation (see the module docstring)."""
    address = ip_literal(host)
    if address is not None:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if address.is_loopback:
            return True
        return not address.is_global and DestinationPolicy(require_https=False, allow_private=True).address_allowed(
            address
        )
    name = host.lower().rstrip(".")
    if not name:
        return False
    return name in _INTERNAL_NAMES or name.endswith(_INTERNAL_SUFFIXES) or "." not in name


def _address_refused(host: str) -> bool:
    """Link-local, metadata, multicast, unspecified or reserved address literals (never loopback)."""
    address = ip_literal(host)
    if address is None or address.is_loopback:
        return False
    return not DestinationPolicy(require_https=False, allow_private=True).address_allowed(address)


def check_base_url(url: str) -> None:
    """Raise :class:`LLMUnavailable` when ``url`` breaks the policy. Messages never echo the URL."""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError) as exc:
        raise LLMUnavailable("llm.base_url is not a valid URL") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise LLMUnavailable("llm.base_url must be an http(s) URL")
    if parsed.userinfo:
        raise LLMUnavailable("llm.base_url must not contain credentials (use llm.api_key)")
    host = parsed.host
    if not host:
        raise LLMUnavailable("llm.base_url has no host")
    if _address_refused(host):
        raise LLMUnavailable("llm.base_url points at a link-local, metadata or reserved address")
    if scheme == "http" and not is_internal_host(host):
        raise LLMUnavailable(
            "llm.base_url must use https unless its host is loopback, a private address, "
            "a docker service name or a .internal name"
        )


def resolve_base_url(settings: Settings) -> Optional[str]:
    """The checked endpoint for the configured provider (None: the provider SDK's default)."""
    url = effective_base_url(settings)
    if url is None:
        if settings.llm.provider == "openai_compatible":
            raise LLMUnavailable("llm.base_url is required for provider 'openai_compatible'")
        _check_allowed(settings, PROVIDER_DEFAULT_HOSTS.get(settings.llm.provider, ""))
        return None
    check_base_url(url)
    _check_allowed(settings, httpx.URL(url).host)
    return url


def _check_allowed(settings: Settings, host: str) -> None:
    """The install's egress allow-list (``ingestion.allowed_destination_hosts``) covers the LLM endpoint too."""
    hosts = allowed_hosts(settings)
    if hosts is not None and not host_on_list(host, hosts):
        raise LLMUnavailable("the LLM endpoint's host is not in ingestion.allowed_destination_hosts")


def base_url_problem(settings: Settings) -> Optional[str]:
    """Why the configured endpoint is refused, for :meth:`Settings.production_problems`."""
    try:
        resolve_base_url(settings)
    except LLMUnavailable as exc:
        return str(exc)
    return None
