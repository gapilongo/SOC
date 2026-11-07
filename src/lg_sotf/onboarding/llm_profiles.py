"""Language-model profiles offered by the first-run setup wizard, and where the configured model runs.

The model is install configuration (``llm.*`` in the env file or YAML, read at
start-up), not tenant data: the wizard records the profile an admin picked,
shows the settings that select it and tests the model that is configured now
(``POST /tenant/llm/test``). It never changes the running configuration.

The default is an EU-hosted model; the other offers are local. A provider
hosted outside the EU is listed last and labelled as such. A provider hosted
in China is never offered; when one is configured it is reported as ``cn`` so
the UI can flag it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional, Tuple
from urllib.parse import urlsplit

from lg_sotf.llm.endpoint import effective_base_url, is_internal_host
from lg_sotf.settings import Settings

Residency = Literal["eu", "local", "us", "cn", "offline", "unknown"]

API_KEY_PLACEHOLDER = "<your API key>"


@dataclass(frozen=True)
class LlmProfile:
    id: str
    label: str
    residency: Residency
    description: str
    provider: str
    fast_model: str
    deep_model: str
    base_url: Optional[str] = None
    needs_api_key: bool = False
    extra_env: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)

    def env(self) -> List[Tuple[str, str]]:
        """The settings that select this profile, as environment variables (``LG_SOTF_LLM__*``)."""
        lines = [("LG_SOTF_LLM__PROVIDER", self.provider)]
        if self.base_url:
            lines.append(("LG_SOTF_LLM__BASE_URL", self.base_url))
        if self.needs_api_key:
            lines.append(("LG_SOTF_LLM__API_KEY", API_KEY_PLACEHOLDER))
        lines += [("LG_SOTF_LLM__FAST__MODEL", self.fast_model), ("LG_SOTF_LLM__DEEP__MODEL", self.deep_model)]
        return lines + list(self.extra_env)


MISTRAL_EU = LlmProfile(
    id="mistral_eu",
    label="Mistral AI (EU)",
    residency="eu",
    description="Mistral's API, hosted in the EU. Needs a Mistral API key.",
    provider="openai",
    base_url="https://api.mistral.ai/v1",
    fast_model="mistral-small-latest",
    deep_model="mistral-medium-latest",
    needs_api_key=True,
    extra_env=(("LG_SOTF_LLM__PROMPT_CACHING", "false"),),
)
OLLAMA_LOCAL = LlmProfile(
    id="ollama_local",
    label="Ollama on this server (local)",
    residency="local",
    description="A model served by Ollama next to LG-SOTF: alert data never leaves the machine. "
    "Start the stack with the Ollama overlay (make quickstart OLLAMA=qwen3:8b).",
    provider="ollama",
    base_url="http://ollama:11434/v1",
    fast_model="qwen3:8b",
    deep_model="qwen3:8b",
    extra_env=(("LG_SOTF_LLM__PROMPT_CACHING", "false"),),
)
SELF_HOSTED = LlmProfile(
    id="self_hosted",
    label="Your own model server (local)",
    residency="local",
    description="An OpenAI-compatible server you run, such as vLLM or llama.cpp, on your network.",
    provider="openai_compatible",
    base_url="http://vllm:8000/v1",
    fast_model="<model name>",
    deep_model="<model name>",
    extra_env=(("LG_SOTF_LLM__PROMPT_CACHING", "false"),),
)
ANTHROPIC = LlmProfile(
    id="anthropic",
    label="Anthropic (outside the EU)",
    residency="us",
    description="Anthropic's API, hosted in the United States. Needs an Anthropic API key.",
    provider="anthropic",
    fast_model="claude-haiku-4-5",
    deep_model="claude-opus-5-5",
    needs_api_key=True,
)

PROFILES: Tuple[LlmProfile, ...] = (MISTRAL_EU, OLLAMA_LOCAL, SELF_HOSTED, ANTHROPIC)
DEFAULT_PROFILE = MISTRAL_EU.id
PROFILE_IDS = frozenset(p.id for p in PROFILES)

# API hosts whose region is known. Matched on the host name or a parent domain.
_EU_HOSTS = ("api.mistral.ai",)
_CN_DOMAINS = ("deepseek.com",)


@dataclass(frozen=True)
class ConfiguredModel:
    provider: str
    enabled: bool
    fast_model: str
    deep_model: str
    residency: Residency
    profile: Optional[str]


def _host(url: Optional[str]) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".") if url else ""
    except ValueError:
        return ""


def _under(host: str, domains: Tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _classify(provider: str, host: str) -> Tuple[Residency, Optional[str]]:
    if provider == "fake":
        return "offline", None
    if host and _under(host, _CN_DOMAINS):
        return "cn", None
    if host and _under(host, _EU_HOSTS):
        return "eu", MISTRAL_EU.id if provider == "openai" else None
    if provider in ("ollama", "openai_compatible"):
        if not is_internal_host(host):
            return "unknown", None
        return "local", OLLAMA_LOCAL.id if provider == "ollama" else SELF_HOSTED.id
    if host:  # a gateway or proxy in front of a cloud API: its region is not known here
        return "unknown", None
    return "us", ANTHROPIC.id if provider == "anthropic" else None


def configured_model(settings: Settings) -> ConfiguredModel:
    """The model this install runs now, where it is hosted and the matching profile (if any)."""
    llm = settings.llm
    residency, profile = _classify(llm.provider, _host(effective_base_url(settings)))
    fake = llm.provider == "fake"  # the offline model ignores the configured names (lg_sotf.llm.client)
    return ConfiguredModel(
        provider=llm.provider,
        enabled=llm.enabled,
        fast_model="fake-fast" if fake else llm.fast.model,
        deep_model="fake-deep" if fake else llm.deep.model,
        residency=residency,
        profile=profile,
    )


__all__ = [
    "DEFAULT_PROFILE",
    "PROFILES",
    "PROFILE_IDS",
    "ConfiguredModel",
    "LlmProfile",
    "Residency",
    "configured_model",
]
