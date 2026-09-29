"""Legacy configuration facade over :class:`lg_sotf.settings.Settings`.

Agents and tools written against the original YAML configuration keep using
``ConfigManager().get("agents.triage.confidence_threshold", 70)``. All values
now come from typed settings (environment, ``.env``, optional YAML); this
class never reads files or the environment itself.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional

from pydantic import ValidationError

from lg_sotf.core.exceptions import ConfigError
from lg_sotf.security.insecure import insecure_secret_problems
from lg_sotf.settings import (
    DatabaseSettings,
    LLMSettings,
    ObservabilitySettings,
    RedisSettings,
    SecuritySettings,
    Settings,
    get_settings,
    reset_settings,
)

_MISSING = object()


class ConfigManager:
    """Dotted-key access to settings, including the free-form ``agents``/``routing``/``tools``/``ingestion`` sections.

    ``ConfigManager()`` wraps the process-wide cached settings;
    ``ConfigManager(path)`` loads a private ``Settings`` with ``path`` as its
    YAML layer (environment variables still take precedence).
    """

    def __init__(self, config_path: Optional[str] = None, *, settings: Optional[Settings] = None):
        if settings is not None and config_path is not None:
            raise ValueError("pass either config_path or settings, not both")
        self.config_path = config_path
        self._settings = settings if settings is not None else self._load()
        self._data = self._settings.model_dump()

    def _load(self) -> Settings:
        if self.config_path is None:
            return get_settings()
        try:
            return Settings(config_file=self.config_path)
        except (FileNotFoundError, ValueError, ValidationError) as exc:
            raise ConfigError(f"Failed to load configuration from {self.config_path}: {exc}") from exc

    @property
    def settings(self) -> Settings:
        return self._settings

    def get(self, key: str, default: Any = None) -> Any:
        """Resolve ``a.b.c`` against the settings tree. Mutable values are returned as copies.

        Secret fields are returned as ``pydantic.SecretStr``; call ``get_secret_value()`` explicitly.
        """
        if not key:
            raise ConfigError("configuration key must not be empty")
        node: Any = self._data
        for part in key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return copy.deepcopy(node) if isinstance(node, (dict, list)) else node

    def has(self, key: str) -> bool:
        return self.get(key, _MISSING) is not _MISSING

    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        value = self.get(f"agents.{agent_name}", {})
        return value if isinstance(value, dict) else {}

    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        value = self.get(f"tools.{tool_name}", {})
        return value if isinstance(value, dict) else {}

    def get_database_config(self) -> DatabaseSettings:
        return self._settings.database

    def get_redis_config(self) -> RedisSettings:
        return self._settings.redis

    def get_llm_config(self) -> LLMSettings:
        return self._settings.llm

    def get_security_config(self) -> SecuritySettings:
        return self._settings.security

    def get_logging_config(self) -> ObservabilitySettings:
        return self._settings.observability

    def validate(self) -> bool:
        """Raise :class:`ConfigError` if the configuration is unsafe for its environment."""
        problems = []
        if not self._settings.database.url.get_secret_value():
            problems.append("database.url must be set")
        if not self._settings.redis.url.get_secret_value():
            problems.append("redis.url must be set")
        if self._settings.is_production:
            problems.extend(self._settings.production_problems())
            problems.extend(p for p in insecure_secret_problems(self._settings) if p not in problems)
        if problems:
            raise ConfigError("Configuration validation failed:\n- " + "\n- ".join(problems))
        return True

    def reload(self) -> None:
        """Re-read configuration. For the shared instance this also refreshes ``get_settings()``."""
        if self.config_path is None:
            reset_settings()
        self._settings = self._load()
        self._data = self._settings.model_dump()
