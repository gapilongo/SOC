"""
Configuration manager implementation for LG-SOTF.

This module provides the main configuration management functionality
including environment-specific settings, validation, and hierarchical configuration.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml
from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

from lg_sotf.core.exceptions import ConfigError

load_dotenv()
class DatabaseConfig(BaseSettings):
    """Database configuration."""

    host: str = Field(default="localhost", env="DB_HOST")
    port: int = Field(default=5432, env="DB_PORT")
    database: str = Field(default="lg_sotf", env="DB_NAME")
    username: str = Field(default="lg_sotf", env="DB_USER")
    password: str = Field(default="password", env="DB_PASSWORD")
    pool_size: int = Field(default=10, env="DB_POOL_SIZE")
    max_overflow: int = Field(default=20, env="DB_MAX_OVERFLOW")


class RedisConfig(BaseSettings):
    """Redis configuration."""

    host: str = Field(default="localhost", env="REDIS_HOST")
    port: int = Field(default=6379, env="REDIS_PORT")
    password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    db: int = Field(default=0, env="REDIS_DB")
    max_connections: int = Field(default=10, env="REDIS_MAX_CONNECTIONS")


class AgentConfig(BaseSettings):
    """Agent configuration."""

    ingestion_batch_size: int = Field(default=100, env="INGESTION_BATCH_SIZE")
    ingestion_polling_interval: int = Field(
        default=30, env="INGESTION_POLLING_INTERVAL"
    )
    triage_confidence_threshold: int = Field(
        default=70, env="TRIAGE_CONFIDENCE_THRESHOLD"
    )
    analysis_max_iterations: int = Field(default=5, env="ANALYSIS_MAX_ITERATIONS")
    human_escalation_threshold: int = Field(
        default=40, env="HUMAN_ESCALATION_THRESHOLD"
    )


class LoggingConfig(BaseSettings):
    """Logging configuration."""

    level: str = Field(default="INFO", env="LOG_LEVEL")
    format: str = Field(default="json", env="LOG_FORMAT")
    file_path: Optional[str] = Field(default=None, env="LOG_FILE_PATH")
    max_file_size: str = Field(default="10MB", env="LOG_MAX_FILE_SIZE")
    backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")


class SecurityConfig(BaseSettings):
    """Security configuration."""

    encryption_key: str = Field(default="", env="ENCRYPTION_KEY")
    jwt_secret: str = Field(default="", env="JWT_SECRET")
    session_timeout: int = Field(default=3600, env="SESSION_TIMEOUT")
    max_login_attempts: int = Field(default=5, env="MAX_LOGIN_ATTEMPTS")


class LLMConfig(BaseSettings):
    """LLM configuration."""

    provider: str = Field(default="mock", env="LLM_PROVIDER")
    api_key: Optional[str] = Field(default=None, env="LLM_API_KEY")
    model: str = Field(default="default", env="LLM_MODEL")
    temperature: float = Field(default=0.7, env="LLM_TEMPERATURE")
    max_tokens: int = Field(default=1000, env="LLM_MAX_TOKENS")
    timeout: int = Field(default=30, env="LLM_TIMEOUT")
    base_url: Optional[str] = Field(default=None, env="LLM_BASE_URL")
    # Azure OpenAI specific
    endpoint: Optional[str] = Field(default=None, env="AZURE_OPENAI_ENDPOINT")
    deployment_name: Optional[str] = Field(default=None, env="AZURE_OPENAI_DEPLOYMENT")


class ConfigManager:
    """Configuration manager for LG-SOTF."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self._config = self._load_config()
        db_yaml = self._config.get("database", {})
        self._database_config = DatabaseConfig(**db_yaml)
        redis_yaml = self._config.get("redis", {})
        self._redis_config = RedisConfig(**redis_yaml)
        llm_yaml = self._config.get("llm", {})
        self._llm_config = LLMConfig(**llm_yaml)
        self._agent_config = AgentConfig()
        self._logging_config = LoggingConfig()
        self._security_config = SecurityConfig()

    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        env = os.getenv("LG_SOTF_ENV", "development")
        return f"configs/{env}.yaml"

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_file}")

            with open(config_file, "r") as f:
                config = yaml.safe_load(f)

            # Override with environment variables
            self._apply_env_overrides(config)

            return config

        except Exception as e:
            raise ConfigError(f"Failed to load configuration: {str(e)}")

    def _apply_env_overrides(self, config: Dict[str, Any]):
        """Apply environment variable overrides."""
        # This is a simplified version - in production, you'd want more sophisticated
        # environment variable handling
        env_mapping = {
            "LG_SOTF_LOG_LEVEL": ("logging", "level"),
            "LG_SOTF_DB_HOST": ("database", "host"),
            "LG_SOTF_REDIS_HOST": ("redis", "host"),
        }

        for env_var, config_path in env_mapping.items():
            if env_var in os.environ:
                self._set_nested_value(config, config_path, os.environ[env_var])

    def _set_nested_value(self, config: Dict[str, Any], path: tuple, value: Any):
        """Set a nested value in the configuration dictionary."""
        for key in path[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[path[-1]] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        try:
            keys = key.split(".")
            value = self._config

            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default

            return value

        except Exception as e:
            raise ConfigError(f"Failed to get configuration value '{key}': {str(e)}")

    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        """Get configuration for a specific agent."""
        yaml_config = self.get(f"agents.{agent_name}", {})
        if agent_name == "ingestion":
            yaml_config.setdefault("polling_interval", self._agent_config.ingestion_polling_interval)
        return yaml_config

    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool."""
        return self.get(f"tools.{tool_name}", {})

    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration."""
        return self._database_config

    def get_redis_config(self) -> RedisConfig:
        """Get Redis configuration."""
        return self._redis_config

    def get_agent_configs(self) -> AgentConfig:
        """Get agent configuration."""
        return self._agent_config

    def get_logging_config(self) -> LoggingConfig:
        """Get logging configuration."""
        return self._logging_config

    def get_security_config(self) -> SecurityConfig:
        """Get security configuration."""
        return self._security_config

    def get_llm_config(self) -> LLMConfig:
        """Get LLM configuration."""
        return self._llm_config

    def reload(self):
        """Reload configuration from file."""
        self._config = self._load_config()

    def validate(self) -> bool:
        """Validate configuration."""
        try:
            # Validate required configuration sections
            required_sections = ["agents", "tools", "storage"]
            for section in required_sections:
                if section not in self._config:
                    raise ConfigError(
                        f"Missing required configuration section: {section}"
                    )

            # Validate database configuration
            if not self._database_config.host:
                raise ConfigError("Database host is required")

            # Validate Redis configuration
            if not self._redis_config.host:
                raise ConfigError("Redis host is required")

            # Validate security configuration
            if not self._security_config.encryption_key:
                raise ConfigError("Encryption key is required")

            return True

        except Exception as e:
            raise ConfigError(f"Configuration validation failed: {str(e)}")
            raise ConfigError(f"Configuration validation failed: {str(e)}")
