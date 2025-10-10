"""
Base plugin interface for ingestion sources.

All ingestion plugins must inherit from this base class.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional


class IngestionPlugin(ABC):
    """Base class for all ingestion plugins."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the plugin.
        
        Args:
            config: Configuration dictionary for the plugin
        """
        self.config = config
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
        self.initialized = False
        
        # Common configuration
        self.enabled = config.get("enabled", True)
        self.timeout = config.get("timeout", 30)
        self.retry_attempts = config.get("retry_attempts", 3)
        self.retry_delay = config.get("retry_delay", 1.0)
        
        # Rate limiting
        self.rate_limit = config.get("rate_limit", 100)  # requests per minute
        self.last_request_time = None
        
        # Metrics
        self.fetch_count = 0
        self.error_count = 0
        self.last_fetch_time = None

    @abstractmethod
    async def initialize(self):
        """Initialize the plugin.
        
        This method should:
        - Validate configuration
        - Establish connections
        - Authenticate if needed
        - Perform any necessary setup
        """
        pass

    @abstractmethod
    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from the source.
        
        Args:
            since: Start time for alert retrieval
            until: End time for alert retrieval
            limit: Maximum number of alerts to retrieve
            query: Optional custom query/filter
            
        Returns:
            List of raw alert dictionaries
        """
        pass

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connection to the data source.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass

    @abstractmethod
    async def cleanup(self):
        """Cleanup plugin resources.
        
        This method should:
        - Close connections
        - Release resources
        - Perform any necessary cleanup
        """
        pass

    async def health_check(self) -> bool:
        """Perform health check on the plugin.
        
        Returns:
            True if plugin is healthy, False otherwise
        """
        try:
            if not self.initialized:
                return False
            
            # Test connection
            return await self.test_connection()
            
        except Exception as e:
            self.logger.error(f"Health check failed for {self.name}: {e}")
            return False

    def get_metrics(self) -> Dict[str, Any]:
        """Get plugin metrics.
        
        Returns:
            Dictionary containing plugin metrics
        """
        return {
            "name": self.name,
            "enabled": self.enabled,
            "initialized": self.initialized,
            "fetch_count": self.fetch_count,
            "error_count": self.error_count,
            "last_fetch_time": self.last_fetch_time.isoformat() if self.last_fetch_time else None,
            "config_keys": list(self.config.keys())
        }

    def _update_metrics(self, success: bool):
        """Update plugin metrics.
        
        Args:
            success: Whether the operation was successful
        """
        self.fetch_count += 1
        if not success:
            self.error_count += 1
        self.last_fetch_time = datetime.utcnow()

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value.
        
        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value