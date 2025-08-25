"""
Base storage backend for LG-SOTF.

This module provides the abstract base class for all storage backends,
ensuring consistent interface across different storage implementations.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from lg_sotf.core.exceptions import StorageError


class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    async def save_state(self, alert_id: str, workflow_instance_id: str, 
                        state_data: Dict[str, Any]) -> None:
        """Save state data."""
        pass
    
    @abstractmethod
    async def get_state(self, alert_id: str, workflow_instance_id: str) -> Optional[Dict[str, Any]]:
        """Get state data."""
        pass
    
    @abstractmethod
    async def get_state_history(self, alert_id: str, workflow_instance_id: str) -> List[Dict[str, Any]]:
        """Get state history."""
        pass
    
    @abstractmethod
    async def delete_state(self, alert_id: str, workflow_instance_id: str) -> None:
        """Delete state data."""
        pass
    
    @abstractmethod
    async def save_config(self, key: str, config_data: Dict[str, Any]) -> None:
        """Save configuration data."""
        pass
    
    @abstractmethod
    async def get_config(self, key: str) -> Optional[Dict[str, Any]]:
        """Get configuration data."""
        pass
    
    @abstractmethod
    async def save_metrics(self, metrics_data: Dict[str, Any]) -> None:
        """Save metrics data."""
        pass
    
    @abstractmethod
    async def get_metrics(self, metric_name: str, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """Get metrics data."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check storage health."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close storage connection."""
        pass