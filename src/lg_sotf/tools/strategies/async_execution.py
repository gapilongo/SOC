"""
Async execution strategy for tools.
"""

import asyncio
from typing import Any, Callable, Dict

from ...core.config.manager import ConfigManager


class AsyncExecutionStrategy:
    """Handles async execution of tools."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.timeout = config_manager.get('tools.execution_timeout', 30)
    
    async def execute_async(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function asynchronously with timeout."""
        try:
            return await asyncio.wait_for(func(*args, **kwargs), timeout=self.timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Tool execution timed out after {self.timeout} seconds")


# src/lg_sotf/tools/strategies/retry.py
"""
Retry strategy for tools.
"""

import asyncio
from typing import Any, Callable

from ...core.config.manager import ConfigManager


class RetryStrategy:
    """Handles retry logic for tool execution."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.max_retries = config_manager.get('tools.max_retries', 3)
        self.backoff_factor = config_manager.get('tools.backoff_factor', 2)
    
    async def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries:
                    wait_time = self.backoff_factor ** attempt
                    await asyncio.sleep(wait_time)
                    continue
                raise
        
        raise last_exception


# src/lg_sotf/tools/strategies/caching.py
"""
Caching strategy for tools.
"""

import hashlib
import json
from typing import Any, Dict, Optional

from ...core.config.manager import ConfigManager


class CachingStrategy:
    """Handles caching for tool results."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.cache: Dict[str, Any] = {}
        self.enabled = config_manager.get('tools.caching_enabled', True)
        self.ttl = config_manager.get('tools.cache_ttl', 300)
    
    def get_cache_key(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Generate cache key for tool execution."""
        key_data = f"{tool_name}:{json.dumps(args, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available."""
        if not self.enabled:
            return None
        return self.cache.get(cache_key)
    
    async def cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache the result."""
        if self.enabled:
            self.cache[cache_key] = result


# src/lg_sotf/tools/strategies/fallback.py
"""
Fallback strategy for tools.
"""

from typing import Any, Dict

from ...core.config.manager import ConfigManager


class FallbackStrategy:
    """Handles fallback logic for tool execution."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
    
    async def execute_fallback(self, tool_adapter: Any, args: Dict[str, Any], 
                             context: Dict[str, Any], error: Exception) -> Dict[str, Any]:
        """Execute fallback logic when primary execution fails."""
        return {
            "fallback": True,
            "error": str(error),
            "message": "Tool execution failed, using fallback response"
        }