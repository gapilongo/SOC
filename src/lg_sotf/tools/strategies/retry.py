"""
Retry strategy for tools.
"""

import asyncio
from typing import Any, Callable

from lg_sotf.core.config.manager import ConfigManager


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
