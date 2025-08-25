"""
Async execution strategy for tools.
"""

import asyncio
from typing import Any, Callable, Dict

from lg_sotf.core.config.manager import ConfigManager


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
