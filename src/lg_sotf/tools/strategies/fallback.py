"""
Fallback strategy for tools.
"""

from typing import Any, Dict

from lg_sotf.core.config.manager import ConfigManager


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