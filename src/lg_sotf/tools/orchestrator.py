"""
Tool orchestrator for LG-SOTF.

This module provides the main tool orchestration functionality,
including tool execution, caching, and fallback mechanisms.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.audit.metrics import MetricsCollector
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import ToolError
from lg_sotf.tools.registry import ToolRegistry
from lg_sotf.tools.strategies.async_execution import AsyncExecutionStrategy
from lg_sotf.tools.strategies.caching import CachingStrategy
from lg_sotf.tools.strategies.fallback import FallbackStrategy
from lg_sotf.tools.strategies.retry import RetryStrategy


class ToolOrchestrator:
    """Orchestrates tool execution with various strategies."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.registry = ToolRegistry()
        self.audit_logger = AuditLogger()
        self.metrics = MetricsCollector()
        
        # Initialize strategies
        self.async_strategy = AsyncExecutionStrategy(config_manager)
        self.retry_strategy = RetryStrategy(config_manager)
        self.caching_strategy = CachingStrategy(config_manager)
        self.fallback_strategy = FallbackStrategy(config_manager)
    
    async def execute_tool(self, tool_name: str, tool_args: Dict[str, Any], 
                          context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a tool with all strategies applied."""
        try:
            start_time = datetime.utcnow()
            execution_id = self._generate_execution_id()
            
            # Log execution start
            self.audit_logger.log_tool_execution_start(
                tool_name=tool_name,
                execution_id=execution_id,
                tool_args=tool_args,
                context=context
            )
            
            # Get tool adapter
            tool_adapter = self.registry.get_tool(tool_name)
            
            # Apply caching strategy
            cache_key = self.caching_strategy.get_cache_key(tool_name, tool_args)
            cached_result = await self.caching_strategy.get_cached_result(cache_key)
            
            if cached_result:
                self.audit_logger.log_tool_execution_end(
                    tool_name=tool_name,
                    execution_id=execution_id,
                    result=cached_result,
                    cached=True
                )
                return cached_result
            
            # Apply retry strategy
            result = await self.retry_strategy.execute_with_retry(
                self._execute_tool_with_fallback,
                tool_adapter,
                tool_args,
                context
            )
            
            # Cache result
            await self.caching_strategy.cache_result(cache_key, result)
            
            # Log execution end
            self.audit_logger.log_tool_execution_end(
                tool_name=tool_name,
                execution_id=execution_id,
                result=result,
                cached=False
            )
            
            # Record metrics
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            self.metrics.record_tool_execution(tool_name, execution_time, True)
            
            return result
            
        except Exception as e:
            # Record error metrics
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            self.metrics.record_tool_execution(tool_name, execution_time, False)
            
            raise ToolError(f"Failed to execute tool {tool_name}: {str(e)}")
    
    async def _execute_tool_with_fallback(self, tool_adapter, tool_args: Dict[str, Any], 
                                         context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool with fallback strategy."""
        try:
            # Apply async execution strategy
            return await self.async_strategy.execute_async(
                tool_adapter.execute,
                tool_args,
                context
            )
        except Exception as e:
            # Apply fallback strategy
            return await self.fallback_strategy.execute_fallback(
                tool_adapter,
                tool_args,
                context,
                e
            )
    
    async def execute_tools_parallel(self, tool_calls: List[Dict[str, Any]], 
                                   context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Execute multiple tools in parallel."""
        try:
            tasks = []
            for tool_call in tool_calls:
                task = self.execute_tool(
                    tool_call['tool_name'],
                    tool_call['tool_args'],
                    context
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    # Log error and return error result
                    self.audit_logger.log_tool_error(
                        tool_calls[i]['tool_name'],
                        result
                    )
                    processed_results.append({
                        'tool_name': tool_calls[i]['tool_name'],
                        'error': str(result),
                        'success': False
                    })
                else:
                    processed_results.append({
                        'tool_name': tool_calls[i]['tool_name'],
                        'result': result,
                        'success': True
                    })
            
            return processed_results
            
        except Exception as e:
            raise ToolError(f"Failed to execute tools in parallel: {str(e)}")
    
    def register_tool(self, tool_name: str, tool_adapter_class: Type, 
                     config: Dict[str, Any] = None):
        """Register a tool with the orchestrator."""
        self.registry.register_tool(tool_name, tool_adapter_class, config)
    
    def get_tool(self, tool_name: str):
        """Get a registered tool."""
        return self.registry.get_tool(tool_name)
    
    def list_tools(self) -> List[str]:
        """List all registered tools."""
        return self.registry.list_tools()
    
    def _generate_execution_id(self) -> str:
        """Generate unique execution ID."""
        import uuid
        return str(uuid.uuid4())