"""
Tests for the workflow engine.
"""

from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.state.manager import StateManager
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.storage.postgres import PostgreSQLStorage


class TestWorkflowEngine:
    """Test cases for WorkflowEngine."""
    
    @pytest_asyncio.fixture
    async def workflow_engine(self, config_manager, state_manager):
        """Create a test workflow engine."""
        config = config_manager  # No await, assuming synchronous
        state = await state_manager  # Await to resolve coroutine
        return WorkflowEngine(config, state)
    
    @pytest.mark.asyncio
    async def test_workflow_engine_initialization(self, workflow_engine):
        """Test workflow engine initialization."""
        assert workflow_engine.config is not None
        assert workflow_engine.state_manager is not None
        assert workflow_engine.graph is not None
        assert workflow_engine.compiled_graph is not None
    
    @pytest.mark.asyncio
    async def test_execute_workflow_success(self, workflow_engine, sample_alert):
        """Test successful workflow execution."""
        workflow_engine.state_manager.create_state = AsyncMock()
        workflow_engine.state_manager.create_state.return_value = Mock()
        workflow_engine.state_manager.create_state.return_value.dict.return_value = sample_alert
        
        workflow_engine.compiled_graph.ainvoke = AsyncMock()
        workflow_engine.compiled_graph.ainvoke.return_value = {"status": "completed"}
        
        result = await workflow_engine.execute_workflow("test-alert-001", sample_alert)
        
        assert result == {"status": "completed"}
        workflow_engine.state_manager.create_state.assert_called_once()
        workflow_engine.compiled_graph.ainvoke.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_workflow_error(self, workflow_engine, sample_alert):
        """Test workflow execution with error."""
        workflow_engine.state_manager.create_state = AsyncMock()
        workflow_engine.state_manager.create_state.side_effect = Exception("Test error")
        
        with pytest.raises(Exception) as exc_info:
            await workflow_engine.execute_workflow("test-alert-001", sample_alert)
        
        assert "Test error" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_build_workflow_graph(self, workflow_engine):
        """Test workflow graph building."""
        graph = workflow_engine._build_workflow_graph()  # Synchronous method
        
        assert graph is not None
        assert hasattr(graph, 'nodes')
        assert hasattr(graph, 'edges')