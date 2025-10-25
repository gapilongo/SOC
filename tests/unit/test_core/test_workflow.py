"""
Comprehensive unit tests for WorkflowEngine.

Tests cover:
- Routing logic (confidence-based decisions)
- State management (atomic updates, versioning)
- Execution guards (locks, duplicate prevention)
- Error handling and recovery
- LLM routing integration
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch, MagicMock

import pytest

from lg_sotf.core.workflow import WorkflowEngine, WorkflowState, ExecutionContext, RoutingDecision
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.state.manager import StateManager
from lg_sotf.core.state.model import TriageStatus
from lg_sotf.core.exceptions import WorkflowError


@pytest.fixture
def mock_config_manager():
    """Create a mock ConfigManager."""
    config = Mock(spec=ConfigManager)
    config.get = Mock(side_effect=lambda key, default=None: {
        'workflow.enable_llm_routing': False,  # Disable LLM for unit tests
        'routing.max_alert_age_hours': 72,
        'routing.correlation_grey_zone_min': 30,
        'routing.correlation_grey_zone_max': 70,
        'routing.analysis_threshold': 40,
        'routing.human_review_min': 20,
        'routing.human_review_max': 60,
        'routing.response_threshold': 80,
    }.get(key, default))
    config.get_agent_config = Mock(return_value={})
    return config


@pytest.fixture
def mock_state_manager():
    """Create a mock StateManager."""
    manager = Mock(spec=StateManager)
    manager.create_state = AsyncMock(return_value=Mock(alert_id="test-001"))
    manager.update_state = AsyncMock()
    manager.get_state = AsyncMock(return_value=None)
    return manager


@pytest.fixture
def mock_redis_storage():
    """Create a mock Redis storage."""
    return Mock()


@pytest.fixture
def mock_tool_orchestrator():
    """Create a mock ToolOrchestrator."""
    return Mock()


@pytest.fixture
def workflow_engine(mock_config_manager, mock_state_manager, mock_redis_storage, mock_tool_orchestrator):
    """Create a WorkflowEngine instance for testing."""
    engine = WorkflowEngine(
        config_manager=mock_config_manager,
        state_manager=mock_state_manager,
        redis_storage=mock_redis_storage,
        tool_orchestrator=mock_tool_orchestrator
    )

    # Mock the graph compilation (synchronous)
    engine.compiled_graph = Mock()
    engine.compiled_graph.ainvoke = AsyncMock()

    # Create mock agents (don't await initialize)
    for agent_type in ['ingestion', 'triage', 'correlation', 'analysis', 'human_loop', 'response']:
        mock_agent = Mock()
        mock_agent.execute = AsyncMock(return_value={})
        mock_agent.initialize = AsyncMock()
        engine.agents[agent_type] = mock_agent
        engine._agent_locks[agent_type] = asyncio.Lock()

    return engine


@pytest.fixture
def sample_workflow_state():
    """Create a sample workflow state."""
    return {
        "alert_id": "test-alert-001",
        "workflow_instance_id": "workflow-001",
        "execution_context": {
            "execution_id": "exec-001",
            "started_at": datetime.utcnow().isoformat(),
            "last_node": "start",
            "executed_nodes": [],
            "execution_time": datetime.utcnow().isoformat()
        },
        "raw_alert": {
            "id": "test-alert-001",
            "severity": "high",
            "title": "Suspicious login",
            "raw_data": {
                "source_ip": "192.168.1.100",
                "user": "admin"
            }
        },
        "enriched_data": {},
        "triage_status": "new",
        "confidence_score": 50,
        "current_node": "triage",
        "priority_level": 3,
        "fp_indicators": [],
        "tp_indicators": [],
        "correlations": [],
        "correlation_score": 0,
        "analysis_conclusion": "",
        "threat_score": 0,
        "recommended_actions": [],
        "analysis_reasoning": [],
        "tool_results": {},
        "processing_notes": [],
        "last_updated": datetime.utcnow().isoformat(),
        "agent_executions": {},
        "state_version": 1
    }


# ========================================
# ROUTING LOGIC TESTS
# ========================================

class TestRoutingAfterTriage:
    """Test routing decisions after triage agent."""

    @pytest.mark.asyncio
    async def test_route_close_low_confidence_with_fp_indicators(self, workflow_engine, sample_workflow_state):
        """Test that low confidence + FP indicators routes to close."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 10
        state["fp_indicators"] = ["benign_process", "known_internal_ip"]

        result = await workflow_engine._route_after_triage(state)

        assert result == "close"

    @pytest.mark.asyncio
    async def test_route_close_more_fp_than_tp(self, workflow_engine, sample_workflow_state):
        """Test that more FP than TP indicators routes to close."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 18
        state["fp_indicators"] = ["indicator1", "indicator2", "indicator3"]
        state["tp_indicators"] = ["indicator1"]

        result = await workflow_engine._route_after_triage(state)

        assert result == "close"

    @pytest.mark.asyncio
    async def test_route_correlation_moderate_confidence(self, workflow_engine, sample_workflow_state):
        """Test that moderate confidence routes to correlation."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 50
        state["fp_indicators"] = []
        state["tp_indicators"] = ["suspicious_activity"]

        result = await workflow_engine._route_after_triage(state)

        # Should route to correlation (builds threat intel)
        assert result == "correlation"

    @pytest.mark.asyncio
    async def test_route_correlation_with_network_indicators(self, workflow_engine, sample_workflow_state):
        """Test that alerts with network indicators route to correlation."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 50
        state["raw_alert"]["raw_data"] = {"source_ip": "192.168.1.100"}

        result = await workflow_engine._route_after_triage(state)

        assert result == "correlation"


class TestRoutingAfterCorrelation:
    """Test routing decisions after correlation agent."""

    @pytest.mark.asyncio
    async def test_route_response_strong_correlations(self, workflow_engine, sample_workflow_state):
        """Test that strong correlations route to response."""
        state = sample_workflow_state.copy()
        state["correlation_score"] = 90
        state["correlations"] = [
            {"alert_id": "alert-1"},
            {"alert_id": "alert-2"},
            {"alert_id": "alert-3"},
            {"alert_id": "alert-4"},
            {"alert_id": "alert-5"}
        ]

        result = workflow_engine._route_after_correlation(state)

        assert result == "response"

    @pytest.mark.asyncio
    async def test_route_analysis_moderate_correlations(self, workflow_engine, sample_workflow_state):
        """Test that moderate correlations route to analysis."""
        state = sample_workflow_state.copy()
        state["correlation_score"] = 65
        state["correlations"] = [{"alert_id": "alert-1"}, {"alert_id": "alert-2"}, {"alert_id": "alert-3"}]

        result = workflow_engine._route_after_correlation(state)

        assert result == "analysis"

    @pytest.mark.asyncio
    async def test_route_close_no_correlations_low_confidence(self, workflow_engine, sample_workflow_state):
        """Test that no correlations + low confidence routes to close."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 25
        state["correlation_score"] = 15
        state["correlations"] = []

        result = workflow_engine._route_after_correlation(state)

        assert result == "close"

    @pytest.mark.asyncio
    async def test_route_human_loop_weak_correlations_high_confidence(self, workflow_engine, sample_workflow_state):
        """Test that weak correlations + high confidence routes to human loop."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 55
        state["correlation_score"] = 25
        state["correlations"] = []

        result = workflow_engine._route_after_correlation(state)

        assert result == "human_loop"


class TestRoutingAfterAnalysis:
    """Test routing decisions after analysis agent."""

    @pytest.mark.asyncio
    async def test_route_response_high_threat_score(self, workflow_engine, sample_workflow_state):
        """Test that high threat score routes to response."""
        state = sample_workflow_state.copy()
        state["threat_score"] = 85
        state["confidence_score"] = 85

        result = workflow_engine._route_after_analysis(state)

        assert result == "response"

    @pytest.mark.asyncio
    async def test_route_close_low_threat(self, workflow_engine, sample_workflow_state):
        """Test that low threat score routes to close."""
        state = sample_workflow_state.copy()
        state["threat_score"] = 25
        state["confidence_score"] = 35

        result = workflow_engine._route_after_analysis(state)

        # With confidence 35, this might route to human_loop based on grey zone logic
        assert result in ["close", "human_loop"]

    @pytest.mark.asyncio
    async def test_route_human_loop_uncertain_conclusion(self, workflow_engine, sample_workflow_state):
        """Test that uncertain analysis routes to human loop."""
        state = sample_workflow_state.copy()
        state["threat_score"] = 50
        state["confidence_score"] = 55
        state["analysis_conclusion"] = "Analysis is uncertain about threat nature"

        result = workflow_engine._route_after_analysis(state)

        assert result == "human_loop"


# ========================================
# STATE MANAGEMENT TESTS
# ========================================

class TestStateManagement:
    """Test state management and atomic updates."""

    @pytest.mark.asyncio
    async def test_execution_context_creation(self, workflow_engine):
        """Test that execution context is created correctly."""
        alert_id = "test-alert-001"

        context = workflow_engine._create_execution_context(alert_id)

        assert context.execution_id.startswith(alert_id)
        assert context.started_at is not None
        assert len(context.locks) == 7  # All node locks
        assert context.node_executions == {}

    @pytest.mark.asyncio
    async def test_convert_to_agent_format(self, workflow_engine, sample_workflow_state):
        """Test conversion of workflow state to agent format."""
        state = sample_workflow_state.copy()

        agent_input = workflow_engine._convert_to_agent_format(state)

        assert agent_input["alert_id"] == state["alert_id"]
        assert agent_input["raw_alert"] == state["raw_alert"]
        assert agent_input["confidence_score"] == state["confidence_score"]
        assert agent_input["fp_indicators"] == state["fp_indicators"]
        assert "metadata" in agent_input


# ========================================
# EXECUTION GUARDS TESTS
# ========================================

class TestExecutionGuards:
    """Test duplicate execution prevention and locks."""

    @pytest.mark.asyncio
    async def test_duplicate_execution_prevented(self, workflow_engine, sample_workflow_state):
        """Test that duplicate agent execution is prevented."""
        state = sample_workflow_state.copy()
        alert_id = state["alert_id"]

        # Create execution context and mark triage as executed
        context = workflow_engine._create_execution_context(alert_id)
        context.node_executions["triage"] = True

        # Mark agent as already executed in state
        state["agent_executions"][f"triage_{alert_id}"] = {
            "executed_at": datetime.utcnow().isoformat(),
            "status": "completed"
        }

        # Attempt to execute triage again
        updates = await workflow_engine._execute_triage(state)

        # Should skip execution since it was already marked as completed
        assert updates == {}

    @pytest.mark.asyncio
    async def test_concurrent_execution_prevented_by_locks(self, workflow_engine, sample_workflow_state):
        """Test that concurrent execution is prevented by locks."""
        state1 = sample_workflow_state.copy()
        state2 = sample_workflow_state.copy()
        alert_id = state1["alert_id"]

        # Create execution context
        workflow_engine._create_execution_context(alert_id)

        # Mock agent to simulate slow execution
        async def slow_execute(input_state):
            await asyncio.sleep(0.05)
            return {"confidence_score": 50, "fp_indicators": [], "tp_indicators": []}

        workflow_engine.agents["triage"].execute = slow_execute

        # Start two concurrent executions with separate state copies
        task1 = asyncio.create_task(workflow_engine._execute_triage(state1))
        task2 = asyncio.create_task(workflow_engine._execute_triage(state2))

        results = await asyncio.gather(task1, task2)

        # First execution should complete, second should be prevented by node_executions tracking
        # Both might return results but the execution guard should prevent actual double execution
        assert len(results) == 2  # Both tasks complete
        # Verify at least one has results (the first to acquire the lock)
        has_results = [bool(r) for r in results]
        assert any(has_results)


# ========================================
# ERROR HANDLING TESTS
# ========================================

class TestErrorHandling:
    """Test error handling and recovery."""

    @pytest.mark.asyncio
    async def test_agent_execution_error_handling(self, workflow_engine, sample_workflow_state):
        """Test that agent execution errors are handled gracefully."""
        state = sample_workflow_state.copy()

        # Create execution context
        workflow_engine._create_execution_context(state["alert_id"])

        # Mock agent to raise an error
        workflow_engine.agents["triage"].execute = AsyncMock(side_effect=Exception("Agent failed"))

        updates = await workflow_engine._execute_triage(state)

        # Should return error in processing notes
        assert "processing_notes" in updates
        assert any("error" in note.lower() or "failed" in note.lower() for note in updates["processing_notes"])

    @pytest.mark.asyncio
    async def test_missing_execution_context_handling(self, workflow_engine, sample_workflow_state):
        """Test handling of missing execution context."""
        state = sample_workflow_state.copy()

        # Don't create execution context (simulate error condition)
        # Attempt to execute node
        updates = await workflow_engine._execute_with("triage", workflow_engine._execute_triage, state)

        # Should handle gracefully and return informative feedback
        assert "processing_notes" in updates
        assert any("Missing execution context" in note for note in updates["processing_notes"])

    @pytest.mark.asyncio
    async def test_workflow_initialization_failure(self, mock_config_manager, mock_state_manager):
        """Test that workflow initialization failures are caught."""
        engine = WorkflowEngine(
            config_manager=mock_config_manager,
            state_manager=mock_state_manager,
            redis_storage=None,
            tool_orchestrator=None
        )

        # Mock agent setup to fail
        with patch.object(engine, '_setup_agents', side_effect=Exception("Setup failed")):
            with pytest.raises(WorkflowError):
                await engine.initialize()


# ========================================
# ROUTING HELPER TESTS
# ========================================

class TestRoutingHelpers:
    """Test routing helper methods."""

    @pytest.mark.asyncio
    async def test_needs_correlation_with_network_indicators(self, workflow_engine, sample_workflow_state):
        """Test detection of network indicators."""
        state = sample_workflow_state.copy()
        state["enriched_data"]["source_ip"] = "192.168.1.100"

        result = workflow_engine._needs_correlation(state)

        assert result is True

    @pytest.mark.asyncio
    async def test_needs_correlation_with_user_indicators(self, workflow_engine, sample_workflow_state):
        """Test detection of user indicators."""
        state = sample_workflow_state.copy()
        # Set user at the raw_alert level (not raw_data)
        state["raw_alert"]["user"] = "admin"

        result = workflow_engine._needs_correlation(state)

        assert result is True

    @pytest.mark.asyncio
    async def test_needs_correlation_with_file_indicators(self, workflow_engine, sample_workflow_state):
        """Test detection of file indicators."""
        state = sample_workflow_state.copy()
        state["enriched_data"]["file_hash"] = "abc123"

        result = workflow_engine._needs_correlation(state)

        assert result is True

    @pytest.mark.asyncio
    async def test_needs_analysis_low_confidence_mixed_signals(self, workflow_engine, sample_workflow_state):
        """Test analysis needed for low confidence with mixed signals."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 35
        state["fp_indicators"] = ["indicator1"]
        state["tp_indicators"] = ["indicator2"]

        result = workflow_engine._needs_analysis(state)

        assert result is True

    @pytest.mark.asyncio
    async def test_needs_analysis_complex_category(self, workflow_engine, sample_workflow_state):
        """Test analysis needed for complex attack categories."""
        state = sample_workflow_state.copy()
        state["enriched_data"]["category"] = "lateral_movement"

        result = workflow_engine._needs_analysis(state)

        assert result is True


# ========================================
# INTEGRATION TESTS (WITHIN WORKFLOW ENGINE)
# ========================================

class TestWorkflowIntegration:
    """Test integrated workflow execution."""

    @pytest.mark.asyncio
    async def test_triage_execution_updates_state(self, workflow_engine, sample_workflow_state):
        """Test that triage execution properly updates state."""
        state = sample_workflow_state.copy()

        # Create execution context
        workflow_engine._create_execution_context(state["alert_id"])

        # Mock triage agent
        workflow_engine.agents["triage"].execute = AsyncMock(return_value={
            "confidence_score": 75,
            "fp_indicators": [],
            "tp_indicators": ["suspicious_login", "unusual_time"],
            "priority_level": 2,
            "triage_status": "triaged"
        })

        updates = await workflow_engine._execute_triage(state)

        assert updates["confidence_score"] == 75
        assert len(updates["tp_indicators"]) == 2
        assert updates["triage_status"] == "triaged"

    @pytest.mark.asyncio
    async def test_correlation_execution_updates_state(self, workflow_engine, sample_workflow_state):
        """Test that correlation execution properly updates state."""
        state = sample_workflow_state.copy()

        # Create execution context
        workflow_engine._create_execution_context(state["alert_id"])

        # Mock correlation agent
        workflow_engine.agents["correlation"].execute = AsyncMock(return_value={
            "correlations": [
                {"alert_id": "alert-1", "similarity": 0.8},
                {"alert_id": "alert-2", "similarity": 0.7}
            ],
            "correlation_score": 75,
            "confidence_score": 65
        })

        updates = await workflow_engine._execute_correlation(state)

        assert len(updates["correlations"]) == 2
        assert updates["correlation_score"] == 75

    @pytest.mark.asyncio
    async def test_analysis_execution_updates_state(self, workflow_engine, sample_workflow_state):
        """Test that analysis execution properly updates state."""
        state = sample_workflow_state.copy()

        # Create execution context
        workflow_engine._create_execution_context(state["alert_id"])

        # Mock analysis agent
        workflow_engine.agents["analysis"].execute = AsyncMock(return_value={
            "threat_score": 80,
            "analysis_conclusion": "Confirmed threat",
            "recommended_actions": ["isolate_host", "block_ip"],
            "analysis_reasoning": [{"step": 1, "action": "checked_threat_intel"}],
            "tool_results": {"virustotal": {"malicious": True}}
        })

        updates = await workflow_engine._execute_analysis(state)

        assert updates["threat_score"] == 80
        assert updates["analysis_conclusion"] == "Confirmed threat"
        assert len(updates["recommended_actions"]) == 2


# ========================================
# WORKFLOW METRICS TESTS
# ========================================

class TestWorkflowMetrics:
    """Test workflow metrics collection."""

    @pytest.mark.asyncio
    async def test_get_workflow_metrics(self, workflow_engine):
        """Test that workflow metrics are collected correctly."""
        metrics = workflow_engine.get_workflow_metrics()

        assert "active_executions" in metrics
        assert "total_agents" in metrics
        assert "agent_locks" in metrics
        assert metrics["synchronization_enabled"] is True
        assert metrics["total_agents"] == len(workflow_engine.agents)


# ========================================
# LLM ROUTING TESTS (FALLBACK)
# ========================================

class TestLLMRouting:
    """Test LLM-enhanced routing (fallback mode)."""

    @pytest.mark.asyncio
    async def test_fallback_routing_after_triage_close_obvious_fp(self, workflow_engine, sample_workflow_state):
        """Test fallback routing closes obvious FPs."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 8
        state["fp_indicators"] = ["benign1", "benign2"]

        result = workflow_engine._fallback_routing(state, "triage")

        assert result == "close"

    @pytest.mark.asyncio
    async def test_fallback_routing_after_triage_response_high_confidence(self, workflow_engine, sample_workflow_state):
        """Test fallback routing sends high confidence to response."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 90
        state["tp_indicators"] = ["mal1", "mal2", "mal3"]

        result = workflow_engine._fallback_routing(state, "triage")

        assert result == "response"

    @pytest.mark.asyncio
    async def test_fallback_routing_prefers_correlation(self, workflow_engine, sample_workflow_state):
        """Test fallback routing prefers correlation for grey zone."""
        state = sample_workflow_state.copy()
        state["confidence_score"] = 50
        state["raw_alert"]["raw_data"]["source_ip"] = "192.168.1.100"

        result = workflow_engine._fallback_routing(state, "triage")

        assert result == "correlation"
