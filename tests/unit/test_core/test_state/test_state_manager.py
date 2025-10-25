"""
Comprehensive unit tests for StateManager.

Tests cover:
- State creation and persistence
- State versioning and history
- State updates with conflict detection
- Historical query methods (correlation support)
- Agent execution tracking
- Workflow history tracking
"""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, MagicMock, patch

import pytest

from lg_sotf.core.state.manager import StateManager
from lg_sotf.core.state.model import SOCState, StateVersion, AgentExecution, TriageStatus, AgentExecutionStatus
from lg_sotf.core.exceptions import StateError
from lg_sotf.storage.base import StorageBackend


@pytest.fixture
def mock_storage_backend():
    """Create a mock storage backend."""
    storage = Mock(spec=StorageBackend)
    storage.save_state = AsyncMock()
    storage.get_state = AsyncMock(return_value=None)
    storage.get_state_history = AsyncMock(return_value=[])
    # Mock PostgreSQL pool for historical queries
    storage.pool = Mock()
    storage.pool.acquire = MagicMock()
    return storage


@pytest.fixture
def state_manager(mock_storage_backend):
    """Create a StateManager instance for testing."""
    return StateManager(storage_backend=mock_storage_backend)


@pytest.fixture
def sample_raw_alert():
    """Create a sample raw alert."""
    return {
        "id": "alert-001",
        "source": "test-siem",
        "severity": "high",
        "title": "Suspicious activity detected",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "user": "admin",
            "process": "powershell.exe"
        }
    }


# ========================================
# STATE CREATION TESTS
# ========================================

class TestStateCreation:
    """Test state creation and initialization."""

    @pytest.mark.asyncio
    async def test_create_state_success(self, state_manager, sample_raw_alert):
        """Test successful state creation."""
        alert_id = "alert-001"
        workflow_instance_id = "workflow-001"

        state = await state_manager.create_state(
            alert_id=alert_id,
            raw_alert=sample_raw_alert,
            workflow_instance_id=workflow_instance_id,
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        assert state.alert_id == alert_id
        assert state.workflow_instance_id == workflow_instance_id
        assert state.raw_alert == sample_raw_alert
        assert state.current_node == "ingestion"
        # add_version increments state_version, so it becomes 2 after adding the first version
        assert state.state_version == 2
        assert len(state.version_history) == 1

    @pytest.mark.asyncio
    async def test_create_state_initializes_version_history(self, state_manager, sample_raw_alert):
        """Test that state creation initializes version history."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        assert len(state.version_history) == 1
        first_version = state.version_history[0]
        assert first_version.version == 1
        assert first_version.author_type == "system"
        assert first_version.author_id == "test_system"
        assert "Initial state creation" in first_version.changes_summary

    @pytest.mark.asyncio
    async def test_create_state_persists_to_storage(self, state_manager, sample_raw_alert, mock_storage_backend):
        """Test that state creation persists to storage."""
        await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        # Verify storage was called
        mock_storage_backend.save_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_state_logs_audit(self, state_manager, sample_raw_alert):
        """Test that state creation logs audit trail."""
        with patch.object(state_manager.audit_logger, 'log_state_creation') as mock_log:
            state = await state_manager.create_state(
                alert_id="alert-001",
                raw_alert=sample_raw_alert,
                workflow_instance_id="workflow-001",
                initial_node="ingestion",
                author_type="system",
                author_id="test_system"
            )

            mock_log.assert_called_once_with(state)


# ========================================
# STATE UPDATE TESTS
# ========================================

class TestStateUpdates:
    """Test state updates and versioning."""

    @pytest.mark.asyncio
    async def test_update_state_increments_version(self, state_manager, sample_raw_alert):
        """Test that updating state increments version."""
        # Create initial state
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        initial_version = state.state_version

        # Update state
        updates = {"confidence_score": 75, "triage_status": "triaged"}
        updated_state = await state_manager.update_state(
            state=state,
            updates=updates,
            author_type="agent",
            author_id="triage_agent",
            changes_summary="Triage completed"
        )

        assert updated_state.state_version == initial_version + 1

    @pytest.mark.asyncio
    async def test_update_state_applies_updates(self, state_manager, sample_raw_alert):
        """Test that updates are correctly applied to state."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        updates = {
            "confidence_score": 85,
            "triage_status": "triaged",
            "priority_level": 2
        }

        updated_state = await state_manager.update_state(
            state=state,
            updates=updates,
            author_type="agent",
            author_id="triage_agent",
            changes_summary="Triage completed"
        )

        assert updated_state.confidence_score == 85
        assert updated_state.triage_status == TriageStatus.TRIAGED
        assert updated_state.priority_level == 2

    @pytest.mark.asyncio
    async def test_update_state_adds_version_record(self, state_manager, sample_raw_alert):
        """Test that state updates add version records."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        initial_version_count = len(state.version_history)

        updates = {"confidence_score": 75}
        updated_state = await state_manager.update_state(
            state=state,
            updates=updates,
            author_type="agent",
            author_id="triage_agent",
            changes_summary="Triage completed"
        )

        assert len(updated_state.version_history) == initial_version_count + 1
        latest_version = updated_state.version_history[-1]
        assert latest_version.author_id == "triage_agent"
        assert "Triage completed" in latest_version.changes_summary

    @pytest.mark.asyncio
    async def test_update_state_persists_changes(self, state_manager, sample_raw_alert, mock_storage_backend):
        """Test that state updates are persisted."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        # Reset mock to count only update calls
        mock_storage_backend.save_state.reset_mock()

        updates = {"confidence_score": 75}
        await state_manager.update_state(
            state=state,
            updates=updates,
            author_type="agent",
            author_id="triage_agent",
            changes_summary="Triage completed"
        )

        # Verify persistence was called
        assert mock_storage_backend.save_state.called

    @pytest.mark.asyncio
    async def test_update_state_nested_fields(self, state_manager, sample_raw_alert):
        """Test updating nested fields in state."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        updates = {
            "enriched_data.threat_intel": {"reputation": "malicious"},
            "metadata.analyst_notes": "Needs investigation"
        }

        updated_state = await state_manager.update_state(
            state=state,
            updates=updates,
            author_type="agent",
            author_id="correlation_agent",
            changes_summary="Added threat intel"
        )

        # Verify nested updates were applied
        assert updated_state.enriched_data.get("threat_intel") == {"reputation": "malicious"}
        assert updated_state.metadata.get("analyst_notes") == "Needs investigation"


# ========================================
# AGENT EXECUTION TRACKING TESTS
# ========================================

class TestAgentExecutionTracking:
    """Test agent execution tracking."""

    @pytest.mark.asyncio
    async def test_add_agent_execution(self, state_manager, sample_raw_alert):
        """Test adding agent execution record."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        execution = AgentExecution(
            agent_name="triage",
            execution_id="exec-001",
            start_time=datetime.utcnow(),
            status=AgentExecutionStatus.COMPLETED,
            inputs={"alert_id": "alert-001"},
            outputs={"confidence_score": 75}
        )

        updated_state = await state_manager.add_agent_execution(
            state=state,
            execution=execution,
            author_type="agent",
            author_id="triage_agent"
        )

        assert len(updated_state.agent_executions) == 1
        assert updated_state.agent_executions[0].agent_name == "triage"
        assert updated_state.agent_executions[0].status == AgentExecutionStatus.COMPLETED


# ========================================
# STATE RETRIEVAL TESTS
# ========================================

class TestStateRetrieval:
    """Test state retrieval from storage."""

    @pytest.mark.asyncio
    async def test_get_state_success(self, state_manager, mock_storage_backend, sample_raw_alert):
        """Test retrieving existing state."""
        # Mock storage to return state data
        state_data = {
            "alert_id": "alert-001",
            "workflow_instance_id": "workflow-001",
            "raw_alert": sample_raw_alert,
            "enriched_data": {},
            "triage_status": "new",
            "confidence_score": 0,
            "fp_indicators": [],
            "tp_indicators": [],
            "current_node": "ingestion",
            "next_nodes": ["ingestion"],
            "state_version": 1,
            "created_at": datetime.utcnow(),
            "last_updated": datetime.utcnow(),
            "version_history": [],
            "agent_executions": [],
            "workflow_history": [],
            "human_feedback": None,
            "escalation_level": 0,
            "assigned_analyst": None,
            "response_actions": [],
            "playbook_executed": None,
            "metadata": {},
            "tags": [],
            "priority_level": 3
        }
        mock_storage_backend.get_state.return_value = state_data

        state = await state_manager.get_state("alert-001", "workflow-001")

        assert state is not None
        assert state.alert_id == "alert-001"

    @pytest.mark.asyncio
    async def test_get_state_not_found(self, state_manager, mock_storage_backend):
        """Test retrieving non-existent state."""
        mock_storage_backend.get_state.return_value = None

        state = await state_manager.get_state("nonexistent", "workflow-999")

        assert state is None


# ========================================
# HISTORICAL QUERY TESTS (CORRELATION SUPPORT)
# ========================================

class TestHistoricalQueries:
    """Test historical query methods for correlation."""

    @pytest.mark.asyncio
    async def test_query_alerts_by_indicator(self, state_manager, mock_storage_backend):
        """Test querying alerts by specific indicator."""
        # Mock PostgreSQL connection and results
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {
                "alert_id": "alert-001",
                "workflow_instance_id": "workflow-001",
                "state_data": json.dumps({"alert_id": "alert-001"}),
                "created_at": datetime.utcnow()
            }
        ])

        mock_storage_backend.pool.acquire.return_value.__aenter__.return_value = mock_conn

        results = await state_manager.query_alerts_by_indicator(
            indicator_type="source_ip",
            indicator_value="192.168.1.100",
            time_window_minutes=60,
            limit=10
        )

        assert len(results) > 0
        assert results[0]["alert_id"] == "alert-001"

    @pytest.mark.asyncio
    async def test_query_similar_alerts(self, state_manager):
        """Test querying similar alerts based on multiple indicators."""
        alert_data = {
            "raw_data": {
                "source_ip": "192.168.1.100",
                "user": "admin",
                "file_hash": "abc123"
            }
        }

        # Mock the query_alerts_by_indicator method
        with patch.object(state_manager, 'query_alerts_by_indicator', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = [
                {
                    "alert_id": "alert-002",
                    "workflow_instance_id": "workflow-002",
                    "state_data": {},
                    "created_at": datetime.utcnow().isoformat()
                }
            ]

            results = await state_manager.query_similar_alerts(
                alert_data=alert_data,
                similarity_threshold=0.5,
                time_window_minutes=1440,
                limit=50
            )

            # Should have called query_alerts_by_indicator for each indicator
            assert mock_query.call_count == 3  # source_ip, user, file_hash

    @pytest.mark.asyncio
    async def test_get_alert_frequency(self, state_manager):
        """Test getting alert frequency statistics."""
        # Mock query_alerts_by_indicator to return sample alerts
        with patch.object(state_manager, 'query_alerts_by_indicator', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = [
                {"alert_id": f"alert-{i}", "created_at": datetime.utcnow().isoformat()}
                for i in range(5)
            ]

            stats = await state_manager.get_alert_frequency(
                indicator_type="source_ip",
                indicator_value="192.168.1.100",
                time_window_minutes=60
            )

            assert stats["total_count"] == 5
            assert stats["indicator_type"] == "source_ip"
            assert stats["indicator_value"] == "192.168.1.100"
            assert "alerts_per_hour" in stats
            assert stats["alerts_per_hour"] == 5.0  # 5 alerts in 1 hour window


# ========================================
# ERROR HANDLING TESTS
# ========================================

class TestErrorHandling:
    """Test error handling in state manager."""

    @pytest.mark.asyncio
    async def test_create_state_storage_failure(self, state_manager, sample_raw_alert, mock_storage_backend):
        """Test handling of storage failure during state creation."""
        mock_storage_backend.save_state.side_effect = Exception("Storage error")

        with pytest.raises(StateError):
            await state_manager.create_state(
                alert_id="alert-001",
                raw_alert=sample_raw_alert,
                workflow_instance_id="workflow-001",
                initial_node="ingestion",
                author_type="system",
                author_id="test_system"
            )

    @pytest.mark.asyncio
    async def test_update_state_storage_failure(self, state_manager, sample_raw_alert, mock_storage_backend):
        """Test handling of storage failure during state update."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        # Make save_state fail on next call
        mock_storage_backend.save_state.side_effect = Exception("Storage error")

        with pytest.raises(StateError):
            await state_manager.update_state(
                state=state,
                updates={"confidence_score": 75},
                author_type="agent",
                author_id="triage_agent",
                changes_summary="Update failed"
            )

    @pytest.mark.asyncio
    async def test_get_state_storage_failure(self, state_manager, mock_storage_backend):
        """Test handling of storage failure during state retrieval."""
        mock_storage_backend.get_state.side_effect = Exception("Storage error")

        with pytest.raises(StateError):
            await state_manager.get_state("alert-001", "workflow-001")


# ========================================
# STATE HASHING TESTS
# ========================================

class TestStateHashing:
    """Test state hashing for change detection."""

    @pytest.mark.asyncio
    async def test_hash_state_consistency(self, state_manager, sample_raw_alert):
        """Test that hashing same state produces same hash."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        hash1 = state_manager._hash_state(state)
        hash2 = state_manager._hash_state(state)

        assert hash1 == hash2

    @pytest.mark.asyncio
    async def test_hash_state_detects_changes(self, state_manager, sample_raw_alert):
        """Test that hashing detects state changes."""
        state = await state_manager.create_state(
            alert_id="alert-001",
            raw_alert=sample_raw_alert,
            workflow_instance_id="workflow-001",
            initial_node="ingestion",
            author_type="system",
            author_id="test_system"
        )

        hash_before = state_manager._hash_state(state)

        # Modify state
        state.confidence_score = 75

        hash_after = state_manager._hash_state(state)

        assert hash_before != hash_after
