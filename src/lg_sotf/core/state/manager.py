"""
State manager implementation for LG-SOTF.

This module provides the main state management functionality including
persistence, versioning, and history tracking.
"""

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from lg_sotf.audit.logger import AuditLogger

# from lg_sotf.audit.tracer import DistributedTracer
from lg_sotf.core.exceptions import StateError
from lg_sotf.storage.base import StorageBackend

from .model import AgentExecution, SOCState, StateVersion, WorkflowNodeHistory
from .serialization import StateSerializer


class StateManager:
    """Manages state persistence, versioning, and history tracking."""
    
    def __init__(self, storage_backend: StorageBackend):
        self.storage = storage_backend
        self.audit_logger = AuditLogger()
        # self.tracer = DistributedTracer()
        self.serializer = StateSerializer()
    
    async def create_state(self, alert_id: str, raw_alert: Dict[str, Any], 
                          workflow_instance_id: str, initial_node: str,
                          author_type: str, author_id: str) -> SOCState:
        """Create a new state object."""
        try:
            state = SOCState(
                alert_id=alert_id,
                raw_alert=raw_alert,
                workflow_instance_id=workflow_instance_id,
                current_node=initial_node,
                next_nodes=[initial_node],
                created_at=datetime.utcnow(),
                last_updated=datetime.utcnow()
            )
            
            # Record initial version
            version = StateVersion(
                version=1,
                timestamp=datetime.utcnow(),
                author_type=author_type,
                author_id=author_id,
                changes_summary="Initial state creation"
            )
            state.add_version(version)
            
            # Persist state
            await self._persist_state(state)
            
            # Log state creation
            self.audit_logger.log_state_creation(state)
            
            return state
            
        except Exception as e:
            raise StateError(f"Failed to create state: {str(e)}")
    
    async def update_state(self, state: SOCState, updates: Dict[str, Any],
                        author_type: str, author_id: str,
                        changes_summary: str) -> SOCState:
        """Update state with versioning."""
        try:
            # Create new version
            from .model import StateVersion
            new_version = StateVersion(
                version=state.state_version + 1,
                timestamp=datetime.utcnow(),
                author_type=author_type,
                author_id=author_id,
                changes_summary=changes_summary
            )
            
            # Apply updates
            old_state_hash = self._hash_state(state)
            
            # Apply field updates
            self._apply_updates(state, updates)
            
            # Add version to history
            state.add_version(new_version)
            
            # Persist state (with proper serialization now working)
            await self._persist_state(state)
            
            # Log state update
            self.audit_logger.log_state_update(state.dict(), old_state_hash)
            
            return state
            
        except Exception as e:
            raise StateError(f"Failed to update state: {str(e)}")
    
    async def add_agent_execution(self, state: SOCState, execution: AgentExecution,
                                 author_type: str, author_id: str) -> SOCState:
        """Add agent execution record to state."""
        try:
            state.add_agent_execution(execution)
            
            updates = {
                f"agent_execution_{execution.execution_id}": execution.dict()
            }
            
            return await self.update_state(
                state,
                updates,
                author_type,
                author_id,
                f"Added agent execution {execution.execution_id}"
            )
            
        except Exception as e:
            raise StateError(f"Failed to add agent execution: {str(e)}")
    
    async def add_workflow_history(self, state: SOCState, history: WorkflowNodeHistory,
                                  author_type: str, author_id: str) -> SOCState:
        """Add workflow node history to state."""
        try:
            state.add_workflow_history(history)
            
            updates = {
                f"workflow_history_{history.node_name}_{history.execution_time.isoformat()}":
                history.dict()
            }
            
            return await self.update_state(
                state,
                updates,
                author_type,
                author_id,
                f"Added workflow history for node {history.node_name}"
            )
            
        except Exception as e:
            raise StateError(f"Failed to add workflow history: {str(e)}")
    
    async def get_state(self, alert_id: str, workflow_instance_id: str) -> Optional[SOCState]:
        """Retrieve state from alert ID and workflow instance ID."""
        try:
            state_data = await self.storage.get_state(alert_id, workflow_instance_id)
            
            if state_data:
                return SOCState.parse_obj(state_data)
            
            return None
            
        except Exception as e:
            raise StateError(f"Failed to get state: {str(e)}")
    
    async def get_state_history(self, alert_id: str, workflow_instance_id: str) -> List[SOCState]:
        """Retrieve state history for debugging."""
        try:
            # This would retrieve all versions of the state
            # Implementation depends on storage backend capabilities
            state_data = await self.storage.get_state_history(alert_id, workflow_instance_id)
            
            if state_data:
                return [SOCState.parse_obj(data) for data in state_data]
            
            return []
            
        except Exception as e:
            raise StateError(f"Failed to get state history: {str(e)}")
    
    async def _persist_state(self, state: SOCState):
        """Persist state to storage backend."""
        try:
            state_data = self.serializer.serialize(state)
            await self.storage.save_state(
                state.alert_id,
                state.workflow_instance_id,
                state_data
            )
        except Exception as e:
            raise StateError(f"Failed to persist state: {str(e)}")
    
    def _hash_state(self, state: SOCState) -> str:
        """Create hash of state for change detection."""
        try:
            state_dict = state.dict()
            # Use the custom JSON serializer to handle datetime objects
            state_str = json.dumps(state_dict, sort_keys=True, default=self._json_datetime_serializer)
            
            return hashlib.sha256(state_str.encode()).hexdigest()
            
        except Exception as e:
            raise StateError(f"Failed to hash state: {str(e)}")
    
    def _json_datetime_serializer(self, obj):
        """Custom JSON serializer for datetime objects in hashing."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'dict'):  # Pydantic models
            return obj.dict()
        elif hasattr(obj, '__dict__'):  # Other objects
            return obj.__dict__
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    def _apply_updates(self, state: SOCState, updates: Dict[str, Any]):
        """Apply updates to state using proper Pydantic model methods."""
        try:
            # Create a new state with updates applied
            # Get current state as dict
            current_dict = state.dict()
            
            # Apply updates
            for key, value in updates.items():
                if '.' in key:
                    # Handle nested updates
                    parts = key.split('.')
                    nested_dict = current_dict
                    for part in parts[:-1]:
                        if part not in nested_dict:
                            nested_dict[part] = {}
                        nested_dict = nested_dict[part]
                    nested_dict[parts[-1]] = value
                else:
                    # Direct field update
                    current_dict[key] = value
            
            # Update the state object fields
            for field_name, field_value in current_dict.items():
                if hasattr(state, field_name):
                    setattr(state, field_name, field_value)
            
            # Update last_updated timestamp
            state.last_updated = datetime.utcnow()
            
        except Exception as e:
            raise StateError(f"Failed to apply updates: {str(e)}")