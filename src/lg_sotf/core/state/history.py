"""
State history management for LG-SOTF.

This module provides functionality for managing state history,
including version tracking and change analysis.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from lg_sotf.storage.base import StorageBackend
from lg_sotf.core.exceptions import StateError
from lg_sotf.core.state.model import SOCState, StateVersion


class StateHistoryManager:
    """Manages state history and version tracking."""
    
    def __init__(self, storage_backend: StorageBackend):
        self.storage = storage_backend
    
    async def get_version_history(self, alert_id: str, workflow_instance_id: str) -> List[StateVersion]:
        """Get version history for a state."""
        try:
            state_history = await self.storage.get_state_history(alert_id, workflow_instance_id)
            
            versions = []
            for state_data in state_history:
                state = SOCState.parse_obj(state_data)
                versions.extend(state.version_history)
            
            return sorted(versions, key=lambda v: v.version)
            
        except Exception as e:
            raise StateError(f"Failed to get version history: {str(e)}")
    
    async def get_state_at_version(self, alert_id: str, workflow_instance_id: str, 
                                  version: int) -> Optional[SOCState]:
        """Get state at specific version."""
        try:
            state_history = await self.storage.get_state_history(alert_id, workflow_instance_id)
            
            for state_data in state_history:
                state = SOCState.parse_obj(state_data)
                if state.state_version >= version:
                    return state
            
            return None
            
        except Exception as e:
            raise StateError(f"Failed to get state at version: {str(e)}")
    
    async def compare_versions(self, alert_id: str, workflow_instance_id: str,
                             version1: int, version2: int) -> Dict[str, Any]:
        """Compare two versions of a state."""
        try:
            state1 = await self.get_state_at_version(alert_id, workflow_instance_id, version1)
            state2 = await self.get_state_at_version(alert_id, workflow_instance_id, version2)
            
            if not state1 or not state2:
                raise StateError("One or both versions not found")
            
            return self._compare_states(state1, state2)
            
        except Exception as e:
            raise StateError(f"Failed to compare versions: {str(e)}")
    
    def _compare_states(self, state1: SOCState, state2: SOCState) -> Dict[str, Any]:
        """Compare two states and return differences."""
        differences = {
            "version1": state1.state_version,
            "version2": state2.state_version,
            "changes": []
        }
        
        # Compare basic fields
        if state1.triage_status != state2.triage_status:
            differences["changes"].append({
                "field": "triage_status",
                "old_value": state1.triage_status,
                "new_value": state2.triage_status
            })
        
        if state1.confidence_score != state2.confidence_score:
            differences["changes"].append({
                "field": "confidence_score",
                "old_value": state1.confidence_score,
                "new_value": state2.confidence_score
            })
        
        # Compare lists
        if set(state1.fp_indicators) != set(state2.fp_indicators):
            differences["changes"].append({
                "field": "fp_indicators",
                "old_value": state1.fp_indicators,
                "new_value": state2.fp_indicators
            })
        
        if set(state1.tp_indicators) != set(state2.tp_indicators):
            differences["changes"].append({
                "field": "tp_indicators",
                "old_value": state1.tp_indicators,
                "new_value": state2.tp_indicators
            })
        
        return differences