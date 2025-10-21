"""
State manager implementation for LG-SOTF.

This module provides the main state management functionality including
persistence, versioning, and history tracking.
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from lg_sotf.audit.logger import AuditLogger

# from lg_sotf.audit.tracer import DistributedTracer
from lg_sotf.core.exceptions import StateError
from lg_sotf.storage.base import StorageBackend

from lg_sotf.core.state.model import AgentExecution, SOCState, StateVersion, WorkflowNodeHistory
from lg_sotf.core.state.serialization import StateSerializer


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

    # ==========================================
    # CORRELATION-SPECIFIC QUERY METHODS
    # ==========================================

    async def query_alerts_by_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        time_window_minutes: Optional[int] = 60,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query historical alerts by specific indicator (IP, hash, user, etc.).

        Args:
            indicator_type: Type of indicator ('source_ip', 'destination_ip', 'file_hash', 'user', etc.)
            indicator_value: Value to search for
            time_window_minutes: Time window to search within (None for all time)
            limit: Maximum number of results

        Returns:
            List of alert dictionaries matching the indicator
        """
        try:
            # Check if storage backend supports PostgreSQL-specific queries
            if hasattr(self.storage, 'pool'):
                return await self._query_postgres_by_indicator(
                    indicator_type, indicator_value, time_window_minutes, limit
                )
            else:
                # Fallback to generic query
                return await self._query_generic_by_indicator(
                    indicator_type, indicator_value, time_window_minutes, limit
                )
        except Exception as e:
            raise StateError(f"Failed to query alerts by indicator: {str(e)}")

    async def _query_postgres_by_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        time_window_minutes: Optional[int],
        limit: int
    ) -> List[Dict[str, Any]]:
        """PostgreSQL-specific indicator query using JSONB operators."""
        try:
            async with self.storage.pool.acquire() as conn:
                # Build time filter
                time_filter = ""
                params = [indicator_value, limit]

                if time_window_minutes:
                    cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
                    time_filter = "AND created_at >= $3"
                    params.append(cutoff_time)

                # Query using JSONB path operators
                query = f'''
                    SELECT
                        alert_id,
                        workflow_instance_id,
                        state_data,
                        created_at
                    FROM states
                    WHERE (
                        state_data->'raw_alert'->'raw_data'->'{indicator_type}' = to_jsonb($1::text)
                        OR state_data->'enriched_data'->'{indicator_type}' = to_jsonb($1::text)
                    )
                    {time_filter}
                    ORDER BY created_at DESC
                    LIMIT $2
                '''

                rows = await conn.fetch(query, *params)

                results = []
                for row in rows:
                    state_data = json.loads(row['state_data'])
                    results.append({
                        'alert_id': row['alert_id'],
                        'workflow_instance_id': row['workflow_instance_id'],
                        'state_data': state_data,
                        'created_at': row['created_at'].isoformat(),
                        'matched_indicator': {
                            'type': indicator_type,
                            'value': indicator_value
                        }
                    })

                return results

        except Exception as e:
            raise StateError(f"PostgreSQL indicator query failed: {str(e)}")

    async def _query_generic_by_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        time_window_minutes: Optional[int],
        limit: int
    ) -> List[Dict[str, Any]]:
        """Generic indicator query for non-PostgreSQL backends."""
        # Fallback implementation - would need to scan states
        # This is less efficient but works with any storage backend
        return []

    async def query_alerts_by_time_range(
        self,
        start_time: datetime,
        end_time: datetime,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query alerts within a specific time range with optional filters.

        Args:
            start_time: Start of time range
            end_time: End of time range
            filters: Additional filters (e.g., {'severity': 'high', 'triage_status': 'triaged'})
            limit: Maximum number of results

        Returns:
            List of alert dictionaries within the time range
        """
        try:
            if hasattr(self.storage, 'pool'):
                return await self._query_postgres_by_time_range(
                    start_time, end_time, filters, limit
                )
            else:
                return []
        except Exception as e:
            raise StateError(f"Failed to query alerts by time range: {str(e)}")

    async def _query_postgres_by_time_range(
        self,
        start_time: datetime,
        end_time: datetime,
        filters: Optional[Dict[str, Any]],
        limit: int
    ) -> List[Dict[str, Any]]:
        """PostgreSQL-specific time range query."""
        try:
            async with self.storage.pool.acquire() as conn:
                # Build filter conditions
                filter_conditions = []
                params = [start_time, end_time, limit]
                param_index = 4

                if filters:
                    for key, value in filters.items():
                        filter_conditions.append(
                            f"state_data->>'{key}' = ${param_index}"
                        )
                        params.append(str(value))
                        param_index += 1

                filter_clause = ""
                if filter_conditions:
                    filter_clause = "AND " + " AND ".join(filter_conditions)

                query = f'''
                    SELECT
                        alert_id,
                        workflow_instance_id,
                        state_data,
                        created_at
                    FROM states
                    WHERE created_at >= $1
                    AND created_at <= $2
                    {filter_clause}
                    ORDER BY created_at DESC
                    LIMIT $3
                '''

                rows = await conn.fetch(query, *params)

                results = []
                for row in rows:
                    state_data = json.loads(row['state_data'])
                    results.append({
                        'alert_id': row['alert_id'],
                        'workflow_instance_id': row['workflow_instance_id'],
                        'state_data': state_data,
                        'created_at': row['created_at'].isoformat()
                    })

                return results

        except Exception as e:
            raise StateError(f"PostgreSQL time range query failed: {str(e)}")

    async def query_similar_alerts(
        self,
        alert_data: Dict[str, Any],
        similarity_threshold: float = 0.7,
        time_window_minutes: Optional[int] = 1440,  # 24 hours default
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Query alerts similar to the given alert based on multiple indicators.

        Args:
            alert_data: Alert data to find similarities for
            similarity_threshold: Minimum similarity score (0-1)
            time_window_minutes: Time window to search within
            limit: Maximum number of results

        Returns:
            List of similar alerts with similarity scores
        """
        try:
            # Extract key indicators
            raw_data = alert_data.get('raw_data', {})
            indicators = []

            # Collect all indicators
            indicator_fields = [
                'source_ip', 'destination_ip', 'file_hash',
                'user', 'username', 'process_name', 'command_line'
            ]

            for field in indicator_fields:
                if field in raw_data and raw_data[field]:
                    indicators.append((field, raw_data[field]))

            if not indicators:
                return []

            # Query for each indicator and merge results
            similar_alerts = {}

            for indicator_type, indicator_value in indicators:
                results = await self.query_alerts_by_indicator(
                    indicator_type,
                    indicator_value,
                    time_window_minutes,
                    limit
                )

                for result in results:
                    alert_id = result['alert_id']
                    if alert_id not in similar_alerts:
                        similar_alerts[alert_id] = {
                            'alert': result,
                            'matching_indicators': [],
                            'similarity_score': 0.0
                        }

                    similar_alerts[alert_id]['matching_indicators'].append({
                        'type': indicator_type,
                        'value': indicator_value
                    })

            # Calculate similarity scores
            total_indicators = len(indicators)
            for alert_id, data in similar_alerts.items():
                matches = len(data['matching_indicators'])
                data['similarity_score'] = matches / total_indicators

            # Filter by threshold and sort
            filtered_similar = [
                data for data in similar_alerts.values()
                if data['similarity_score'] >= similarity_threshold
            ]

            filtered_similar.sort(
                key=lambda x: x['similarity_score'],
                reverse=True
            )

            return filtered_similar[:limit]

        except Exception as e:
            raise StateError(f"Failed to query similar alerts: {str(e)}")

    async def get_alert_frequency(
        self,
        indicator_type: str,
        indicator_value: str,
        time_window_minutes: int = 60
    ) -> Dict[str, Any]:
        """Get frequency statistics for a specific indicator.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value to analyze
            time_window_minutes: Time window for frequency calculation

        Returns:
            Dictionary with frequency statistics
        """
        try:
            alerts = await self.query_alerts_by_indicator(
                indicator_type,
                indicator_value,
                time_window_minutes,
                limit=1000  # Higher limit for stats
            )

            return {
                'indicator_type': indicator_type,
                'indicator_value': indicator_value,
                'time_window_minutes': time_window_minutes,
                'total_count': len(alerts),
                'alerts_per_hour': len(alerts) / (time_window_minutes / 60) if time_window_minutes > 0 else 0,
                'first_seen': alerts[-1]['created_at'] if alerts else None,
                'last_seen': alerts[0]['created_at'] if alerts else None,
                'unique_alert_ids': len(set(a['alert_id'] for a in alerts))
            }

        except Exception as e:
            raise StateError(f"Failed to get alert frequency: {str(e)}")