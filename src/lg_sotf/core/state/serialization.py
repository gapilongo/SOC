"""
State serialization utilities for LG-SOTF.

This module provides serialization and deserialization utilities for
state objects, ensuring proper handling of complex data structures.
"""

import json
from datetime import datetime
from typing import Any, Dict

from lg_sotf.core.exceptions import StateError
from lg_sotf.core.state.model import SOCState


class StateSerializer:
    """Handles state serialization and deserialization."""
    
    def serialize(self, state: SOCState) -> Dict[str, Any]:
        """Serialize state object to dictionary."""
        try:
            import json

            # Convert to dict first, then serialize/deserialize to handle datetime objects
            state_dict = state.dict()
            # Use custom JSON serializer to handle datetime objects
            json_str = json.dumps(state_dict, default=self._json_serializer)
            return json.loads(json_str)
        except Exception as e:
            raise StateError(f"Failed to serialize state: {str(e)}")
    
    def deserialize(self, state_data: Dict[str, Any]) -> SOCState:
        """Deserialize dictionary to state object."""
        try:
            return SOCState.parse_obj(state_data)
        except Exception as e:
            raise StateError(f"Failed to deserialize state: {str(e)}")
    
    def serialize_to_json(self, state: SOCState) -> str:
        """Serialize state to JSON string."""
        try:
            return json.dumps(self.serialize(state), default=self._json_serializer)
        except Exception as e:
            raise StateError(f"Failed to serialize state to JSON: {str(e)}")
    
    def deserialize_from_json(self, json_str: str) -> SOCState:
        """Deserialize JSON string to state object."""
        try:
            state_data = json.loads(json_str)
            return self.deserialize(state_data)
        except Exception as e:
            raise StateError(f"Failed to deserialize state from JSON: {str(e)}")
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for special types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'dict'):  # Pydantic models
            return obj.dict()
        elif hasattr(obj, '__dict__'):  # Other objects with __dict__
            return obj.__dict__
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")