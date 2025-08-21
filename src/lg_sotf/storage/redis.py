"""
Redis storage backend for LG-SOTF.

This module provides the Redis implementation of the storage backend,
offering fast caching and session management capabilities.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import aioredis

from ..core.exceptions import StorageError
from .base import StorageBackend


class RedisStorage(StorageBackend):
    """Redis storage backend implementation."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.redis_client = None
        self.default_ttl = 3600  # 1 hour default TTL
    
    async def initialize(self) -> None:
        """Initialize Redis connection pool and validate connection."""
        try:
            # Create Redis client directly from URL (aioredis 2.0+ API)
            self.redis_client = aioredis.from_url(
                self.connection_string,
                max_connections=20,
                retry_on_timeout=True,
                socket_keepalive=True,
                decode_responses=False  # Keep as bytes for compatibility
            )
            
            # Test connection
            await self.redis_client.ping()
            
            # Set up key expiration policies if needed
            await self._setup_key_policies()
            
        except Exception as e:
            raise StorageError(f"Failed to initialize Redis storage: {str(e)}")
    
    async def _setup_key_policies(self):
        """Set up Redis key expiration policies."""
        try:
            # This is where you would set up Redis policies if needed
            # For now, we'll just verify the connection
            await self.redis_client.setex("lg_sotf_health_check", 60, "healthy")
            
        except Exception as e:
            raise StorageError(f"Failed to setup Redis policies: {str(e)}")
    
    async def save_state(self, alert_id: str, workflow_instance_id: str, 
                        state_data: Dict[str, Any]) -> None:
        """Save state data to Redis."""
        try:
            # Create composite key
            key = f"state:{alert_id}:{workflow_instance_id}"
            
            # Serialize state data
            state_json = json.dumps(state_data, default=self._json_serializer)
            
            # Save to Redis with TTL
            await self.redis_client.setex(key, self.default_ttl, state_json)
            
        except Exception as e:
            raise StorageError(f"Failed to save state to Redis: {str(e)}")
    
    async def get_state(self, alert_id: str, workflow_instance_id: str) -> Optional[Dict[str, Any]]:
        """Get state data from Redis."""
        try:
            # Create composite key
            key = f"state:{alert_id}:{workflow_instance_id}"
            
            # Get data from Redis
            state_json = await self.redis_client.get(key)
            
            if state_json is None:
                return None
            
            # Handle bytes response (aioredis 2.0+ returns bytes by default)
            if isinstance(state_json, bytes):
                state_json = state_json.decode('utf-8')
            
            # Deserialize state data
            return json.loads(state_json)
            
        except Exception as e:
            raise StorageError(f"Failed to get state from Redis: {str(e)}")
    
    async def get_state_history(self, alert_id: str, workflow_instance_id: str) -> List[Dict[str, Any]]:
        """Get state history from Redis."""
        try:
            # For Redis, we'll store history as a separate key
            history_key = f"state_history:{alert_id}:{workflow_instance_id}"
            
            # Get history data
            history_json = await self.redis_client.get(history_key)
            
            if history_json is None:
                return []
            
            # Handle bytes response
            if isinstance(history_json, bytes):
                history_json = history_json.decode('utf-8')
            
            # Deserialize history data
            return json.loads(history_json)
            
        except Exception as e:
            raise StorageError(f"Failed to get state history from Redis: {str(e)}")
    
    async def delete_state(self, alert_id: str, workflow_instance_id: str) -> None:
        """Delete state data from Redis."""
        try:
            # Delete state key
            state_key = f"state:{alert_id}:{workflow_instance_id}"
            await self.redis_client.delete(state_key)
            
            # Delete history key
            history_key = f"state_history:{alert_id}:{workflow_instance_id}"
            await self.redis_client.delete(history_key)
            
        except Exception as e:
            raise StorageError(f"Failed to delete state from Redis: {str(e)}")
    
    async def save_config(self, key: str, config_data: Dict[str, Any]) -> None:
        """Save configuration data to Redis."""
        try:
            # Create config key
            config_key = f"config:{key}"
            
            # Serialize config data
            config_json = json.dumps(config_data, default=self._json_serializer)
            
            # Save to Redis (configs don't expire by default)
            await self.redis_client.set(config_key, config_json)
            
        except Exception as e:
            raise StorageError(f"Failed to save config to Redis: {str(e)}")
    
    async def get_config(self, key: str) -> Optional[Dict[str, Any]]:
        """Get configuration data from Redis."""
        try:
            # Create config key
            config_key = f"config:{key}"
            
            # Get config data
            config_json = await self.redis_client.get(config_key)
            
            if config_json is None:
                return None
            
            # Handle bytes response
            if isinstance(config_json, bytes):
                config_json = config_json.decode('utf-8')
            
            # Deserialize config data
            return json.loads(config_json)
            
        except Exception as e:
            raise StorageError(f"Failed to get config from Redis: {str(e)}")
    
    async def save_metrics(self, metrics_data: Dict[str, Any]) -> None:
        """Save metrics data to Redis."""
        try:
            # Use Redis streams for metrics
            stream_key = "metrics:stream"
            
            # Convert metrics_data values to strings for Redis streams
            string_metrics = {k: json.dumps(v) if not isinstance(v, (str, int, float)) else str(v) 
                            for k, v in metrics_data.items()}
            
            # Add metrics to stream
            await self.redis_client.xadd(
                stream_key,
                string_metrics,
                maxlen=10000,  # Keep only last 10,000 entries
                approximate=True
            )
            
        except Exception as e:
            raise StorageError(f"Failed to save metrics to Redis: {str(e)}")
    
    async def get_metrics(self, metric_name: str, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """Get metrics data from Redis."""
        try:
            # Parse time range
            start_timestamp = int(datetime.fromisoformat(start_time).timestamp() * 1000)
            end_timestamp = int(datetime.fromisoformat(end_time).timestamp() * 1000)
            
            # Read from metrics stream
            stream_key = "metrics:stream"
            
            # Get metrics data
            metrics_data = []
            try:
                # Read stream within time range
                result = await self.redis_client.xrange(
                    stream_key,
                    min=start_timestamp,
                    max=end_timestamp
                )
                
                for entry_id, fields in result:
                    # Handle bytes response
                    if isinstance(entry_id, bytes):
                        entry_id = entry_id.decode('utf-8')
                    
                    # Convert fields from bytes to strings
                    decoded_fields = {}
                    for field_key, field_value in fields.items():
                        if isinstance(field_key, bytes):
                            field_key = field_key.decode('utf-8')
                        if isinstance(field_value, bytes):
                            field_value = field_value.decode('utf-8')
                        decoded_fields[field_key] = field_value
                    
                    metrics_data.append({
                        'timestamp': datetime.fromtimestamp(int(entry_id.split('-')[0]) / 1000).isoformat(),
                        'data': decoded_fields
                    })
                
            except aioredis.ResponseError:
                # Stream might not exist yet
                pass
            
            return metrics_data
            
        except Exception as e:
            raise StorageError(f"Failed to get metrics from Redis: {str(e)}")
    
    async def cache_result(self, cache_key: str, result: Dict[str, Any], ttl: int = None) -> None:
        """Cache a result in Redis."""
        try:
            # Use provided TTL or default
            cache_ttl = ttl or self.default_ttl
            
            # Serialize result
            result_json = json.dumps(result, default=self._json_serializer)
            
            # Cache the result
            await self.redis_client.setex(f"cache:{cache_key}", cache_ttl, result_json)
            
        except Exception as e:
            raise StorageError(f"Failed to cache result in Redis: {str(e)}")
    
    async def get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get a cached result from Redis."""
        try:
            # Get cached result
            result_json = await self.redis_client.get(f"cache:{cache_key}")
            
            if result_json is None:
                return None
            
            # Handle bytes response
            if isinstance(result_json, bytes):
                result_json = result_json.decode('utf-8')
            
            # Deserialize result
            return json.loads(result_json)
            
        except Exception as e:
            raise StorageError(f"Failed to get cached result from Redis: {str(e)}")
    
    async def increment_counter(self, counter_name: str, increment: int = 1) -> int:
        """Increment a counter in Redis."""
        try:
            counter_key = f"counter:{counter_name}"
            return await self.redis_client.incrby(counter_key, increment)
            
        except Exception as e:
            raise StorageError(f"Failed to increment counter in Redis: {str(e)}")
    
    async def get_counter(self, counter_name: str) -> int:
        """Get a counter value from Redis."""
        try:
            counter_key = f"counter:{counter_name}"
            value = await self.redis_client.get(counter_key)
            
            if value is None:
                return 0
                
            # Handle bytes response
            if isinstance(value, bytes):
                value = value.decode('utf-8')
                
            return int(value)
            
        except Exception as e:
            raise StorageError(f"Failed to get counter from Redis: {str(e)}")
    
    async def set_session_data(self, session_id: str, data: Dict[str, Any], ttl: int = None) -> None:
        """Set session data in Redis."""
        try:
            session_ttl = ttl or self.default_ttl
            session_key = f"session:{session_id}"
            
            # Serialize session data
            session_json = json.dumps(data, default=self._json_serializer)
            
            # Set session data
            await self.redis_client.setex(session_key, session_ttl, session_json)
            
        except Exception as e:
            raise StorageError(f"Failed to set session data in Redis: {str(e)}")
    
    async def get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from Redis."""
        try:
            session_key = f"session:{session_id}"
            session_json = await self.redis_client.get(session_key)
            
            if session_json is None:
                return None
            
            # Handle bytes response
            if isinstance(session_json, bytes):
                session_json = session_json.decode('utf-8')
            
            # Deserialize session data
            return json.loads(session_json)
            
        except Exception as e:
            raise StorageError(f"Failed to get session data from Redis: {str(e)}")
    
    async def delete_session_data(self, session_id: str) -> None:
        """Delete session data from Redis."""
        try:
            session_key = f"session:{session_id}"
            await self.redis_client.delete(session_key)
            
        except Exception as e:
            raise StorageError(f"Failed to delete session data from Redis: {str(e)}")
    
    async def health_check(self) -> bool:
        """Check Redis health."""
        try:
            if self.redis_client is None:
                return False
            
            # Test basic operations
            await self.redis_client.ping()
            
            # Test set/get operation
            test_key = "lg_sotf_health_check"
            await self.redis_client.setex(test_key, 10, "healthy")
            result = await self.redis_client.get(test_key)
            
            # Handle bytes response
            if isinstance(result, bytes):
                result = result.decode('utf-8')
            
            return result == "healthy"
            
        except Exception:
            return False
    
    async def close(self) -> None:
        """Close Redis connection."""
        try:
            if self.redis_client:
                await self.redis_client.close()
                self.redis_client = None
            
        except Exception as e:
            raise StorageError(f"Failed to close Redis connection: {str(e)}")
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for complex objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    async def cleanup_expired_keys(self, pattern: str = "*") -> int:
        """Clean up expired keys matching a pattern."""
        try:
            keys_removed = 0
            async for key in self.redis_client.scan_iter(match=pattern):
                # Check TTL
                ttl = await self.redis_client.ttl(key)
                if ttl == -1:  # No expiration
                    continue
                elif ttl == -2:  # Key doesn't exist
                    continue
                elif ttl <= 0:  # Expired
                    await self.redis_client.delete(key)
                    keys_removed += 1
            
            return keys_removed
            
        except Exception as e:
            raise StorageError(f"Failed to cleanup expired keys: {str(e)}")
    
    async def get_memory_usage(self) -> Dict[str, Any]:
        """Get Redis memory usage statistics."""
        try:
            info = await self.redis_client.info('memory')
            
            return {
                'used_memory': info.get('used_memory', 0),
                'used_memory_human': info.get('used_memory_human', '0B'),
                'used_memory_peak': info.get('used_memory_peak', 0),
                'used_memory_peak_human': info.get('used_memory_peak_human', '0B'),
                'mem_fragmentation_ratio': info.get('mem_fragmentation_ratio', 0.0),
                'mem_allocator': info.get('mem_allocator', 'unknown')
            }
            
        except Exception as e:
            raise StorageError(f"Failed to get Redis memory usage: {str(e)}")
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get Redis connection statistics."""
        try:
            info = await self.redis_client.info('clients')
            
            return {
                'connected_clients': info.get('connected_clients', 0),
                'blocked_clients': info.get('blocked_clients', 0),
                'client_longest_output_list': info.get('client_longest_output_list', 0),
                'client_biggest_input_buf': info.get('client_biggest_input_buf', 0)
            }
            
        except Exception as e:
            raise StorageError(f"Failed to get Redis connection stats: {str(e)}")