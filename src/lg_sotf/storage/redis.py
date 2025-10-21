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

from lg_sotf.core.exceptions import StorageError
from lg_sotf.storage.base import StorageBackend


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

    # ==========================================
    # CORRELATION-SPECIFIC PATTERN DETECTION
    # ==========================================

    async def increment_indicator_count(
        self,
        indicator_type: str,
        indicator_value: str,
        window_seconds: int = 3600,
        alert_id: str = None
    ) -> int:
        """Increment and get count for an indicator using improved data model.

        Uses Redis Hash for metadata and Set for alert tracking.

        Args:
            indicator_type: Type of indicator (e.g., 'ip', 'hash', 'user')
            indicator_value: Value of the indicator
            window_seconds: Time window in seconds (for TTL)
            alert_id: Optional alert ID to track relationship

        Returns:
            Current count within the window
        """
        try:
            # Main indicator key (HASH for metadata)
            indicator_key = f"indicator:{indicator_type}:{indicator_value}"

            # Increment count in hash
            count = await self.redis_client.hincrby(indicator_key, 'count', 1)

            # Set first_seen if this is the first occurrence
            if count == 1:
                from datetime import datetime
                now = datetime.utcnow().isoformat()
                await self.redis_client.hset(indicator_key, 'first_seen', now)
                await self.redis_client.hset(indicator_key, 'type', indicator_type)

            # Always update last_seen
            from datetime import datetime
            await self.redis_client.hset(indicator_key, 'last_seen', datetime.utcnow().isoformat())

            # Set TTL on the hash
            await self.redis_client.expire(indicator_key, window_seconds)

            # If alert_id provided, track the relationship
            if alert_id:
                # Add alert to indicator's alert set
                alerts_key = f"indicator:{indicator_type}:{indicator_value}:alerts"
                await self.redis_client.sadd(alerts_key, alert_id)
                await self.redis_client.expire(alerts_key, window_seconds)

                # Add indicator to alert's indicator set (bidirectional)
                alert_indicators_key = f"alert:{alert_id}:indicators"
                indicator_ref = f"{indicator_type}:{indicator_value}"
                await self.redis_client.sadd(alert_indicators_key, indicator_ref)
                await self.redis_client.expire(alert_indicators_key, window_seconds)

            return count

        except Exception as e:
            raise StorageError(f"Failed to increment indicator count: {str(e)}")

    async def get_indicator_count(
        self,
        indicator_type: str,
        indicator_value: str
    ) -> int:
        """Get current count for an indicator from Hash.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value of the indicator

        Returns:
            Current count
        """
        try:
            indicator_key = f"indicator:{indicator_type}:{indicator_value}"
            count = await self.redis_client.hget(indicator_key, 'count')

            if count is None:
                return 0

            if isinstance(count, bytes):
                count = count.decode('utf-8')

            return int(count)

        except Exception as e:
            raise StorageError(f"Failed to get indicator count: {str(e)}")

    async def get_indicator_metadata(
        self,
        indicator_type: str,
        indicator_value: str
    ) -> Dict[str, Any]:
        """Get all metadata for an indicator.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value of the indicator

        Returns:
            Dictionary with count, first_seen, last_seen, etc.
        """
        try:
            indicator_key = f"indicator:{indicator_type}:{indicator_value}"
            metadata = await self.redis_client.hgetall(indicator_key)

            if not metadata:
                return {}

            # Decode bytes keys and values
            decoded_metadata = {}
            for key, value in metadata.items():
                if isinstance(key, bytes):
                    key = key.decode('utf-8')
                if isinstance(value, bytes):
                    value = value.decode('utf-8')

                # Convert count to int
                if key == 'count':
                    value = int(value)

                decoded_metadata[key] = value

            return decoded_metadata

        except Exception as e:
            raise StorageError(f"Failed to get indicator metadata: {str(e)}")

    async def record_alert_timestamp(
        self,
        indicator_type: str,
        indicator_value: str,
        timestamp: Optional[datetime] = None,
        ttl: int = 86400,
        alert_id: str = None
    ) -> None:
        """Record an alert timestamp for burst detection with alert ID context.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value of the indicator
            timestamp: Timestamp to record (defaults to now)
            ttl: Time to live in seconds (default 24 hours)
            alert_id: Optional alert ID to track which alert triggered this
        """
        try:
            if timestamp is None:
                timestamp = datetime.utcnow()

            key = f"indicator:{indicator_type}:{indicator_value}:timeline"
            score = timestamp.timestamp()

            # Store alert_id as member (or timestamp if no alert_id)
            member = alert_id if alert_id else timestamp.isoformat()

            # Add to sorted set with timestamp as score
            await self.redis_client.zadd(key, {member: score})

            # Keep only entries within TTL window
            cutoff = (datetime.utcnow() - timedelta(seconds=ttl)).timestamp()
            await self.redis_client.zremrangebyscore(key, '-inf', cutoff)

            # Set expiry - use the same TTL for consistency
            await self.redis_client.expire(key, ttl)

        except Exception as e:
            raise StorageError(f"Failed to record alert timestamp: {str(e)}")

    async def get_alert_burst_stats(
        self,
        indicator_type: str,
        indicator_value: str,
        time_window_minutes: int = 60
    ) -> Dict[str, Any]:
        """Get burst statistics for an indicator with alert IDs.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value of the indicator
            time_window_minutes: Time window to analyze

        Returns:
            Dictionary with burst statistics including alert IDs
        """
        try:
            key = f"indicator:{indicator_type}:{indicator_value}:timeline"

            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=time_window_minutes)

            # Get events in time window with scores
            events = await self.redis_client.zrangebyscore(
                key,
                start_time.timestamp(),
                end_time.timestamp(),
                withscores=True
            )

            count = len(events)

            # Extract alert IDs (members)
            alert_ids = []
            for member, score in events:
                if isinstance(member, bytes):
                    member = member.decode('utf-8')
                alert_ids.append(member)

            # Calculate events per minute
            events_per_minute = count / time_window_minutes if time_window_minutes > 0 else 0

            # Determine if this is a burst (more than 5 events per minute)
            is_burst = events_per_minute > 5

            return {
                'indicator_type': indicator_type,
                'indicator_value': indicator_value,
                'time_window_minutes': time_window_minutes,
                'total_events': count,
                'events_per_minute': round(events_per_minute, 2),
                'is_burst': is_burst,
                'burst_severity': self._calculate_burst_severity(events_per_minute),
                'alert_ids': alert_ids  # NEW: Include which alerts contributed
            }

        except Exception as e:
            raise StorageError(f"Failed to get burst stats: {str(e)}")

    def _calculate_burst_severity(self, events_per_minute: float) -> str:
        """Calculate burst severity based on event frequency."""
        if events_per_minute < 5:
            return 'normal'
        elif events_per_minute < 10:
            return 'low'
        elif events_per_minute < 20:
            return 'medium'
        elif events_per_minute < 50:
            return 'high'
        else:
            return 'critical'

    async def cache_correlation_result(
        self,
        indicator_type: str,
        indicator_value: str,
        correlation_data: Dict[str, Any],
        ttl: int = 300  # 5 minutes default
    ) -> None:
        """Cache correlation results for quick retrieval.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value of the indicator
            correlation_data: Correlation data to cache
            ttl: Time to live in seconds
        """
        try:
            key = f"correlation_cache:{indicator_type}:{indicator_value}"

            # Serialize correlation data
            data_json = json.dumps(correlation_data, default=self._json_serializer)

            # Cache with TTL
            await self.redis_client.setex(key, ttl, data_json)

        except Exception as e:
            raise StorageError(f"Failed to cache correlation result: {str(e)}")

    async def get_cached_correlation(
        self,
        indicator_type: str,
        indicator_value: str
    ) -> Optional[Dict[str, Any]]:
        """Get cached correlation results.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value of the indicator

        Returns:
            Cached correlation data or None
        """
        try:
            key = f"correlation_cache:{indicator_type}:{indicator_value}"

            # Get cached data
            data_json = await self.redis_client.get(key)

            if data_json is None:
                return None

            # Handle bytes response
            if isinstance(data_json, bytes):
                data_json = data_json.decode('utf-8')

            # Deserialize and return
            return json.loads(data_json)

        except Exception as e:
            raise StorageError(f"Failed to get cached correlation: {str(e)}")

    async def track_indicator_pair(
        self,
        indicator1_type: str,
        indicator1_value: str,
        indicator2_type: str,
        indicator2_value: str,
        ttl: int = 3600
    ) -> int:
        """Track co-occurrence using Sorted Set (score = co-occurrence count).

        Uses single-direction storage with ZINCRBY to avoid duplication.

        Args:
            indicator1_type: Type of first indicator
            indicator1_value: Value of first indicator
            indicator2_type: Type of second indicator
            indicator2_value: Value of second indicator
            ttl: Time to live in seconds

        Returns:
            Co-occurrence count
        """
        try:
            # Create co-occurrence key for indicator1
            cooccur_key = f"indicator:{indicator1_type}:{indicator1_value}:cooccur"

            # Member is the related indicator
            member = f"{indicator2_type}:{indicator2_value}"

            # Increment score (co-occurrence count) using ZINCRBY
            count = await self.redis_client.zincrby(cooccur_key, 1, member)

            # Set TTL
            await self.redis_client.expire(cooccur_key, ttl)

            # Also track reverse direction for bidirectional queries
            reverse_cooccur_key = f"indicator:{indicator2_type}:{indicator2_value}:cooccur"
            reverse_member = f"{indicator1_type}:{indicator1_value}"
            await self.redis_client.zincrby(reverse_cooccur_key, 1, reverse_member)
            await self.redis_client.expire(reverse_cooccur_key, ttl)

            return int(count)

        except Exception as e:
            raise StorageError(f"Failed to track indicator pair: {str(e)}")

    async def get_related_indicators(
        self,
        indicator_type: str,
        indicator_value: str,
        min_count: int = 2,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get indicators that frequently co-occur with the given indicator.

        Uses Sorted Set with scores as co-occurrence counts.

        Args:
            indicator_type: Type of indicator
            indicator_value: Value of the indicator
            min_count: Minimum co-occurrence count
            limit: Maximum number of results to return

        Returns:
            List of related indicators with counts (sorted by count DESC)
        """
        try:
            cooccur_key = f"indicator:{indicator_type}:{indicator_value}:cooccur"

            # Get top related indicators (sorted by score DESC)
            related_with_scores = await self.redis_client.zrevrange(
                cooccur_key,
                0,
                limit - 1,
                withscores=True
            )

            # Parse results
            related = []
            for member, score in related_with_scores:
                if isinstance(member, bytes):
                    member = member.decode('utf-8')

                count = int(score)

                # Only include if meets minimum
                if count >= min_count:
                    # Parse member (format: "type:value")
                    parts = member.split(':', 1)
                    if len(parts) == 2:
                        related.append({
                            'related_indicator_type': parts[0],
                            'related_indicator_value': parts[1],
                            'co_occurrence_count': count
                        })

            # Already sorted by score DESC from ZREVRANGE
            return related

        except Exception as e:
            raise StorageError(f"Failed to get related indicators: {str(e)}")