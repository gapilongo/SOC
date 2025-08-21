"""
PostgreSQL storage backend for LG-SOTF.

This module provides the PostgreSQL implementation of the storage backend,
offering robust persistence and querying capabilities.
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg

from ..core.exceptions import StorageError
from .base import StorageBackend


class PostgreSQLStorage(StorageBackend):
    """PostgreSQL storage backend implementation."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.pool = None
    
    async def initialize(self) -> None:
        """Initialize PostgreSQL connection pool and create tables."""
        try:
            self.pool = await asyncpg.create_pool(
                self.connection_string,
                min_size=5,
                max_size=20,
                command_timeout=60
            )
            
            # Create tables if they don't exist
            await self._create_tables()
            
        except Exception as e:
            raise StorageError(f"Failed to initialize PostgreSQL storage: {str(e)}")
    
    async def _create_tables(self) -> None:
        """Create necessary tables."""
        async with self.pool.acquire() as conn:
            # Create states table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS states (
                    alert_id VARCHAR(255) NOT NULL,
                    workflow_instance_id VARCHAR(255) NOT NULL,
                    state_data JSONB NOT NULL,
                    version INTEGER NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (alert_id, workflow_instance_id, version)
                )
            ''')
            
            # Create configs table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS configs (
                    key VARCHAR(255) PRIMARY KEY,
                    config_data JSONB NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create metrics table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id SERIAL PRIMARY KEY,
                    metric_name VARCHAR(255) NOT NULL,
                    metric_data JSONB NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_states_alert_id 
                ON states (alert_id)
            ''')
            
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_states_created_at 
                ON states (created_at)
            ''')
    
    async def save_state(self, alert_id: str, workflow_instance_id: str, 
                        state_data: Dict[str, Any]) -> None:
        """Save state data."""
        try:
            async with self.pool.acquire() as conn:
                # Get current version
                version_query = '''
                    SELECT COALESCE(MAX(version), 0) + 1 as new_version
                    FROM states
                    WHERE alert_id = $1 AND workflow_instance_id = $2
                '''
                version = await conn.fetchval(version_query, alert_id, workflow_instance_id)
                
                # Serialize state data with proper datetime handling
                serialized_data = json.dumps(state_data, default=self._json_serializer)
                
                # Insert new version
                await conn.execute('''
                    INSERT INTO states (alert_id, workflow_instance_id, state_data, version)
                    VALUES ($1, $2, $3, $4)
                ''', alert_id, workflow_instance_id, serialized_data, version)
                
        except Exception as e:
            raise StorageError(f"Failed to save state: {str(e)}")

    def _json_serializer(self, obj):
        """JSON serializer for datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    async def get_state(self, alert_id: str, workflow_instance_id: str) -> Optional[Dict[str, Any]]:
        """Get state data."""
        try:
            async with self.pool.acquire() as conn:
                query = '''
                    SELECT state_data
                    FROM states
                    WHERE alert_id = $1 AND workflow_instance_id = $2
                    ORDER BY version DESC
                    LIMIT 1
                '''
                result = await conn.fetchrow(query, alert_id, workflow_instance_id)
                
                if result:
                    return json.loads(result['state_data'])
                
                return None
                
        except Exception as e:
            raise StorageError(f"Failed to get state: {str(e)}")
    
    async def get_state_history(self, alert_id: str, workflow_instance_id: str) -> List[Dict[str, Any]]:
        """Get state history."""
        try:
            async with self.pool.acquire() as conn:
                query = '''
                    SELECT state_data, version, created_at
                    FROM states
                    WHERE alert_id = $1 AND workflow_instance_id = $2
                    ORDER BY version ASC
                '''
                results = await conn.fetch(query, alert_id, workflow_instance_id)
                
                return [
                    {
                        'state_data': json.loads(row['state_data']),
                        'version': row['version'],
                        'created_at': row['created_at']
                    }
                    for row in results
                ]
                
        except Exception as e:
            raise StorageError(f"Failed to get state history: {str(e)}")
    
    async def delete_state(self, alert_id: str, workflow_instance_id: str) -> None:
        """Delete state data."""
        try:
            async with self.pool.acquire() as conn:
                await conn.execute('''
                    DELETE FROM states
                    WHERE alert_id = $1 AND workflow_instance_id = $2
                ''', alert_id, workflow_instance_id)
                
        except Exception as e:
            raise StorageError(f"Failed to delete state: {str(e)}")
    
    async def save_config(self, key: str, config_data: Dict[str, Any]) -> None:
        """Save configuration data."""
        try:
            async with self.pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO configs (key, config_data)
                    VALUES ($1, $2)
                    ON CONFLICT (key) 
                    DO UPDATE SET config_data = $2, updated_at = CURRENT_TIMESTAMP
                ''', key, json.dumps(config_data))
                
        except Exception as e:
            raise StorageError(f"Failed to save config: {str(e)}")
    
    async def get_config(self, key: str) -> Optional[Dict[str, Any]]:
        """Get configuration data."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.fetchrow('''
                    SELECT config_data FROM configs WHERE key = $1
                ''', key)
                
                if result:
                    return json.loads(result['config_data'])
                
                return None
                
        except Exception as e:
            raise StorageError(f"Failed to get config: {str(e)}")
    
    async def save_metrics(self, metrics_data: Dict[str, Any]) -> None:
        """Save metrics data."""
        try:
            async with self.pool.acquire() as conn:
                for metric_name, data in metrics_data.items():
                    await conn.execute('''
                        INSERT INTO metrics (metric_name, metric_data)
                        VALUES ($1, $2)
                    ''', metric_name, json.dumps(data))
                
        except Exception as e:
            raise StorageError(f"Failed to save metrics: {str(e)}")
    
    async def get_metrics(self, metric_name: str, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """Get metrics data."""
        try:
            async with self.pool.acquire() as conn:
                query = '''
                    SELECT metric_data, timestamp
                    FROM metrics
                    WHERE metric_name = $1 
                    AND timestamp BETWEEN $2 AND $3
                    ORDER BY timestamp ASC
                '''
                results = await conn.fetch(query, metric_name, start_time, end_time)
                
                return [
                    {
                        'metric_data': json.loads(row['metric_data']),
                        'timestamp': row['timestamp']
                    }
                    for row in results
                ]
                
        except Exception as e:
            raise StorageError(f"Failed to get metrics: {str(e)}")
    
    async def health_check(self) -> bool:
        """Check PostgreSQL health."""
        try:
            async with self.pool.acquire() as conn:
                await conn.fetchval('SELECT 1')
                return True
        except Exception:
            return False
    
    async def close(self) -> None:
        """Close PostgreSQL connection pool."""
        if self.pool:
            await self.pool.close()