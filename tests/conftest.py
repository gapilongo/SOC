"""
Pytest configuration and fixtures for LG-SOTF tests.
"""

import asyncio
from typing import Any, Dict

import pytest

from src.lg_sotf.core.config.manager import ConfigManager
from src.lg_sotf.core.state.manager import StateManager
from src.lg_sotf.storage.postgres import PostgreSQLStorage
from src.lg_sotf.storage.redis import RedisStorage


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def config_manager():
    """Create a test configuration manager."""
    return ConfigManager()


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing."""
    return {
        "id": "test-alert-001",
        "source": "test-siem",
        "timestamp": "2024-01-01T00:00:00Z",
        "severity": "high",
        "description": "Test alert for unit testing",
        "raw_data": {
            "event_type": "malware_detection",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e"
        }
    }


@pytest.fixture
def sample_state(sample_alert):
    """Create a sample state for testing."""
    return {
        "alert_id": "test-alert-001",
        "raw_alert": sample_alert,
        "enriched_data": {},
        "triage_status": "new",
        "confidence_score": 0,
        "fp_indicators": [],
        "tp_indicators": [],
        "workflow_instance_id": "test-workflow-001",
        "current_node": "ingestion",
        "next_nodes": ["ingestion"],
        "state_version": 1,
        "created_at": "2024-01-01T00:00:00Z",
        "last_updated": "2024-01-01T00:00:00Z",
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


@pytest.fixture
async def postgres_storage():
    """Create a test PostgreSQL storage instance."""
    # Use test database
    storage = PostgreSQLStorage("postgresql://test:test@localhost:5432/lg_sotf_test")
    await storage.initialize()
    yield storage
    await storage.close()


@pytest.fixture
async def redis_storage():
    """Create a test Redis storage instance."""
    # Use test Redis
    storage = RedisStorage("redis://localhost:6379/1")
    await storage.initialize()
    yield storage
    await storage.close()


@pytest.fixture
async def state_manager(postgres_storage):
    """Create a test state manager."""
    return StateManager(postgres_storage)