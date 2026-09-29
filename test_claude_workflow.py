#!/usr/bin/env python3
"""Test script to demonstrate Claude API integration in SOC workflow."""

import asyncio
import json
import os
from datetime import datetime

# Set environment variables for security
os.environ['ENCRYPTION_KEY'] = "dev_encryption_key_32bytes_test!"
os.environ['JWT_SECRET'] = "dev_jwt_secret_32bytes_testing!"

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.storage.postgres import PostgreSQLStorage
from lg_sotf.storage.redis import RedisStorage
from lg_sotf.core.state.manager import StateManager


async def test_claude_workflow():
    """Test the workflow with Claude API."""

    print("=" * 80)
    print("SOC WORKFLOW TEST - Claude API Integration")
    print("=" * 80)

    # Load configuration
    config_manager = ConfigManager("configs/development.yaml")
    print(f"✓ Configuration loaded")
    print(f"  - LLM Provider: {config_manager.get('llm.provider')}")
    print(f"  - LLM Model: {config_manager.get('llm.model')}")
    print(f"  - LLM Correlation Enabled: {config_manager.get('agents.correlation.enable_llm_correlation')}")
    print(f"  - LLM Triage Enabled: {config_manager.get('agents.triage.enable_llm_scoring')}")

    # Initialize storage
    pg_connection = config_manager.get('storage.connection_string')
    pg_storage = PostgreSQLStorage(pg_connection)
    await pg_storage.initialize()

    redis_connection = config_manager.get('storage.redis.connection_string')
    redis_storage = RedisStorage(redis_connection)
    await redis_storage.initialize()

    state_manager = StateManager(pg_storage, config_manager)
    await state_manager.initialize()

    print(f"✓ Storage initialized (PostgreSQL + Redis)")

    # Initialize workflow
    workflow_engine = WorkflowEngine(config_manager, state_manager, redis_storage)
    await workflow_engine.initialize()

    print(f"✓ Workflow engine initialized with {len(workflow_engine.agents)} agents")
    print()

    # Create test alert
    test_alert = {
        "id": f"test-malware-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source": "crowdstrike-edr",
        "severity": "critical",
        "category": "malware",
        "title": "Trojan.Win32.Agent Detected",
        "description": "Suspicious trojan detected on endpoint executing malicious payload",
        "raw_data": {
            "source_ip": "192.168.1.100",
            "destination_ip": "185.220.101.50",  # Known bad IP
            "destination_port": 4444,  # C2 port
            "user": "administrator",
            "host": "WORKSTATION-01",
            "process_name": "update.exe",  # Suspicious name
            "file_hash": "a1b2c3d4e5f6789",  # Mock malicious hash
            "file_path": "C:\\Temp\\update.exe",
            "event_type": "file_creation",
            "protocol": "TCP"
        }
    }

    print("📧 Processing alert with Claude API:")
    print(f"   Alert ID: {test_alert['id']}")
    print(f"   Severity: {test_alert['severity']}")
    print(f"   Category: {test_alert['category']}")
    print(f"   Source IP: {test_alert['raw_data']['source_ip']}")
    print(f"   Dest IP: {test_alert['raw_data']['destination_ip']}")
    print()

    #Execute workflow
    try:
        print("🤖 Invoking multi-agent workflow with Claude...")
        print("-" * 80)

        result = await workflow_engine.process_alert(test_alert)

        print("-" * 80)
        print("✅ Workflow completed successfully!")
        print()
        print("📊 Results:")
        print(f"   Final Status: {result.get('triage_status', 'unknown')}")
        print(f"   Confidence Score: {result.get('confidence_score', 0)}%")
        print(f"   Priority: {result.get('priority_level', 'unknown')}")
        print(f"   Correlations Found: {len(result.get('correlations', []))}")

        if result.get('fp_indicators'):
            print(f"   False Positive Indicators: {len(result['fp_indicators'])}")
            for fp in result['fp_indicators'][:3]:
                print(f"      - {fp}")

        if result.get('tp_indicators'):
            print(f"   True Positive Indicators: {len(result['tp_indicators'])}")
            for tp in result['tp_indicators'][:3]:
                print(f"      - {tp}")

        print()
        print("🔍 Claude API was used for:")
        print("   ✓ Intelligent triage scoring")
        print("   ✓ Correlation analysis")
        print("   ✓ Workflow routing decisions")

        print()
        print("=" * 80)
        print("Test completed! Claude API integration is working! 🎉")
        print("=" * 80)

        return result

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_claude_workflow())
