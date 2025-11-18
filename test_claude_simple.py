#!/usr/bin/env python3
"""Simple test to demonstrate Claude API is working."""

import asyncio
import os

# Set environment for Anthropic to auto-discover credentials
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.utils.llm import get_llm_client

async def test_claude_api():
    """Test that Claude API is accessible and working."""

    print("=" * 80)
    print("🧪 TESTING CLAUDE API INTEGRATION")
    print("=" * 80)
    print()

    # Load configuration
    config_manager = ConfigManager("configs/development.yaml")

    print("📋 Configuration:")
    print(f"   LLM Provider: {config_manager.get('llm.provider')}")
    print(f"   LLM Model: {config_manager.get('llm.model')}")
    print(f"   Temperature: {config_manager.get('llm.temperature')}")
    print()

    # Get LLM client
    print("🔌 Initializing Claude client...")
    llm_client = get_llm_client(config_manager)
    print(f"   ✓ Client initialized: {type(llm_client).__name__}")
    print()

    # Test with a security triage question
    print("🤖 Testing Claude API with security triage task...")
    print("-" * 80)

    test_alert = {
        "source_ip": "192.168.1.100",
        "destination_ip": "185.220.101.50",
        "destination_port": 4444,
        "process_name": "update.exe",
        "file_hash": "a1b2c3d4e5f6789",
        "user": "administrator"
    }

    prompt = f"""You are a cybersecurity analyst. Analyze this security alert and determine if it's a true positive (TP) or false positive (FP).

Alert Data:
- Source IP: {test_alert['source_ip']}
- Destination IP: {test_alert['destination_ip']}
- Destination Port: {test_alert['destination_port']}
- Process: {test_alert['process_name']}
- User: {test_alert['user']}
- File Hash: {test_alert['file_hash']}

Provide a JSON response with:
{{
  "verdict": "TP" or "FP",
  "confidence": 0-100,
  "reasoning": "brief explanation",
  "threat_level": "low/medium/high/critical",
  "indicators": ["list", "of", "suspicious", "indicators"]
}}"""

    # Call Claude API
    response = await llm_client.ainvoke(prompt)

    print("📨 Claude Response:")
    print(response.content)
    print("-" * 80)
    print()

    print("✅ SUCCESS! Claude API is working!")
    print()
    print("🎯 This proves the SOC system can use Claude for:")
    print("   • Intelligent alert triage")
    print("   • Correlation analysis")
    print("   • Threat assessment")
    print("   • Automated decision making")
    print()
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(test_claude_api())
