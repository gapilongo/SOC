#!/usr/bin/env python3
"""
Minimal LLM test - just test the existing code behavior.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.utils.llm import get_llm_client


async def main():
    """Minimal test."""
    # Load config and create LLM client
    config_manager = ConfigManager("configs/development.yaml")
    llm = get_llm_client(config_manager)

    # Test prompt for security analysis
    prompt = """
    Analyze this security alert for me:

    Type: Unauthorized Access Attempt
    Source IP: 192.168.1.15
    Destination: Database Server (10.0.0.5)
    Timestamp: 2023-11-15 14:32:18 UTC
    Details: Multiple failed login attempts to admin account

    Please provide:
    1. Threat assessment level
    2. Likelihood of being a real threat vs false positive
    3. Recommended immediate actions
    """

    print("Sending prompt to LLM:")
    print(prompt)
    print("\n" + "=" * 50 + "\n")

    # Call the LLM with our prompt
    try:
        response = await llm.ainvoke(prompt)
        print("LLM Response:")
        print(response.content)
    except Exception as e:
        print(f"Error: {e}")
        # Fallback to direct method call if ainvoke doesn't work
        response = await llm.ainvoke(prompt)
        print("LLM Response (fallback):")
        print(response)


if __name__ == "__main__":
    asyncio.run(main())
