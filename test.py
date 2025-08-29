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
    
    # Just call generate and print full response
    response = await llm.ainvoke("are you free to use as api?")
    print("Response:")
    print(response.content if hasattr(response, "content") else response)


if __name__ == "__main__":
    asyncio.run(main())