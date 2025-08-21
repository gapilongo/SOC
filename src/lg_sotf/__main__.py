"""
Module entry point for LG-SOTF.

This allows running the application as:
python -m lg_sotf.main
"""

import asyncio

from ...main import main

if __name__ == "__main__":
    asyncio.run(main())