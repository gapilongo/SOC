"""Synthetic vendor payloads (see README.md in this directory)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

VENDOR_DIR = Path(__file__).parent


def load_vendor(name: str) -> Dict[str, Any]:
    data = json.loads((VENDOR_DIR / f"{name}.json").read_text(encoding="utf-8"))
    assert data.get("_synthetic"), f"{name}.json must be marked synthetic"
    return data


def vendor_events(name: str) -> List[Dict[str, Any]]:
    return list(load_vendor(name)["events"])
