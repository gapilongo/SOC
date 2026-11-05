#!/usr/bin/env python3
"""Export the API's OpenAPI document to ``docs/openapi.json``.

    python scripts/export_openapi.py            # rewrite docs/openapi.json
    python scripts/export_openapi.py --check    # print to stdout; exit 1 if the committed file differs

The app is built the way the unit tests build it (explicit test settings, no
``.env``, no observability), so the output does not depend on the machine.
Keys are sorted and the file ends with a newline, so a diff shows only real
contract changes. ``tests/unit/api/test_openapi_snapshot.py`` compares the
committed file with a fresh export; after an intended API change (or a
FastAPI/pydantic upgrade, or a version bump) rerun this script and review the
diff.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = REPO_ROOT / "docs" / "openapi.json"
REGENERATE = "python scripts/export_openapi.py"

# Same base as the ``make_settings`` fixture in tests/conftest.py. The schema does not
# depend on settings; these only let the app factory run without a .env file.
_SETTINGS: Dict[str, Any] = {
    "environment": "test",
    "llm": {"provider": "fake", "allow_fake": True},
    "security": {
        "encryption_keys": "bGctc290Zi10ZXN0LXN1aXRlLW9ubHkta2V5LTAwMDA=",
        "indicator_hmac_key": "lg-sotf-test-suite-only-indicator-hmac-key",
    },
}


def build_openapi() -> Dict[str, Any]:
    from lg_sotf.api.app import create_app
    from lg_sotf.settings import Settings

    settings = Settings(_env_file=None, **_SETTINGS)
    return create_app(settings, configure_observability=False).openapi()


def render(schema: Dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="write to stdout instead of docs/openapi.json; exit 1 if the committed file differs",
    )
    args = parser.parse_args(argv)
    text = render(build_openapi())
    if args.check:
        sys.stdout.write(text)
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None
        if current != text:
            print(f"{OUTPUT.relative_to(REPO_ROOT)} is stale; regenerate with: {REGENERATE}", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(text)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
