"""Seed the Wazuh lab or load more alerts into it (see ``tests/fixtures/wazuh_lab/__init__.py``).

    python -m tests.fixtures.wazuh_lab seed [--url URL] [--template FILE]
    python -m tests.fixtures.wazuh_lab load FILE [FILE ...] [--index NAME] [--url URL]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from tests.fixtures.wazuh_lab import DEFAULT_URL, SAMPLE_ALERTS, WazuhLab, read_alerts


def _load(lab: WazuhLab, files: List[Path], index: Optional[str]) -> int:
    failed = 0
    for path in files:
        indexed, rejected = lab.load(read_alerts(path), index)
        print(f"{path}: {indexed} alerts indexed" + (f", {len(rejected)} rejected: {sorted(set(rejected))}" if rejected else ""))
        failed += len(rejected)
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.fixtures.wazuh_lab")
    parser.add_argument("--url", default=os.environ.get("LG_SOTF_WAZUH_LAB_URL", DEFAULT_URL), help="lab indexer URL")
    parser.add_argument("--ca", default=os.environ.get("LG_SOTF_TEST_WAZUH_CA"), help="the lab's root CA (PEM)")
    sub = parser.add_subparsers(dest="command", required=True)
    seed = sub.add_parser("seed", help="install the wazuh template and load the sample alerts")
    seed.add_argument("--template", type=Path, help="a local wazuh-template.json instead of the pinned download")
    load = sub.add_parser("load", help="load alert files (JSON with 'events', or alerts.json lines)")
    load.add_argument("files", type=Path, nargs="+")
    load.add_argument("--index", help="target index (default: wazuh-alerts-4.x-<day of each alert>)")
    args = parser.parse_args(argv)

    with WazuhLab(args.url, ca_file=args.ca) as lab:
        lab.wait_ready()
        if args.command == "seed":
            lab.install_template(args.template.read_bytes() if args.template else None)
            return _load(lab, [SAMPLE_ALERTS], None)
        if not lab.has_template():
            print("the wazuh template is not installed; run `seed` first", file=sys.stderr)
            return 1
        return _load(lab, args.files, args.index)


if __name__ == "__main__":
    sys.exit(main())
