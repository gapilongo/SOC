"""Fetch the AIT Alert Data Set and sample ``aitads_v1`` from it (see ``tests/fixtures/aitads/__init__.py``).

    python -m tests.fixtures.aitads fetch DIR                 # download ait_ads.zip and labels.csv, check md5, unzip
    python -m tests.fixtures.aitads build DIR --out FILE      # sample aitads_v1 (.jsonl or .jsonl.gz) from DIR

DIR holds ~2.8 GB once extracted: keep it outside the repository (and outside /tmp, which may be cleared).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import httpx

from tests.fixtures.aitads.loader import FILES, SCENARIOS, ZENODO_RECORD, build
from tests.fixtures.attack_corpus.corpus import gzip_bytes, sha256_text

DOWNLOAD_URL = "https://zenodo.org/api/records/8263181/files/{name}/content"


def _md5(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(directory: Path) -> None:
    """Download the release into ``directory`` (skipping files already there with the right md5) and unzip it."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, md5 in FILES.items():
        target = directory / name
        if not (target.exists() and _md5(target) == md5):
            with httpx.stream("GET", DOWNLOAD_URL.format(name=name), follow_redirects=True, timeout=600) as response:
                response.raise_for_status()
                with target.open("wb") as fh:
                    for chunk in response.iter_bytes():
                        fh.write(chunk)
        if _md5(target) != md5:
            raise SystemExit(f"{name}: md5 differs from the one {ZENODO_RECORD} publishes")
    with zipfile.ZipFile(directory / "ait_ads.zip") as archive:
        for member in archive.namelist():
            if member.endswith("_wazuh.json") and "/" not in member and not (directory / member).exists():
                archive.extract(member, directory)
    print(f"{directory}: AIT-ADS ready ({', '.join(SCENARIOS)})")


def _lines(path: Path) -> Iterator[str]:
    with path.open(encoding="utf-8") as fh:
        yield from fh


def build_file(directory: Path, out: Path, per_scenario: int, attack_share: float, seed: int,
               scenarios: Optional[List[str]] = None) -> str:
    sources: Dict[str, Iterator[str]] = {
        name: _lines(directory / f"{name}_wazuh.json") for name in (scenarios or SCENARIOS)
    }
    text = build(sources, (directory / "labels.csv").read_text(encoding="utf-8"),
                 per_scenario=per_scenario, attack_share=attack_share, seed=seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(gzip_bytes(text) if out.suffix == ".gz" else text.encode("utf-8"))
    return text


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.fixtures.aitads", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p_fetch = sub.add_parser("fetch", help="download and unzip the release")
    p_fetch.add_argument("directory", type=Path)
    p_build = sub.add_parser("build", help="sample aitads_v1 from a fetched directory")
    p_build.add_argument("directory", type=Path)
    p_build.add_argument("--out", type=Path, required=True)
    p_build.add_argument("--per-scenario", type=int, default=5000)
    p_build.add_argument("--attack-share", type=float, default=0.2)
    p_build.add_argument("--seed", type=int, default=20261108)
    p_build.add_argument("--scenario", action="append", choices=SCENARIOS, help="only these scenarios (repeatable)")
    args = parser.parse_args(argv)
    if args.command == "fetch":
        fetch(args.directory)
        return 0
    text = build_file(args.directory, args.out, args.per_scenario, args.attack_share, args.seed, args.scenario)
    print(f"{args.out}: {text.count(chr(10)) - 1} items, sha256 of the JSONL text {sha256_text(text)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
