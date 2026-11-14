#!/usr/bin/env python3
"""Load the telemetry around chosen corpus alerts into a Wazuh indexer (OpenSearch), shifted to "now".

The investigation harness (ADR 0014, Amendment 1) is measured two ways at
every step: offline on ``corpus_v1`` with its event store, and on a live stack
that receives corpus alerts with their timestamps moved to the present. The
Wazuh evidence tools then query the stack's indexer, so the telemetry around
each alert has to be there too, around the same moment. This script puts it
there::

    LG_SOTF_CORPUS_INDEXER_URL=https://indexer.lab.example:9200 \\
    LG_SOTF_CORPUS_INDEXER_USERNAME=... LG_SOTF_CORPUS_INDEXER_PASSWORD=... \\
    python scripts/load_corpus_telemetry.py --host indexer.lab.example \\
        --items cv1-0003,cv1-0069,cv1-0113 --manifest build/telemetry-manifest.json

For every item it selects, from the dataset's alerts and its context events
(``tests/fixtures/eval/<dataset>_events.jsonl.gz``), what an evidence tool can
read about that alert: the host's activity an hour either side, the logons
of the alert's source address, user and workstation over the day before, and
every earlier sighting of its service, image path or process image in the 30
days before. Each document is copied with its time moved by the same amount
as the alert, so the alert sits at its **anchor** (``--now``, plus ``--pace``
seconds per item) and its context keeps its distance from it. The manifest
lists each item's anchor: send the alert with that timestamp.

Safety:

* the indexer URL and credentials come from the environment and are never
  printed, not even in an error;
* the URL's host must be passed with ``--host``, or nothing is sent;
* only ``POST /<index>/_bulk`` is called, on one explicit index
  (``--index``, default ``wazuh-alerts-4.x-corpus-telemetry`` so the Wazuh
  index template gives the fields their production mappings). A pull source
  that reads ``wazuh-alerts-*`` would ingest these documents as alerts: give
  the stack's source a narrower index pattern, or load into another index.

Loading is idempotent: a document's ``_id`` is ``<item id>:<source document
id>``, so loading the same items again replaces their copies (around the new
anchor) instead of adding to them. Two chosen items whose context overlaps (a
spray's alerts, two alerts on one host within the hour) each bring their own
copy; space them with ``--pace`` when that matters. Free-text log lines keep
their original clock; the indexed time fields are shifted.

``--dry-run`` selects and counts without reading the environment or sending.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import httpx

from lg_sotf.eval.tool_fixtures import EventQuery, EventStore, event_time, field_values

REPO_ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = REPO_ROOT / "tests" / "fixtures" / "eval"
DATASETS = ("corpus_v1", "corpus_skills_v1")
DEFAULT_INDEX = "wazuh-alerts-4.x-corpus-telemetry"
ENV_PREFIX = "LG_SOTF_CORPUS_INDEXER_"
URL_ENV = ENV_PREFIX + "URL"
USERNAME_ENV = ENV_PREFIX + "USERNAME"
PASSWORD_ENV = ENV_PREFIX + "PASSWORD"
CA_ENV = ENV_PREFIX + "CA_FILE"
ED = "data.win.eventdata."
LOGON_EVENT_IDS = ("4624", "4625", "4648", "4740", "4771", "4776")
HOST_WINDOW = timedelta(minutes=60)
LOGON_WINDOW = timedelta(minutes=1440)
PREVALENCE_WINDOW = timedelta(days=30)
#: Fields that identify who or where a logon came from, and the alert fields whose value they are matched with.
LOGON_PIVOTS = (("ipAddress", ("ipAddress",)), ("targetUserName", ("targetUserName",)),
                ("workstationName", ("workstationName", "callerComputerName")),
                ("callerComputerName", ("workstationName", "callerComputerName")))
PREVALENCE_FIELDS = ("imagePath", "serviceName", "image")
_INDEX = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,254}$")
_STAMP = "%Y-%m-%dT%H:%M:%S.%f"


class LoadError(Exception):
    """The load cannot go ahead; the message never carries the URL or a credential."""


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    raw = path.read_bytes()
    text = (gzip.decompress(raw) if path.suffix == ".gz" else raw).decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_dataset(dataset: str, directory: Path = EVAL_DIR) -> Tuple[Dict[str, Dict[str, Any]], EventStore]:
    """The dataset's alerts by item id, and the store of everything around them."""
    if dataset not in DATASETS:
        raise LoadError(f"unknown dataset {dataset!r}; one of {', '.join(DATASETS)}")
    items = [row for row in read_jsonl(directory / f"{dataset}.jsonl.gz") if "_meta" not in row]
    events = [row for row in read_jsonl(directory / f"{dataset}_events.jsonl.gz") if "_meta" not in row]
    return {row["id"]: row["alert"] for row in items}, EventStore([*(row["alert"] for row in items), *events])


def context_docs(store: EventStore, alert: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """What an evidence tool can read about ``alert``, itself included, in time order."""
    at = event_time(alert)
    view = store.as_of(at + HOST_WINDOW)
    queries = [EventQuery(agent=str(alert["agent"]["name"]), start=at - HOST_WINDOW)]
    for path, sources in LOGON_PIVOTS:
        values = sorted({v for name in sources for v in field_values(alert, ED + name) if v not in ("", "-")})
        if values:
            queries.append(EventQuery(start=at - LOGON_WINDOW, event_ids=LOGON_EVENT_IDS, where={ED + path: values}))
    for name in PREVALENCE_FIELDS:
        values = field_values(alert, ED + name)
        if values:
            queries.append(EventQuery(start=at - PREVALENCE_WINDOW, where={ED + name: values}))
    found: Dict[str, Dict[str, Any]] = {}
    for query in queries:
        for doc in view.select(query):
            found.setdefault(str(doc["id"]), doc)
    return sorted(found.values(), key=lambda d: (event_time(d), str(d["id"])))


def _millis(at: datetime) -> str:
    at = at.astimezone(UTC)
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}"


def shifted(doc: Mapping[str, Any], delta: timedelta) -> Dict[str, Any]:
    """A copy of ``doc`` moved in time by ``delta``: the manager's timestamps, its id and the event's own clock."""
    moved = copy.deepcopy(dict(doc))
    at = event_time(doc) + delta
    moved["timestamp"] = _millis(at) + "+0000"
    moved["@timestamp"] = _millis(at) + "Z"
    moved["id"] = f"{int(at.timestamp())}.{str(doc['id']).split('.', 1)[-1]}"
    win = (moved.get("data") or {}).get("win") or {}
    system, eventdata = win.get("system") or {}, win.get("eventdata") or {}
    if "systemTime" in system:
        system["systemTime"] = at.astimezone(UTC).strftime(_STAMP) + "0Z"
    if "utcTime" in eventdata:
        eventdata["utcTime"] = at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return moved


def plan(dataset: str, item_ids: Sequence[str], now: datetime, pace_s: float,
         directory: Path = EVAL_DIR) -> Tuple[List[Dict[str, Any]], List[Tuple[str, Dict[str, Any]]]]:
    """The manifest (item, anchor, document count) and the ``(_id, document)`` pairs to index."""
    alerts, store = load_dataset(dataset, directory)
    unknown = [item_id for item_id in item_ids if item_id not in alerts]
    if unknown:
        raise LoadError(f"not items of {dataset}: {', '.join(unknown)}")
    manifest: List[Dict[str, Any]] = []
    actions: List[Tuple[str, Dict[str, Any]]] = []
    for position, item_id in enumerate(dict.fromkeys(item_ids)):
        anchor = now + timedelta(seconds=pace_s * position)
        delta = anchor - event_time(alerts[item_id])
        docs = context_docs(store, alerts[item_id])
        actions += [(f"{item_id}:{doc['id']}", shifted(doc, delta)) for doc in docs]
        manifest.append({"item": item_id, "anchor": _millis(anchor) + "+0000", "documents": len(docs)})
    return manifest, actions


def checked_url(url: str, allowed_hosts: Iterable[str]) -> str:
    """``url`` when it is an http(s) URL whose host was explicitly passed; the error names neither."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LoadError(f"{URL_ENV} is not an http(s) URL")
    if parts.hostname.lower() not in {h.strip().lower() for h in allowed_hosts}:
        raise LoadError(f"the host in {URL_ENV} was not passed with --host; refusing to send")
    if parts.username or parts.password:
        raise LoadError(f"{URL_ENV} must not carry credentials; use {USERNAME_ENV} and {PASSWORD_ENV}")
    return f"{parts.scheme}://{parts.netloc}"


def bulk_body(index: str, actions: Sequence[Tuple[str, Mapping[str, Any]]]) -> str:
    lines: List[str] = []
    for doc_id, doc in actions:
        lines += [json.dumps({"index": {"_index": index, "_id": doc_id}}), json.dumps(doc, ensure_ascii=False)]
    return "\n".join(lines) + "\n"


def send(client: httpx.Client, index: str, actions: Sequence[Tuple[str, Mapping[str, Any]]],
         batch: int = 500) -> Tuple[int, List[str]]:
    """Bulk-index ``actions``; returns (documents accepted, reasons of the rejected ones)."""
    accepted, rejected = 0, []
    for start in range(0, len(actions), batch):
        chunk = actions[start:start + batch]
        try:
            response = client.post(f"/{index}/_bulk", params={"refresh": "true"}, content=bulk_body(index, chunk),
                                   headers={"Content-Type": "application/x-ndjson"})
        except httpx.HTTPError as exc:  # the exception text can hold the URL
            raise LoadError(f"the indexer request failed ({type(exc).__name__})") from None
        if response.status_code >= 300:
            raise LoadError(f"the indexer answered HTTP {response.status_code}")
        results = [row.get("index", {}) for row in response.json().get("items", [])]
        rejected += [str((row.get("error") or {}).get("type", "error")) for row in results if row.get("error")]
        accepted += sum(1 for row in results if not row.get("error"))
    return accepted, rejected


def _client(base_url: str, ca_file: Optional[str]) -> httpx.Client:
    username, password = os.environ.get(USERNAME_ENV), os.environ.get(PASSWORD_ENV)
    if not username or not password:
        raise LoadError(f"set {USERNAME_ENV} and {PASSWORD_ENV}")
    return httpx.Client(base_url=base_url, auth=(username, password), verify=ca_file or True, timeout=60.0,
                        trust_env=False, follow_redirects=False)


def _item_ids(args: argparse.Namespace) -> List[str]:
    ids = [part.strip() for part in (args.items or "").split(",") if part.strip()]
    if args.items_file:
        ids += [line.split()[0] for line in args.items_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")]
    if not ids:
        raise LoadError("no items: pass --items or --items-file")
    return ids


def _now(value: Optional[str]) -> datetime:
    if value is None:
        return datetime.now(UTC)
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise LoadError("--now must be an ISO 8601 time, for example 2026-11-14T09:00:00Z") from None
    if when.tzinfo is None:
        raise LoadError("--now needs a time zone (end it with Z for UTC)")
    return when


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n", 1)[0])
    parser.add_argument("--dataset", choices=DATASETS, default=DATASETS[0])
    parser.add_argument("--items", help="comma-separated item ids, for example cv1-0003,cv1-0069")
    parser.add_argument("--items-file", type=Path, help="a file with one item id per line")
    parser.add_argument("--host", action="append", default=[], metavar="HOST",
                        help=f"an indexer host the load may go to; the host of {URL_ENV} must be one (repeatable)")
    parser.add_argument("--index", default=DEFAULT_INDEX, help=f"target index (default: {DEFAULT_INDEX})")
    parser.add_argument("--now", help="anchor of the first item (ISO 8601, default: the current time)")
    parser.add_argument("--pace", type=float, default=0.0, metavar="SECONDS",
                        help="seconds between the anchors of consecutive items (default: 0)")
    parser.add_argument("--ca-file", default=os.environ.get(CA_ENV),
                        help=f"CA bundle for the indexer's certificate (default: ${CA_ENV}, else the system store)")
    parser.add_argument("--manifest", type=Path, help="write each item's anchor to this JSON file")
    parser.add_argument("--dry-run", action="store_true", help="select and count; read no environment, send nothing")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> str:
    if not _INDEX.match(args.index):
        raise LoadError("--index must be one concrete index name (lower case, no wildcard)")
    manifest, actions = plan(args.dataset, _item_ids(args), _now(args.now), args.pace)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps({"dataset": args.dataset, "index": args.index, "items": manifest},
                                            indent=1) + "\n", encoding="utf-8")
    summary = f"{len(actions)} documents around {len(manifest)} items of {args.dataset}"
    if args.dry_run:
        return f"dry run: {summary} would go to index {args.index}"
    url = os.environ.get(URL_ENV)
    if not url:
        raise LoadError(f"set {URL_ENV} (and pass its host with --host)")
    with _client(checked_url(url, args.host), args.ca_file) as client:
        accepted, rejected = send(client, args.index, actions)
    if rejected:
        raise LoadError(f"{accepted} documents indexed, {len(rejected)} rejected: {', '.join(sorted(set(rejected)))}")
    return f"{summary} indexed into {args.index}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        print(run(parse_args(argv)))
    except LoadError as exc:
        print(f"load_corpus_telemetry: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
