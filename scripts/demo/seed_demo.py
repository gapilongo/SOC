#!/usr/bin/env python3
"""Post the demo alert set to a running LG-SOTF API and time the triage (standard library only).

    python3 scripts/demo/seed_demo.py --base-url http://127.0.0.1:8000 \\
        --credentials .quickstart/admin-credentials.txt --api-key-file .quickstart/ingest-api-key

Used by ``scripts/quickstart.sh``, but works against any deployment:

1. waits for ``/readyz``;
2. signs in as the admin named in ``--credentials`` (a private ``KEY=value``
   file with ``EMAIL``, ``PASSWORD`` and optionally ``TENANT``);
3. creates an ``ingest``-scoped API key and stores it in ``--api-key-file``
   (mode 0600), or reuses the key already there;
4. posts ``--alerts`` (``scripts/demo/alerts.json``) to ``/ingest/alerts``
   with that key, shifting ``occurred_at`` so the newest alert is two minutes
   old and suffixing ``source_alert_id`` so a re-run creates new alerts;
5. polls ``/alerts`` until every posted alert has left the queue (closed,
   waiting for an analyst or waiting for an approval) and prints the result
   and the measured times. ``--started-at`` (epoch seconds) adds the time
   from that moment, e.g. the start of the quickstart, to the first verdict.

Secrets are read from files and never printed. Exit code 0 when every alert
was triaged in time, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

API = "/api/v1"
SETTLED = ("closed", "waiting_human", "waiting_approval")
DEFAULT_ALERTS = Path(__file__).resolve().parent / "alerts.json"
NEWEST_ALERT_AGE = timedelta(minutes=2)


class SeedError(Exception):
    pass


def read_kv(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def write_private(path: Path, text: str) -> None:
    """Create ``path`` readable by its owner only (refuses to overwrite)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


class Client:
    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self, method: str, path: str, *, body: Any = None, headers: Optional[Mapping[str, str]] = None
    ) -> Tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(  # noqa: S310 - the operator's own API URL
            self.base_url + path,
            data=data,
            method=method,
            headers={"Accept": "application/json", **({"Content-Type": "application/json"} if data else {}), **(headers or {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = None
            return exc.code, payload


def shifted(alerts: List[Dict[str, Any]], now: datetime, run: str) -> List[Dict[str, Any]]:
    """Copies with ``occurred_at`` moved so the newest is ``NEWEST_ALERT_AGE`` old, and run-unique ids."""
    stamps = [datetime.fromisoformat(a["occurred_at"].replace("Z", "+00:00")) for a in alerts if a.get("occurred_at")]
    delta = (now - NEWEST_ALERT_AGE - max(stamps)) if stamps else timedelta(0)
    out = []
    for alert in alerts:
        copy = json.loads(json.dumps(alert))
        if copy.get("occurred_at"):
            when = datetime.fromisoformat(copy["occurred_at"].replace("Z", "+00:00")) + delta
            copy["occurred_at"] = when.astimezone(UTC).isoformat().replace("+00:00", "Z")
        if copy.get("source_alert_id"):
            copy["source_alert_id"] = f"{copy['source_alert_id']}-{run}"
        out.append(copy)
    return out


def load_alerts(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    alerts = data["alerts"] if isinstance(data, dict) else data
    if not isinstance(alerts, list) or not alerts:
        raise SeedError(f"{path}: no alerts")
    return alerts


def wait_ready(client: Client, within: float) -> None:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            status, _ = client.request("GET", "/readyz")
            if status == 200:
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1.0)
    raise SeedError(f"the API was not ready within {within:.0f} s")


def login(client: Client, creds: Mapping[str, str]) -> Dict[str, str]:
    body: Dict[str, Any] = {"email": creds["EMAIL"], "password": creds["PASSWORD"]}
    if creds.get("TENANT"):
        body["tenant"] = creds["TENANT"]
    status, payload = client.request("POST", f"{API}/auth/login", body=body)
    if status != 200 or not isinstance(payload, dict) or "access_token" not in payload:
        raise SeedError(f"admin sign-in failed (HTTP {status})")
    return {"Authorization": f"Bearer {payload['access_token']}"}


def ingest_key(client: Client, auth: Mapping[str, str], path: Path) -> str:
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return path.read_text(encoding="utf-8").strip()
    status, payload = client.request(
        "POST", f"{API}/api-keys", body={"name": "quickstart-ingest", "scopes": ["ingest"]}, headers=auth
    )
    if status != 201 or not isinstance(payload, dict) or not payload.get("key"):
        raise SeedError(f"creating the ingest API key failed (HTTP {status})")
    write_private(path, payload["key"] + "\n")
    print(f"ok    created an ingest API key (stored in {path})")
    return str(payload["key"])


def list_alerts(client: Client, auth: Mapping[str, str]) -> Dict[str, Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}
    cursor: Optional[str] = None
    while True:
        query = "?limit=200" + (f"&cursor={urllib.parse.quote(cursor)}" if cursor else "")
        status, page = client.request("GET", f"{API}/alerts{query}", headers=auth)
        if status == 401:
            raise SeedError("session expired while waiting")
        if status != 200 or not isinstance(page, dict):
            raise SeedError(f"listing alerts failed (HTTP {status})")
        found.update({a["id"]: a for a in page.get("items", [])})
        cursor = page.get("next_cursor")
        if not cursor:
            return found


def fmt_duration(seconds: float) -> str:
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs:02d}s" if minutes else f"{secs}s"


def run(args: argparse.Namespace) -> int:
    client = Client(args.base_url)
    creds = read_kv(args.credentials)
    for key in ("EMAIL", "PASSWORD"):
        if not creds.get(key):
            raise SeedError(f"{args.credentials} has no {key}")
    wait_ready(client, args.ready_timeout)
    auth = login(client, creds)
    key = ingest_key(client, auth, args.api_key_file)

    run_tag = "qs" + datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    alerts = shifted(load_alerts(args.alerts), datetime.now(UTC), run_tag)
    posted_at = time.time()
    status, body = client.request("POST", f"{API}/ingest/alerts", body={"alerts": alerts}, headers={"X-API-Key": key})
    if status != 202 or not isinstance(body, dict):
        raise SeedError(f"ingest failed (HTTP {status})")
    ids = [i["alert_id"] for i in body.get("items", []) if i.get("status") == "inserted"]
    print(f"ok    posted {len(alerts)} demo alerts: {body.get('inserted')} stored, {body.get('rejected')} rejected")
    if not ids:
        raise SeedError("no alert was stored")

    first_verdict: Optional[float] = None
    deadline = time.monotonic() + args.timeout
    current: Dict[str, Dict[str, Any]] = {}
    while time.monotonic() < deadline:
        listed = list_alerts(client, auth)
        current = {a: listed[a] for a in ids if a in listed}
        done = [a for a in current.values() if a["status"] in SETTLED or a["status"] == "failed"]
        if first_verdict is None and any(a["status"] in SETTLED for a in done):
            first_verdict = time.time()
            print(f"ok    first verdict {fmt_duration(first_verdict - posted_at)} after ingest")
        if len(done) == len(ids):
            break
        time.sleep(1.0)
    finished = time.time()

    rows = sorted(current.values(), key=lambda a: a.get("occurred_at", ""))
    print()
    print(f"{'severity':<9} {'status':<17} {'disposition':<15} title")
    for a in rows:
        print(f"{a['severity']:<9} {a['status']:<17} {a.get('disposition') or '-':<15} {a['title'][:70]}")
    settled = [a for a in rows if a["status"] in SETTLED]
    failed = [a for a in rows if a["status"] == "failed"]
    timing: Dict[str, Any] = {
        "alerts": len(ids),
        "triaged": len(settled),
        "failed": len(failed),
        "provider": args.provider,
        "first_verdict_after_ingest_s": round(first_verdict - posted_at, 1) if first_verdict else None,
        "all_triaged_after_ingest_s": round(finished - posted_at, 1) if len(settled) == len(ids) else None,
        "first_verdict_after_start_s": (
            round(first_verdict - args.started_at, 1) if first_verdict and args.started_at else None
        ),
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    print()
    print(f"triaged {len(settled)}/{len(ids)} alerts" + (f", {len(failed)} failed" if failed else ""))
    if first_verdict is not None:
        print(f"time to first verdict: {fmt_duration(first_verdict - posted_at)} after ingest", end="")
        if args.started_at:
            print(f", {fmt_duration(first_verdict - args.started_at)} after the quickstart started", end="")
        print()
    if timing["all_triaged_after_ingest_s"] is not None:
        print(f"all {len(ids)} alerts triaged {fmt_duration(timing['all_triaged_after_ingest_s'])} after ingest")
    if args.timing_out is not None:
        args.timing_out.write_text(json.dumps(timing, indent=2) + "\n", encoding="utf-8")
    return 0 if len(settled) == len(ids) else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--credentials", type=Path, required=True, help="KEY=value file with EMAIL, PASSWORD, TENANT")
    parser.add_argument("--api-key-file", type=Path, required=True, help="Where the ingest API key is kept (0600)")
    parser.add_argument("--alerts", type=Path, default=DEFAULT_ALERTS)
    parser.add_argument("--timeout", type=float, default=900.0, help="Seconds to wait for triage")
    parser.add_argument("--ready-timeout", type=float, default=180.0)
    parser.add_argument("--started-at", type=float, default=None, help="Epoch seconds the measurement starts from")
    parser.add_argument("--timing-out", type=Path, default=None, help="Write the measured times as JSON here")
    parser.add_argument("--provider", default=os.environ.get("LG_SOTF_LLM__PROVIDER", "unknown"))
    args = parser.parse_args(argv)
    try:
        return run(args)
    except SeedError as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
