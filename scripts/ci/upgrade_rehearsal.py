#!/usr/bin/env python3
"""HTTP driver and checks for ``scripts/ci/upgrade_rehearsal.sh`` (N-1 -> N upgrade with waiting runs).

Phases (``--base-url`` is the API of the release currently running):

``seed``
    on release N-1: create an ingest key, ingest ``--count`` alerts the fake
    LLM escalates (C2 beacons, each on its own host) and wait until every one
    waits for an analyst. With ``--mid-work``, as an analyst would leave the
    queue at upgrade time: claim one escalation and decide another as a true
    positive, so that run waits for an approval of its response actions.
    Records the alert ids in ``--state`` (appends on a second call).
    With ``--settle-within S`` (N-1 on the schema N migrated), alerts its
    worker has not settled after S seconds are left queued for release N
    (an N-1 worker may fail a message once per pooled connection after a
    migration altered a table it reads: asyncpg's InvalidCachedStatementError;
    the entry stays pending and release N's worker claims it from the stopped
    consumer). None may fail, and the ones it settles must wait for an analyst.
``drain``
    on release N: work the queue until every recorded alert is closed (decide
    each open or claimed escalation, approve each pending action), then
    ingest one new alert and work it to closed too. Fails on a failed alert,
    a decision that could not resume its runs, or an alert that never closes.
``privileges``
    compare the runtime role's catalog snapshots (``--before``/``--after``,
    lines from the shell script's ``privilege_snapshot``): nothing it had may
    change; privileges on objects that did not exist before (new tables or
    partitions) are allowed and listed.

Credentials come from the environment: ``SMOKE_ADMIN_EMAIL`` and
``SMOKE_ADMIN_PASSWORD`` (the bootstrap platform admin). Nothing secret is
printed. Reuses the stack smoke driver's helpers (``scripts/smoke_stack.py``).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from smoke_stack import (  # a standalone script next to this one
    ACTION_DONE,
    API,
    SETTLED,
    Session,
    Smoke,
    SmokeFailure,
    beacon_event,
    check,
    env,
    expect,
    expect_quiet,
    no_cookie_jar,
    ok,
)

WAITING = ("waiting_human", "waiting_approval")


def load_ids(state: Path) -> List[str]:
    if not state.exists():
        return []
    ids: List[str] = json.loads(state.read_text())["alert_ids"]
    return ids


def isolated_beacon(run: str, n: int) -> Dict[str, Any]:
    """A beacon the fake LLM leaves to an analyst: its own escalation, decided by nobody yet.

    Without the smoke beacon's description (malware, command and control) and
    with no entity shared with another alert (correlation raises the threat
    score), the score stays below the response policy and the run escalates.
    """
    event = beacon_event(run, n)
    del event["description"]
    event["entities"] = {"hosts": [f"ws-{run[:6]}-{n}"], "ips": [f"203.0.113.{n % 250 + 1}"], "users": [f"u{n}"]}
    return event


class Rehearsal(Smoke):
    async def admin(self) -> Session:
        email, password = env("SMOKE_ADMIN_EMAIL"), env("SMOKE_ADMIN_PASSWORD")
        assert email is not None and password is not None
        return await self.login(email, password)

    async def ingest(self, admin: Session, count: int, first: int) -> List[str]:
        key = expect_quiet(
            await self.client.post(
                f"{API}/api-keys", json={"name": f"upgrade-{self.run}", "scopes": ["ingest"]}, headers=admin.headers
            ),
            201,
        )
        batch = [isolated_beacon(self.run, first + n) for n in range(count)]
        body = expect(
            await self.client.post(f"{API}/ingest/alerts", json=batch, headers={"X-API-Key": key["key"]}),
            202,
            f"ingest {count} C2 beacon alerts",
        )
        ids = [i["alert_id"] for i in body["items"] if i["status"] == "inserted"]
        check(len(ids) == count, f"{len(ids)} alerts queued")
        return ids

    async def open_escalations(self, admin: Session, alert_ids: Set[str]) -> List[Dict[str, Any]]:
        page = expect_quiet(
            await self.client.get(
                f"{API}/escalations", params={"status": ["open", "claimed"], "limit": 200}, headers=admin.headers
            ),
            200,
        )
        return [e for e in page["items"] if {e["alert_id"], *e["related_alert_ids"]} & alert_ids]

    async def claim(self, admin: Session, esc: Dict[str, Any]) -> int:
        if esc["status"] == "claimed":
            return int(esc["version"])
        claimed = expect(
            await self.client.post(
                f"{API}/escalations/{esc['id']}/claim", json={"version": esc["version"]}, headers=admin.headers
            ),
            200,
            f"claim the escalation of alert {esc['alert_id']}",
        )
        return int(claimed["version"])

    async def decide(self, admin: Session, esc: Dict[str, Any], decision: str) -> None:
        version = await self.claim(admin, esc)
        decided = expect(
            await self.client.post(
                f"{API}/escalations/{esc['id']}/decision",
                json={"decision": decision, "version": version, "notes": f"upgrade rehearsal: {decision}"},
                headers=admin.headers,
            ),
            200,
            f"decide {decision} for alert {esc['alert_id']}",
        )
        check(
            decided["resumes_failed"] == 0 and esc["alert_id"] in decided["resumed_alert_ids"],
            f"{len(decided['resumed_alert_ids'])} waiting run(s) resumed",
            decided,
        )

    async def escalated(self, admin: Session, ids: List[str]) -> None:
        settled = await self.wait_statuses(admin, ids, SETTLED, f"{len(ids)} alerts to settle")
        statuses = {a: row["status"] for a, row in settled.items()}
        check(set(statuses.values()) == {"waiting_human"}, f"{len(ids)} runs wait for an analyst", statuses)

    async def settled_or_queued(self, admin: Session, ids: List[str], within: float) -> None:
        deadline = time.monotonic() + within
        while True:
            listed = await self.alerts_by_id(admin)
            statuses = {a: listed[a]["status"] for a in ids}
            if all(s in SETTLED for s in statuses.values()) or time.monotonic() > deadline:
                break
            await asyncio.sleep(1.0)
        left = [a for a, s in statuses.items() if s in ("new", "queued")]
        settled = {a: s for a, s in statuses.items() if a not in left}
        check(set(settled.values()) <= {"waiting_human"}, "settled runs wait for an analyst", statuses)
        ok(f"{len(settled)} of {len(ids)} settled within {within:.0f}s; {len(left)} left queued for release N")

    async def seed(
        self, known: List[str], count: int, mid_work: bool, settle_within: Optional[float] = None
    ) -> List[str]:
        """Alerts that wait for an analyst on this release (``known``: those seeded before)."""
        admin = await self.admin()
        ids = await self.ingest(admin, count, first=len(known))
        if settle_within is not None:
            await self.settled_or_queued(admin, ids, settle_within)
            return ids
        await self.escalated(admin, ids)
        if mid_work:
            escalations = await self.open_escalations(admin, set(ids))
            check(len(escalations) >= 2, f"{len(escalations)} open escalations")
            await self.claim(admin, escalations[0])
            await self.decide(admin, escalations[1], "true_positive")
            target = escalations[1]["alert_id"]
            await self.wait_statuses(admin, [target], ("waiting_approval",), "the true positive to wait for approval")
            ok("one run waits for an approval of its response actions")
        return ids

    async def work_queue(self, admin: Session, ids: List[str]) -> None:
        """Decide and approve until every alert in ``ids`` is closed (``wait_statuses`` fails on ``failed``)."""
        deadline = time.monotonic() + 2 * self.timeout
        while time.monotonic() < deadline:
            settled = await self.wait_statuses(admin, ids, SETTLED, "alerts to settle")
            waiting = {a for a, row in settled.items() if row["status"] in WAITING}
            if not waiting:
                ok(f"all {len(ids)} alerts closed")
                return
            for esc in await self.open_escalations(admin, waiting):
                await self.decide(admin, esc, "false_positive")
            for alert_id in sorted(a for a in waiting if settled[a]["status"] == "waiting_approval"):
                await self.approve_next(admin, alert_id)
            await asyncio.sleep(1.0)
        raise SmokeFailure(f"alerts still waiting after {2 * self.timeout:.0f}s")

    async def approve_next(self, admin: Session, alert_id: str) -> None:
        """Approve one pending action, as an analyst works, and wait until the run has settled again."""
        page = expect_quiet(
            await self.client.get(f"{API}/actions", params={"alert_id": alert_id}, headers=admin.headers), 200
        )
        todo = [a for a in page["items"] if a["status"] == "awaiting_approval"]
        if not todo:
            return  # approved a moment ago; the worker has not resumed the run yet
        action = todo[0]
        expect(
            await self.client.post(f"{API}/actions/{action['id']}/approve", json={}, headers=admin.headers),
            200,
            f"approve {action['action_type']} on alert {alert_id}",
        )
        done = await self.wait_action(admin, action["id"], ACTION_DONE)
        check(done["status"] == "dry_run", f"{action['action_type']} ran as a dry run", done["status"])
        await self.wait_statuses(admin, [alert_id], SETTLED, "the run to settle after the approval")

    async def drain(self, ids: List[str]) -> List[str]:
        """Close every alert in ``ids``, then one new alert: its id."""
        admin = await self.admin()
        check(bool(ids), f"{len(ids)} alerts from release N-1 to drain")
        await self.work_queue(admin, ids)
        fresh = await self.ingest(admin, 1, first=len(ids))
        await self.escalated(admin, fresh)
        await self.work_queue(admin, fresh)
        return fresh


def compare_privileges(before: Path, after: Path) -> None:
    """Snapshot lines are ``<kind>\\t<object>\\t<detail>``; ``object`` lines list what exists."""

    def read(path: Path) -> Set[str]:
        return {line for line in path.read_text().splitlines() if line.strip()}

    def grants(lines: Set[str]) -> Set[str]:
        return {line for line in lines if not line.startswith("object\t")}

    old, new = read(before), read(after)
    existed = {line.split("\t")[1] for line in old if line.startswith("object\t")}
    lost = sorted(grants(old) - grants(new))
    gained = sorted(grants(new) - grants(old))
    changed = [line for line in gained if line.split("\t")[1] in existed or line.split("\t")[0] in ("role", "member")]
    check(not lost, "the runtime role lost no privilege or attribute", lost)
    check(not changed, "the runtime role gained nothing on objects that existed before", changed)
    new_objects = sorted({line.split("\t")[1] for line in gained})
    ok(f"privileges on {len(new_objects)} new object(s): {', '.join(new_objects) or 'none'}")


async def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("phase", choices=["seed", "drain", "privileges"])
    parser.add_argument("--base-url", default=os.environ.get("SMOKE_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--state", type=Path, default=Path("upgrade-state.json"))
    parser.add_argument("--count", type=int, default=4)
    parser.add_argument("--mid-work", action="store_true")
    parser.add_argument("--settle-within", type=float)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        if args.phase == "privileges":
            compare_privileges(args.before, args.after)
        else:
            async with httpx.AsyncClient(base_url=args.base_url, timeout=30.0, cookies=no_cookie_jar()) as client:
                rehearsal = Rehearsal(client, args.base_url, timeout=args.timeout)
                known = load_ids(args.state)
                if args.phase == "seed":
                    seeded = await rehearsal.seed(known, args.count, args.mid_work, args.settle_within)
                    args.state.write_text(json.dumps({"alert_ids": known + seeded}))
                else:
                    fresh = await rehearsal.drain(known)
                    args.state.write_text(json.dumps({"alert_ids": known, "fresh_alert_ids": fresh}))
    except SmokeFailure as exc:
        print(f"FAIL  {exc}", flush=True)
        return 1
    print(f"done  {args.phase} in {time.monotonic() - started:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
