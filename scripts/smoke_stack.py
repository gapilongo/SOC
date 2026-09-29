#!/usr/bin/env python3
"""Customer-path smoke test for a running LG-SOTF stack, through the HTTP API only.

Driven by ``scripts/smoke_stack.sh`` (which starts the docker compose stack),
but usable against any deployment::

    SMOKE_ADMIN_EMAIL=... SMOKE_ADMIN_PASSWORD=... SMOKE_METRICS_TOKEN=... \\
        python scripts/smoke_stack.py --base-url http://127.0.0.1:8000 flow

Phases (each prints one ``ok``/``FAIL`` line per check and exits non-zero on
the first failure):

``flow``
    readiness; admin login and the refresh-cookie attributes; an ``ingest``
    API key; canonical alerts to ``/ingest/alerts`` and vendor payloads to a
    ``webhook`` source; the WebSocket event stream; alerts settle; the
    escalated alert is claimed and decided; its pending actions are approved
    (dry-run) and the alert closes; dashboard, LLM usage, audit log and chain,
    ``/metrics`` with and without the token; tenant isolation against a
    second tenant's admin; refresh rotation, reuse refusal and logout.
``burst``
    ingest ``--count`` alerts and record their ids in ``--state`` (for the
    worker-restart check).
``settled``
    wait until every alert recorded by ``burst`` has left the queue
    (``--timeout`` seconds) and none is ``failed``.
``ready`` / ``unready``
    wait until ``/readyz`` answers 200 / 503.

Credentials come from the environment (never the command line):
``SMOKE_ADMIN_EMAIL``/``SMOKE_ADMIN_PASSWORD`` (a platform admin of the first
tenant), ``SMOKE_TENANT_B``/``SMOKE_TENANT_B_EMAIL``/``SMOKE_TENANT_B_PASSWORD``
(an ordinary admin of a second tenant; optional, isolation checks are skipped
without it) and ``SMOKE_METRICS_TOKEN`` (optional). Nothing secret is printed.

Needs Python 3.11+, ``httpx`` and ``websockets`` (both ship in the image).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from http.cookiejar import CookieJar, DefaultCookiePolicy
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import urlsplit, urlunsplit

import httpx

API = "/api/v1"
REFRESH_COOKIE = "lgsotf_refresh"
SETTLED = ("waiting_human", "waiting_approval", "closed")
ACTION_DONE = ("dry_run", "succeeded", "rejected", "blocked", "failed")
FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "vendors"


class SmokeFailure(Exception):
    pass


def ok(message: str) -> None:
    print(f"ok    {message}", flush=True)


def check(condition: bool, message: str, detail: Any = "") -> None:
    if not condition:
        raise SmokeFailure(f"{message}{': ' + str(detail)[:500] if detail != '' else ''}")
    ok(message)


def expect(response: httpx.Response, status: int, message: str) -> Any:
    if response.status_code != status:
        raise SmokeFailure(
            f"{message}: expected HTTP {status}, got {response.status_code} "
            f"{response.request.method} {response.request.url.path}: {response.text[:400]}"
        )
    ok(f"{message} ({status})")
    return response.json() if response.content and "json" in response.headers.get("content-type", "") else None


async def eventually(
    probe: Callable[[], Awaitable[Any]], what: str, within: float = 120.0, interval: float = 0.5
) -> Any:
    """Poll ``probe`` until it returns something truthy; fail with ``what`` after ``within`` seconds."""
    deadline = time.monotonic() + within
    last: Any = None
    while time.monotonic() < deadline:
        last = await probe()
        if last:
            return last
        await asyncio.sleep(interval)
    raise SmokeFailure(f"timed out after {within:.0f}s waiting for {what}")


def env(name: str, required: bool = True) -> Optional[str]:
    value = os.environ.get(name) or None
    if required and value is None:
        raise SmokeFailure(f"environment variable {name} is not set")
    return value


def load_fixture(name: str) -> Dict[str, Any]:
    data: Dict[str, Any] = json.loads((FIXTURES / name).read_text())
    return data


def beacon_event(run: str, n: int) -> Dict[str, Any]:
    """A synthetic alert the fake LLM escalates (C2 keywords) and plans containment for."""
    return {
        "source_alert_id": f"smoke-{run}-c2-{n}",
        "title": "Possible C2 beacon from workstation",
        "description": "Periodic beacon to a command and control server; malware suspected.",
        "severity": "medium",
        "occurred_at": "2024-03-05T10:05:00Z",
        "entities": {
            "ips": ["203.0.113.44", "10.0.0.5"],
            "hosts": [f"ws-{run[:6]}"],
            "users": ["jdoe"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "processes": ["powershell.exe"],
        },
    }


def burst_event(run: str, n: int) -> Dict[str, Any]:
    severities = ("low", "medium", "high")
    return {
        "source_alert_id": f"smoke-{run}-burst-{n}",
        "title": f"Suspicious login burst {n}",
        "severity": severities[n % len(severities)],
        "occurred_at": "2024-03-05T11:00:00Z",
        "entities": {"users": [f"user{n}"], "hosts": [f"host-{n % 7}"]},
    }


def ws_url(base_url: str, token: str) -> str:
    parts = urlsplit(base_url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urlunsplit((scheme, parts.netloc, f"{API}/ws", f"token={token}", ""))


def no_cookie_jar() -> CookieJar:
    """The refresh cookie is handled explicitly, so httpx must never store or replay cookies itself."""
    return CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))


@dataclass
class Session:
    access_token: str
    refresh_token: str
    cookie_attributes: Dict[str, Any]

    @property
    def headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


def parse_refresh_cookie(response: httpx.Response) -> Dict[str, Any]:
    for header in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(header)
        if REFRESH_COOKIE in cookie:
            morsel = cookie[REFRESH_COOKIE]
            lowered = header.lower()
            return {
                "value": morsel.value,
                "path": morsel["path"],
                "httponly": "httponly" in lowered,
                "secure": "secure" in lowered,
                "samesite": str(morsel["samesite"]).lower(),
                "max_age": morsel["max-age"],
            }
    raise SmokeFailure(f"no {REFRESH_COOKIE} cookie in the response")


@dataclass
class Smoke:
    client: httpx.AsyncClient
    base_url: str
    run: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    timeout: float = 180.0
    # WebSocket base URL when it differs from ``base_url`` (tests serve HTTP in-process over ASGI).
    ws_base_url: Optional[str] = None

    # -- helpers ---------------------------------------------------------------

    async def login(self, email: str, password: str, tenant: Optional[str] = None) -> Session:
        body: Dict[str, Any] = {"email": email, "password": password}
        if tenant:
            body["tenant"] = tenant
        response = await self.client.post(f"{API}/auth/login", json=body)
        data = expect(response, 200, f"login {email.split('@')[-1]}")
        cookie = parse_refresh_cookie(response)
        return Session(data["access_token"], cookie["value"], cookie)

    async def refresh(self, refresh_token: str) -> httpx.Response:
        return await self.client.post(f"{API}/auth/refresh", headers={"Cookie": f"{REFRESH_COOKIE}={refresh_token}"})

    async def alerts_by_id(self, session: Session, source_id: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        found: Dict[str, Dict[str, Any]] = {}
        cursor: Optional[str] = None
        while True:
            params: Dict[str, Any] = {"limit": 200}
            if source_id:
                params["source_id"] = source_id
            if cursor:
                params["cursor"] = cursor
            page = expect_quiet(await self.client.get(f"{API}/alerts", params=params, headers=session.headers), 200)
            found.update({a["id"]: a for a in page["items"]})
            cursor = page.get("next_cursor")
            if not cursor:
                return found

    async def wait_statuses(
        self, session: Session, alert_ids: Iterable[str], allowed: Iterable[str], what: str
    ) -> Dict[str, Dict[str, Any]]:
        wanted, allowed = set(alert_ids), set(allowed)

        async def probe() -> Optional[Dict[str, Dict[str, Any]]]:
            # One paginated listing per poll (not one request per alert) stays well inside the rate limit.
            listed = await self.alerts_by_id(session)
            missing = wanted - set(listed)
            if missing:
                raise SmokeFailure(f"alerts disappeared while waiting for {what}: {sorted(missing)[:5]}")
            current = {a: listed[a] for a in wanted}
            failed = [a for a, row in current.items() if row["status"] == "failed"]
            if failed:
                raise SmokeFailure(f"alerts failed while waiting for {what}: {failed}")
            return current if all(row["status"] in allowed for row in current.values()) else None

        result: Dict[str, Dict[str, Any]] = await eventually(probe, what, self.timeout, interval=1.0)
        return result

    async def wait_action(self, session: Session, action_id: str, allowed: Iterable[str]) -> Dict[str, Any]:
        allowed = set(allowed)

        async def probe() -> Optional[Dict[str, Any]]:
            row: Dict[str, Any] = expect_quiet(
                await self.client.get(f"{API}/actions/{action_id}", headers=session.headers), 200
            )
            return row if row["status"] in allowed else None

        result: Dict[str, Any] = await eventually(probe, f"action {action_id} to run", self.timeout)
        return result

    # -- phases ----------------------------------------------------------------

    async def wait_ready(self, ready: bool, within: float) -> None:
        want = 200 if ready else 503

        async def probe() -> Optional[Dict[str, Any]]:
            try:
                response = await self.client.get("/readyz")
            except httpx.HTTPError:
                return None
            return response.json() if response.status_code == want else None

        body = await eventually(probe, f"/readyz {want}", within, interval=1.0)
        check(True, f"/readyz answers {want} {json.dumps(body.get('checks', {}), sort_keys=True)}")

    async def flow(self) -> None:
        admin_email, admin_password = env("SMOKE_ADMIN_EMAIL"), env("SMOKE_ADMIN_PASSWORD")
        assert admin_email is not None and admin_password is not None
        expect(await self.client.get("/healthz"), 200, "GET /healthz")
        expect(await self.client.get("/readyz"), 200, "GET /readyz")
        expect(await self.client.get(f"{API}/alerts"), 401, "unauthenticated /alerts is refused")

        # Login and the refresh cookie.
        admin = await self.login(admin_email, admin_password)
        attrs = admin.cookie_attributes
        check(
            attrs["httponly"] and attrs["samesite"] == "strict" and attrs["path"] == f"{API}/auth",
            "refresh cookie is HttpOnly, SameSite=Strict, scoped to /api/v1/auth",
            {k: v for k, v in attrs.items() if k != "value"},
        )
        if os.environ.get("SMOKE_EXPECT_SECURE_COOKIE", "1") == "1":
            check(attrs["secure"], "refresh cookie is Secure")
        me = expect(await self.client.get(f"{API}/auth/me", headers=admin.headers), 200, "GET /auth/me")
        check(me["role"] == "admin" and me["kind"] == "user", "principal is an admin user", me["role"])
        tenant_a = me["tenant_id"]

        # API keys: ingest and read-only.
        created = expect(
            await self.client.post(
                f"{API}/api-keys",
                json={"name": f"smoke-ingest-{self.run}", "scopes": ["ingest"]},
                headers=admin.headers,
            ),
            201,
            "create an ingest API key",
        )
        ingest_headers = {"X-API-Key": created["key"]}
        check("key_hash" not in created and created["prefix"], "API key response carries no hash")
        listed = expect(await self.client.get(f"{API}/api-keys", headers=admin.headers), 200, "list API keys")
        check(all("key" not in k for k in listed), "listed API keys never include the secret")
        expect(
            await self.client.get(f"{API}/alerts", headers=ingest_headers), 403, "an ingest-only key cannot read alerts"
        )

        async with self.event_stream(admin.access_token) as events:
            # Canonical alerts through /ingest/alerts.
            canonical = load_fixture("canonical.json")["events"]
            for event in canonical:
                if "source_alert_id" in event:
                    event["source_alert_id"] = f"{event['source_alert_id']}-{self.run}"
            batch = canonical + [beacon_event(self.run, 1)]
            body = expect(
                await self.client.post(f"{API}/ingest/alerts", json={"alerts": batch}, headers=ingest_headers),
                202,
                f"POST /ingest/alerts ({len(batch)} canonical events)",
            )
            inserted = [i for i in body["items"] if i["status"] == "inserted"]
            check(
                body["inserted"] == len(inserted) >= 2 and body["enqueued"] == body["inserted"],
                "canonical alerts stored and queued",
                {k: body[k] for k in ("received", "inserted", "duplicates", "rejected", "enqueued")},
            )
            beacon_id = body["items"][-1]["alert_id"]
            again = expect(
                await self.client.post(f"{API}/ingest/alerts", json=[batch[-1]], headers=ingest_headers),
                202,
                "re-POST of the same event",
            )
            check(again["items"][0]["status"] == "duplicate" and again["enqueued"] == 0, "duplicates are not re-queued")

            # A webhook source with the vendor fixture's field map, then vendor-native payloads.
            webhook = load_fixture("webhook_generic.json")
            source_id = f"smoke-webhook-{self.run}"
            expect(
                await self.client.post(
                    f"{API}/sources",
                    json={
                        "id": source_id,
                        "type": "webhook",
                        "name": f"Smoke generic webhook {self.run}",
                        "config": webhook["config"],
                    },
                    headers=admin.headers,
                ),
                201,
                "create a webhook source",
            )
            vendor = webhook["events"]
            for event in vendor:
                with suppress(KeyError, TypeError):
                    event["alert"]["uuid"] = f"{event['alert']['uuid']}-{self.run}"
            pushed = expect(
                await self.client.post(f"{API}/ingest/webhook/{source_id}", json=vendor, headers=ingest_headers),
                202,
                f"POST /ingest/webhook/{{source}} ({len(vendor)} vendor events)",
            )
            check(
                pushed["inserted"] >= 1 and pushed["source_id"] == source_id,
                "vendor events normalized and stored",
                {k: pushed[k] for k in ("received", "inserted", "rejected")},
            )
            expect(
                await self.client.post(
                    f"{API}/ingest/webhook/no-such-source-{self.run}", json=vendor[0], headers=ingest_headers
                ),
                404,
                "an unknown webhook source is refused",
            )
            all_ids = [i["alert_id"] for i in inserted] + [
                i["alert_id"] for i in pushed["items"] if i["status"] == "inserted"
            ]

            # Every alert leaves the queue: closed, or waiting for a human.
            settled = await self.wait_statuses(admin, all_ids, SETTLED, "all ingested alerts to settle")
            summary = {s: sum(1 for r in settled.values() if r["status"] == s) for s in SETTLED}
            check(True, f"{len(all_ids)} alerts settled {json.dumps(summary, sort_keys=True)}")
            escalated = [a for a in all_ids if settled[a]["status"] == "waiting_human"]
            check(bool(escalated), f"{len(escalated)} alerts escalated to an analyst")
            target = beacon_id if beacon_id in escalated else escalated[0]
            timeline = expect(
                await self.client.get(f"{API}/alerts/{target}/events", headers=admin.headers), 200, "alert timeline"
            )
            check(len(timeline["items"]) >= 3, f"timeline has {len(timeline['items'])} events")

            # Work the queue as an analyst would until every alert is closed: decide open escalations
            # (the target and anything whose response was approved are true positives, the rest false
            # positives) and approve pending actions one at a time.
            malicious = {target}
            benign: Set[str] = set()
            pending: List[Dict[str, Any]] = []
            first_decision = True
            deadline = time.monotonic() + 2 * self.timeout
            while True:
                if time.monotonic() > deadline:
                    raise SmokeFailure("alerts did not close while working the review queue")
                settled = await self.wait_statuses(admin, all_ids, SETTLED, "alerts to settle")
                open_ids = {a for a in all_ids if settled[a]["status"] == "waiting_human"}
                if open_ids:
                    page = expect_quiet(
                        await self.client.get(
                            f"{API}/escalations",
                            params={"status": ["open", "claimed"], "limit": 200},
                            headers=admin.headers,
                        ),
                        200,
                    )
                    ours = [e for e in page["items"] if {e["alert_id"], *e["related_alert_ids"]} & open_ids]
                    if not ours:
                        # Decided a moment ago: the alert shows waiting_human until the worker takes the resume.
                        await asyncio.sleep(1.0)
                        continue
                    ok(f"{len(ours)} open escalation(s) for {len(open_ids)} waiting alert(s)")
                    for esc in ours:
                        members = {esc["alert_id"], *esc["related_alert_ids"]}
                        decision = "true_positive" if members & malicious else "false_positive"
                        claimed = expect(
                            await self.client.post(
                                f"{API}/escalations/{esc['id']}/claim",
                                json={"version": esc["version"]},
                                headers=admin.headers,
                            ),
                            200,
                            f"claim {esc['level']} escalation ({esc['reason'][:60]})",
                        )
                        check(
                            claimed["status"] == "claimed" and claimed["version"] > esc["version"],
                            "claim bumps the version",
                        )
                        if first_decision:
                            stale = await self.client.post(
                                f"{API}/escalations/{esc['id']}/decision",
                                json={"decision": decision, "version": esc["version"]},
                                headers=admin.headers,
                            )
                            expect_status(stale, 409, "a decision with a stale version")
                            first_decision = False
                        decided = expect(
                            await self.client.post(
                                f"{API}/escalations/{esc['id']}/decision",
                                json={
                                    "decision": decision,
                                    "version": claimed["version"],
                                    "notes": f"smoke: {decision}",
                                },
                                headers=admin.headers,
                            ),
                            200,
                            f"decide {decision}",
                        )
                        check(
                            decided["resumes_failed"] == 0 and esc["alert_id"] in decided["resumed_alert_ids"],
                            f"{len(decided['resumed_alert_ids'])} run(s) resumed",
                        )
                        if decision == "false_positive":
                            benign.update(a for a in decided["resumed_alert_ids"] if a in all_ids)
                    continue
                waiting = [a for a in all_ids if settled[a]["status"] == "waiting_approval"]
                if not waiting:
                    break
                progressed = False
                for alert_id in waiting:
                    page = expect_quiet(
                        await self.client.get(f"{API}/actions", params={"alert_id": alert_id}, headers=admin.headers),
                        200,
                    )
                    todo = [a for a in page["items"] if a["status"] == "awaiting_approval"]
                    if not todo:
                        continue  # approved a moment ago; the worker has not resumed the run yet
                    progressed = True
                    ok(f"{len(todo)} actions await approval")
                    malicious.add(alert_id)
                    for action in todo:
                        approved = expect(
                            await self.client.post(
                                f"{API}/actions/{action['id']}/approve", json={}, headers=admin.headers
                            ),
                            200,
                            f"approve {action['action_type']} ({action['risk_level']} risk)",
                        )
                        check(
                            approved["action"]["status"] in ("approved",) + ACTION_DONE,
                            "approval recorded",
                            approved["action"]["status"],
                        )
                        # One approval at a time, as an analyst works: wait until the worker has executed it
                        # and the run has settled again before approving the next action.
                        await self.wait_action(admin, action["id"], ACTION_DONE)
                        await self.wait_statuses(admin, [alert_id], SETTLED, "the run to settle after approval")
                        pending.append(action)
                if not progressed:
                    await asyncio.sleep(1.0)
            closed = await self.wait_statuses(admin, all_ids, ("closed",), "every alert to close")
            check(bool(pending), f"{len(pending)} actions were approved in total")
            dispositions = {a: closed[a]["disposition"] for a in all_ids}
            check(dispositions[target] == "malicious", "the true positive closed as malicious", dispositions[target])
            check(
                all(dispositions[a] == "benign" for a in benign - malicious),
                "false positives closed as benign",
                {a: dispositions[a] for a in benign},
            )
            check(all(closed[a]["closed_at"] for a in all_ids), f"all {len(all_ids)} alerts closed")
            ledger = []
            for alert_id in {a["alert_id"] for a in pending}:
                ledger.extend(
                    expect_quiet(
                        await self.client.get(f"{API}/actions", params={"alert_id": alert_id}, headers=admin.headers),
                        200,
                    )["items"]
                )
            outcome = {str(a["id"]): a["status"] for a in ledger}
            check(
                all(outcome[str(a["id"])] == "dry_run" for a in pending),
                "approved actions ran as dry-run",
                sorted(set(outcome.values())),
            )

            # The WebSocket saw the whole lifecycle.
            await eventually(
                lambda: asyncio.sleep(0, result=any(e.get("type") == "action.updated" for e in events)),
                "action events on the WebSocket",
                15,
            )
            types_seen = {
                e.get("type") for e in events if e.get("alert_id") in all_ids or e.get("alert_id") == beacon_id
            }
            check(
                {"alert.created", "alert.updated", "escalation.created", "action.updated"} <= types_seen,
                f"WebSocket delivered {len(events)} events",
                sorted(t for t in types_seen if t),
            )
            check(
                all(e.get("tenant_id") == tenant_a for e in events if "tenant_id" in e),
                "every WebSocket event belongs to the tenant",
            )

        # Dashboard, LLM usage, audit.
        dash = expect(
            await self.client.get(f"{API}/dashboard/summary", headers=admin.headers), 200, "dashboard summary"
        )
        check(
            dash["alerts_total"] >= len(all_ids) and dash["by_status"].get("closed", 0) >= 1,
            "dashboard counts the alerts",
            {k: dash[k] for k in ("alerts_total", "by_status", "open_escalations")},
        )

        async def metered() -> Optional[Dict[str, Any]]:
            # Workers flush usage in batches (every 30 s by default).
            body: Dict[str, Any] = expect_quiet(await self.client.get(f"{API}/usage/llm", headers=admin.headers), 200)
            return body if body["total_calls"] > 0 and body["days"] else None

        usage = await eventually(metered, "LLM usage to be recorded", 90, interval=2.0)
        check(
            True,
            "LLM calls are metered (/usage/llm) "
            + json.dumps({k: usage[k] for k in ("total_calls", "total_input_tokens", "total_output_tokens")}),
        )
        audit = expect(
            await self.client.get(f"{API}/audit", params={"limit": 200}, headers=admin.headers), 200, "audit log"
        )
        actions_seen = {e["action"] for e in audit["items"]}
        check(
            {
                "auth.login",
                "api_key.created",
                "source.created",
                "escalation.claimed",
                "escalation.decided",
                "response_action.approved",
                "response_action.dry_run",
            }
            <= actions_seen,
            "audit log records key, source, review and approval",
            sorted(actions_seen),
        )
        chain = expect(await self.client.get(f"{API}/audit/verify", headers=admin.headers), 200, "audit chain check")
        check(chain["ok"] is True, "audit hash chain verifies", chain)

        # Metrics: token required, never under /api/v1.
        metrics_token = env("SMOKE_METRICS_TOKEN", required=False)
        if metrics_token:
            expect_status(await self.client.get("/metrics"), 401, "/metrics without the token")
            expect_status(
                await self.client.get("/metrics", headers={"Authorization": "Bearer wrong-token"}),
                401,
                "/metrics with a wrong token",
            )
            metrics = await self.client.get("/metrics", headers={"Authorization": f"Bearer {metrics_token}"})
            expect_status(metrics, 200, "/metrics with the token")
            check("lgsotf_http_requests_total" in metrics.text, "Prometheus exposition includes HTTP metrics")
            check('tenant_id="' not in metrics.text and tenant_a not in metrics.text, "metrics carry no tenant ids")
        expect_status(await self.client.get(f"{API}/metrics"), 404, "/api/v1/metrics is not served")

        await self.isolation(admin, tenant_a, beacon_id, ledger)
        await self.session_flow(admin_email, admin_password)

    async def isolation(self, admin: Session, tenant_a: str, a_alert: str, a_actions: List[Dict[str, Any]]) -> None:
        tenant_b = env("SMOKE_TENANT_B", required=False)
        email, password = env("SMOKE_TENANT_B_EMAIL", required=False), env("SMOKE_TENANT_B_PASSWORD", required=False)
        if not (tenant_b and email and password):
            print("skip  tenant isolation (SMOKE_TENANT_B* not set)", flush=True)
            return
        other = await self.login(email, password, tenant_b)
        me = expect(await self.client.get(f"{API}/auth/me", headers=other.headers), 200, "tenant B /auth/me")
        check(me["tenant_id"] == tenant_b and not me["is_platform_admin"], "tenant B admin is not a platform admin")
        b_alerts = await self.alerts_by_id(other)
        check(
            a_alert not in b_alerts and all(a["tenant_id"] == tenant_b for a in b_alerts.values()),
            f"tenant B lists none of tenant A's alerts ({len(b_alerts)} own)",
        )
        expect_status(
            await self.client.get(f"{API}/alerts/{a_alert}", headers=other.headers),
            404,
            "tenant A alert by id from tenant B",
        )
        expect_status(
            await self.client.get(f"{API}/alerts/{a_alert}/events", headers=other.headers),
            404,
            "tenant A timeline from tenant B",
        )
        if a_actions:
            expect_status(
                await self.client.get(f"{API}/actions/{a_actions[0]['id']}", headers=other.headers),
                404,
                "tenant A action by id from tenant B",
            )
            expect_status(
                await self.client.post(f"{API}/actions/{a_actions[0]['id']}/approve", json={}, headers=other.headers),
                404,
                "approving tenant A's action from tenant B",
            )
        esc = await self.client.get(f"{API}/escalations", headers=other.headers)
        check(
            all(e["tenant_id"] == tenant_b for e in expect_quiet(esc, 200)["items"]), "tenant B escalations are its own"
        )
        expect_status(
            await self.client.get(f"{API}/alerts", headers={**other.headers, "X-Tenant-ID": tenant_a}),
            403,
            "X-Tenant-ID from a non-platform admin",
        )
        audit = expect_quiet(await self.client.get(f"{API}/audit", params={"limit": 200}, headers=other.headers), 200)
        check(all(e["tenant_id"] == tenant_b for e in audit["items"]), "tenant B audit log is its own")

        # Tenant B's own ingest key writes into tenant B only.
        key = expect_quiet(
            await self.client.post(
                f"{API}/api-keys", json={"name": "smoke-b", "scopes": ["ingest"]}, headers=other.headers
            ),
            201,
        )
        body = expect_quiet(
            await self.client.post(
                f"{API}/ingest/alerts",
                json=[{"source_alert_id": f"b-{self.run}", "title": "Tenant B scheduled backup", "severity": "low"}],
                headers={"X-API-Key": key["key"]},
            ),
            202,
        )
        b_id = body["items"][0]["alert_id"]
        expect_status(
            await self.client.get(f"{API}/alerts/{b_id}", headers=other.headers), 200, "tenant B reads its alert"
        )
        expect_status(
            await self.client.get(f"{API}/alerts/{b_id}", headers=admin.headers),
            404,
            "tenant A cannot read tenant B's alert",
        )

        # The platform admin may look in with X-Tenant-ID; the access lands in tenant B's audit log.
        seen = await self.client.get(f"{API}/alerts/{b_id}", headers={**admin.headers, "X-Tenant-ID": tenant_b})
        expect_status(seen, 200, "platform admin reads tenant B with X-Tenant-ID")
        audit = expect_quiet(
            await self.client.get(
                f"{API}/audit", params={"action": "platform_admin.tenant_access"}, headers=other.headers
            ),
            200,
        )
        check(bool(audit["items"]), "the cross-tenant access is in tenant B's audit log")

    async def session_flow(self, email: str, password: str) -> None:
        session = await self.login(email, password)
        rotated = await self.refresh(session.refresh_token)
        body = expect(rotated, 200, "POST /auth/refresh with the cookie")
        new_cookie = parse_refresh_cookie(rotated)
        check(
            new_cookie["value"] != session.refresh_token and body["access_token"] != session.access_token,
            "refresh rotates the cookie and issues a new access token",
        )
        expect_status(
            await self.client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}),
            200,
            "the refreshed access token works",
        )
        reuse = await self.refresh(session.refresh_token)
        expect_status(reuse, 401, "re-using the rotated refresh cookie")
        check(
            any(
                REFRESH_COOKIE in h and ("max-age=0" in h.lower() or "expires=" in h.lower())
                for h in reuse.headers.get_list("set-cookie")
            ),
            "the refused refresh clears the cookie",
        )
        # Reuse of a rotated token revokes the whole family, so sign in again for the logout check.
        session = await self.login(email, password)
        response = await self.client.post(
            f"{API}/auth/logout",
            headers={"Cookie": f"{REFRESH_COOKIE}={session.refresh_token}", **session.headers},
        )
        expect_status(response, 204, "POST /auth/logout")
        expect_status(await self.refresh(session.refresh_token), 401, "refresh after logout")
        expect_status(
            await self.client.get(f"{API}/auth/me", headers=session.headers),
            401,
            "the access token presented at logout is revoked",
        )

    async def burst(self, count: int, state: Path) -> None:
        email, password = env("SMOKE_ADMIN_EMAIL"), env("SMOKE_ADMIN_PASSWORD")
        assert email is not None and password is not None
        admin = await self.login(email, password)
        key = expect_quiet(
            await self.client.post(
                f"{API}/api-keys", json={"name": f"smoke-burst-{self.run}", "scopes": ["ingest"]}, headers=admin.headers
            ),
            201,
        )
        batch = [burst_event(self.run, n) for n in range(count)] + [beacon_event(self.run, 2)]
        body = expect(
            await self.client.post(f"{API}/ingest/alerts", json=batch, headers={"X-API-Key": key["key"]}),
            202,
            f"burst of {len(batch)} alerts",
        )
        ids = [i["alert_id"] for i in body["items"] if i["status"] == "inserted"]
        check(len(ids) == len(batch), f"{len(ids)} alerts queued")
        save_state(state, ids)

    async def settled(self, state: Path) -> None:
        email, password = env("SMOKE_ADMIN_EMAIL"), env("SMOKE_ADMIN_PASSWORD")
        assert email is not None and password is not None
        ids = load_state(state)
        admin = await self.login(email, password)
        settled = await self.wait_statuses(admin, ids, SETTLED, f"{len(ids)} burst alerts to settle")
        counts: Dict[str, int] = {}
        for row in settled.values():
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        check(
            len(settled) == len(ids), f"all {len(ids)} alerts settled, none lost {json.dumps(counts, sort_keys=True)}"
        )

    @asynccontextmanager
    async def event_stream(self, token: str) -> AsyncIterator[List[Dict[str, Any]]]:
        from websockets.asyncio.client import connect

        events: List[Dict[str, Any]] = []
        async with connect(ws_url(self.ws_base_url or self.base_url, token), open_timeout=10) as ws:
            hello = json.loads(await asyncio.wait_for(ws.recv(), 10))
            check(hello.get("type") == "hello", "WebSocket /api/v1/ws connected", hello.get("type"))

            async def reader() -> None:
                async for message in ws:
                    event = json.loads(message)
                    if event.get("type") != "ping":
                        events.append(event)

            task = asyncio.create_task(reader())
            try:
                yield events
            finally:
                task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await task


def save_state(path: Path, alert_ids: List[str]) -> None:
    path.write_text(json.dumps({"alert_ids": alert_ids}))


def load_state(path: Path) -> List[str]:
    ids: List[str] = json.loads(path.read_text())["alert_ids"]
    return ids


def expect_quiet(response: httpx.Response, status: int) -> Any:
    if response.status_code != status:
        raise SmokeFailure(
            f"expected HTTP {status}, got {response.status_code} {response.request.method} "
            f"{response.request.url.path}: {response.text[:400]}"
        )
    return response.json()


def expect_status(response: httpx.Response, status: int, message: str) -> None:
    check(
        response.status_code == status, f"{message} -> {status}", f"got {response.status_code}: {response.text[:200]}"
    )


async def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("phase", choices=["flow", "burst", "settled", "ready", "unready"])
    parser.add_argument("--base-url", default=os.environ.get("SMOKE_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--state", type=Path, default=Path(os.environ.get("SMOKE_STATE", "smoke-state.json")))
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--timeout", type=float, default=180.0)
    args = parser.parse_args(argv)

    async with httpx.AsyncClient(base_url=args.base_url, timeout=30.0, cookies=no_cookie_jar()) as client:
        smoke = Smoke(client, args.base_url, timeout=args.timeout)
        started = time.monotonic()
        try:
            if args.phase == "flow":
                await smoke.flow()
            elif args.phase == "burst":
                await smoke.burst(args.count, args.state)
            elif args.phase == "settled":
                await smoke.settled(args.state)
            else:
                await smoke.wait_ready(args.phase == "ready", args.timeout)
        except SmokeFailure as exc:
            print(f"FAIL  {exc}", flush=True)
            return 1
        print(f"done  {args.phase} in {time.monotonic() - started:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
