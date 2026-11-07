"""The Wazuh 4.14 lab: a Wazuh indexer seeded with alerts (docker/docker-compose.wazuh-test.yml).

:class:`WazuhLab` is the lab's admin client. It installs the ``wazuh``
index template that Wazuh publishes for 4.14 (the one Filebeat installs on a
real manager, fetched at a pinned tag and checked against its SHA-256; it is
GPLv2, so it is not vendored here), bulk-loads alert documents, and creates
the least-privilege reader users the contract tests connect with.

Alerts are routed to ``wazuh-alerts-4.x-<YYYY.MM.DD>`` by their
``timestamp``, as Filebeat does, unless an index is given. Alert files are
either ``{"events": [...]}`` JSON (like ``alerts_4_14.json``) or the
manager's own ``alerts.json`` (one alert per line), so alerts recorded on a
real Wazuh lab can be loaded unchanged::

    python -m tests.fixtures.wazuh_lab seed                 # template + the sample alerts
    python -m tests.fixtures.wazuh_lab load my-alerts.json  # more alerts

The admin client talks to the lab only (the image's demo ``admin`` user, the
demo CA when given, no hostname check: the demo certificate names
``demo.indexer``). Never point it at a real cluster.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import httpx

WAZUH_VERSION = "4.14.8"
TEMPLATE_NAME = "wazuh"
TEMPLATE_URL = (
    f"https://raw.githubusercontent.com/wazuh/wazuh/v{WAZUH_VERSION}/extensions/elasticsearch/7.x/wazuh-template.json"
)
TEMPLATE_SHA256 = "b2d182f49cc68957849e77fd2d79528fd2273ebaec1106c9661c9e320577a089"
INDEX_PREFIX = "wazuh-alerts-4.x-"
LAB_ADMIN = ("admin", "admin")  # the indexer image's demo admin; the lab is never reachable off the host
DEMO_HOSTNAME = "demo.indexer"  # the only name in the image's demo certificate
DEFAULT_URL = "https://127.0.0.1:59200"
SAMPLE_ALERTS = Path(__file__).parent / "alerts_4_14.json"
READ_ACTIONS = ("read", "indices:data/read/search*", "indices:admin/mappings/get")


class LabError(RuntimeError):
    pass


def read_alerts(path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Alerts from ``{"events": [...]}`` JSON or from an ``alerts.json`` file (one alert per line)."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        return list(data["events"])
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise LabError(f"{path}: expected alert objects")


def daily_index(alert: Dict[str, Any]) -> str:
    """``wazuh-alerts-4.x-YYYY.MM.DD`` from the alert's ``timestamp`` (UTC), as Filebeat names it."""
    raw = alert.get("timestamp")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            when = datetime.strptime(str(raw), fmt)
        except ValueError:
            continue
        return f"{INDEX_PREFIX}{when.astimezone(UTC):%Y.%m.%d}"
    raise LabError("an alert without a parseable timestamp needs an explicit index")


def lab_tls(ca_file: Optional[str]) -> Union[ssl.SSLContext, bool]:
    if not ca_file:
        return False
    context = ssl.create_default_context(cafile=ca_file)
    context.check_hostname = False
    return context


def fetch_template() -> bytes:
    body = httpx.get(TEMPLATE_URL, timeout=30, follow_redirects=True).raise_for_status().content
    digest = hashlib.sha256(body).hexdigest()
    if digest != TEMPLATE_SHA256:
        raise LabError(f"wazuh-template.json for {WAZUH_VERSION} has SHA-256 {digest}, expected {TEMPLATE_SHA256}")
    return body


class WazuhLab:
    def __init__(self, url: str = DEFAULT_URL, *, ca_file: Optional[str] = None, timeout: float = 30.0):
        self.http = httpx.Client(base_url=url, auth=LAB_ADMIN, verify=lab_tls(ca_file), timeout=timeout)

    def __enter__(self) -> WazuhLab:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self.http.close()

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self.http.request(method, path, **kwargs)
        if resp.status_code >= 300:
            raise LabError(f"{method} {path}: HTTP {resp.status_code} {resp.text[:500]}")
        return resp.json() if resp.content else None

    def wait_ready(self, timeout_s: float = 180.0) -> None:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                self._call("GET", "/_cluster/health", params={"wait_for_status": "yellow", "timeout": "5s"})
                return
            except (httpx.HTTPError, LabError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)

    # -- template and alerts --------------------------------------------------

    def install_template(self, template: Optional[bytes] = None) -> None:
        body = template if template is not None else fetch_template()
        self._call("PUT", f"/_template/{TEMPLATE_NAME}", content=body, headers={"Content-Type": "application/json"})

    def has_template(self) -> bool:
        return self.http.get(f"/_template/{TEMPLATE_NAME}").status_code == 200

    def load(self, alerts: Iterable[Dict[str, Any]], index: Optional[str] = None) -> Tuple[int, List[str]]:
        """Bulk-index ``alerts`` (refreshed before returning); returns (indexed, rejection reasons)."""
        lines: List[str] = []
        for alert in alerts:
            meta: Dict[str, Any] = {"_index": index or daily_index(alert)}
            lines += [json.dumps({"index": meta}), json.dumps(alert)]
        if not lines:
            return 0, []
        body = self._call(
            "POST", "/_bulk", params={"refresh": "true"}, content="\n".join(lines) + "\n",
            headers={"Content-Type": "application/x-ndjson"},
        )
        rejected = [
            str(item["index"]["error"].get("type")) for item in body["items"] if item["index"].get("error")
        ]
        return len(body["items"]) - len(rejected), rejected

    def delete_index(self, pattern: str) -> None:
        self.http.delete(f"/{pattern}", params={"ignore_unavailable": "true", "allow_no_indices": "true"})

    # -- users ------------------------------------------------------------------

    def put_reader(self, username: str, password: str, patterns: Sequence[str] = ("wazuh-alerts-*",)) -> None:
        """A user that may only search the alert indices (what the connector's docs ask an MSSP for)."""
        role = f"{username}-role"
        self._call("PUT", f"/_plugins/_security/api/roles/{role}", json={
            "cluster_permissions": ["cluster_composite_ops_ro"],
            "index_permissions": [{"index_patterns": list(patterns), "allowed_actions": list(READ_ACTIONS)}],
        })
        self.put_user(username, password)
        self._call("PUT", f"/_plugins/_security/api/rolesmapping/{role}", json={"users": [username]})

    def put_user(self, username: str, password: str) -> None:
        """A user with no roles at all."""
        self._call("PUT", f"/_plugins/_security/api/internalusers/{username}", json={"password": password})

    def delete_user(self, username: str) -> None:
        for path in (f"rolesmapping/{username}-role", f"roles/{username}-role", f"internalusers/{username}"):
            self.http.delete(f"/_plugins/_security/api/{path}")
