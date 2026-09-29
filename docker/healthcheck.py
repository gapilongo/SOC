"""Container health probe for the lg-sotf image (standard library only).

Finds the process role from PID 1's command line (``dumb-init -- lg-sotf
<role> ...``) and requests that role's liveness endpoint:

* ``api``: ``http://127.0.0.1:<--port | LG_SOTF_API__PORT | 8000>/healthz``
* ``worker`` / ``scheduler``: ``http://127.0.0.1:<--metrics-port | 9100>/healthz``
* anything else (``migrate``, ``version``, ops commands): healthy; one-shot
  commands report through their exit code instead.

``HEALTHCHECK_URL`` overrides the detection. Exit status 0 means healthy.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from typing import List, Optional

TIMEOUT_S = 4.0
SERVER_ROLES = {"api": ("--port", "LG_SOTF_API__PORT", 8000), "worker": ("--metrics-port", None, 9100)}
SERVER_ROLES["scheduler"] = SERVER_ROLES["worker"]


def pid1_argv() -> List[str]:
    try:
        with open("/proc/1/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def option(argv: List[str], name: str) -> Optional[str]:
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None


def role_url(argv: List[str]) -> Optional[str]:
    """URL of the role's /healthz, or ``None`` when the command serves no health endpoint."""
    try:
        idx = next(i for i, a in enumerate(argv) if os.path.basename(a) == "lg-sotf")
    except StopIteration:
        return None
    rest = argv[idx + 1 :]
    role = next((a for a in rest if not a.startswith("-")), None)
    if role not in SERVER_ROLES:
        return None
    flag, env_name, default = SERVER_ROLES[role]
    port = option(rest, flag) or (os.environ.get(env_name) if env_name else None) or str(default)
    return f"http://127.0.0.1:{int(port)}/healthz"


def main() -> int:
    url = os.environ.get("HEALTHCHECK_URL") or role_url(pid1_argv())
    if url is None:
        return 0
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_S) as resp:  # noqa: S310 - fixed local http URL
            return 0 if resp.status == 200 else 1
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"unhealthy: {url}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
