"""``lg-sotf`` command line: process roles (api, worker, scheduler, migrate) and operations commands."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Coroutine, List, Optional, TypeVar

import click

from lg_sotf import __version__
from lg_sotf.settings import Settings, get_settings

T = TypeVar("T")

DEFAULT_METRICS_PORT = 9100


def _prepare() -> Settings:
    """Common startup for every command: logging, tracing, production safety checks."""
    from lg_sotf.observability.logging import configure_logging
    from lg_sotf.observability.tracing import setup_tracing

    settings = get_settings()
    configure_logging(settings, stream=sys.stderr)
    setup_tracing(settings)
    try:
        settings.assert_safe()
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    return settings


def _run(coro: Coroutine[Any, Any, T]) -> T:
    from lg_sotf.db.errors import DatabaseUnavailable
    from lg_sotf.runtime.ops import OperationError
    from lg_sotf.security.hashing import SecurityConfigError

    try:
        return asyncio.run(coro)
    except (OperationError, SecurityConfigError) as exc:
        raise click.ClickException(str(exc)) from exc
    except DatabaseUnavailable as exc:
        raise click.ClickException(f"database unavailable: {exc}") from exc


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """LG-SOTF: multi-tenant AI triage for security alerts.

    Configuration comes from LG_SOTF_* environment variables and the optional
    YAML file named by LG_SOTF_CONFIG_FILE.
    """


@cli.command()
def version() -> None:
    """Print the version."""
    click.echo(__version__)


@cli.command()
@click.option("--host", default=None, help="Bind address (default: api.host).")
@click.option("--port", type=int, default=None, help="Port (default: api.port).")
def api(host: Optional[str], port: Optional[int]) -> None:
    """Run the REST/WebSocket API server."""
    import uvicorn

    settings = _prepare()
    uvicorn.run(
        "lg_sotf.api.app:create_app",
        factory=True,
        host=host or settings.api.host,
        port=port or settings.api.port,
        proxy_headers=True,
        forwarded_allow_ips=settings.api.forwarded_allow_ips,
        log_config=None,
        access_log=False,
        server_header=False,
    )


_metrics_host = click.option(
    "--metrics-host",
    default="0.0.0.0",  # noqa: S104 - probes and Prometheus reach the pod IP
    show_default=True,
    help="Bind address of /metrics, /healthz, /readyz.",
)
_metrics_port = click.option(
    "--metrics-port", type=int, default=DEFAULT_METRICS_PORT, show_default=True, help="Port of the health server."
)


@cli.command()
@_metrics_host
@_metrics_port
def worker(metrics_host: str, metrics_port: int) -> None:
    """Consume the alert queue and run workflows."""
    from lg_sotf.runtime.worker import run_worker

    settings = _prepare()
    _run(run_worker(settings, metrics_host=metrics_host, metrics_port=metrics_port))


@cli.command()
@_metrics_host
@_metrics_port
def scheduler(metrics_host: str, metrics_port: int) -> None:
    """Run periodic jobs (source polling, sweeps, maintenance) while holding the leader lock."""
    from lg_sotf.runtime.scheduler import run_scheduler

    settings = _prepare()
    _run(run_scheduler(settings, metrics_host=metrics_host, metrics_port=metrics_port))


@cli.command()
def migrate() -> None:
    """Upgrade the schema, set up checkpoints, grant runtime privileges and bootstrap the tenant/admin."""
    from lg_sotf.runtime.ops import migrate as run_migrate

    settings = _prepare()
    report = _run(run_migrate(settings))
    click.echo(f"schema: up to date; tenant: {report.tenant_id} ({'created' if report.tenant_created else 'exists'})")
    if report.runtime_role_granted:
        click.echo(f"runtime role: privileges granted to {report.runtime_role_granted}")
    if report.admin_created:
        click.echo(f"bootstrap admin created: {report.admin_created}")


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            raise click.ClickException("no password on stdin")
        return password
    value: str = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    return value


@cli.command("create-admin")
@click.option("--tenant", "tenant_id", required=True, help="Tenant id.")
@click.option("--email", required=True, help="Login email.")
@click.option(
    "--role", type=click.Choice(["admin", "analyst", "viewer"]), default="admin", show_default=True, help="Role."
)
@click.option("--password-stdin", is_flag=True, help="Read the password from the first line of stdin.")
@click.option("--platform-admin", is_flag=True, help="Allow acting on other tenants.")
def create_admin(tenant_id: str, email: str, role: str, password_stdin: bool, platform_admin: bool) -> None:
    """Create a local user (argon2id password)."""
    from lg_sotf.runtime.ops import create_user

    settings = _prepare()
    password = _read_password(password_stdin)
    user = _run(
        create_user(
            settings, tenant_id=tenant_id, email=email, role=role, password=password, platform_admin=platform_admin
        )
    )
    click.echo(f"created {user.role} {user.email} in tenant {user.tenant_id} (id {user.id})")


@cli.command()
@click.option("--tenant", "tenant_id", required=True, help="Tenant id.")
@click.option("--alert", "alert_id", required=True, help="Alert id.")
@click.option("--force", is_flag=True, help="Reprocess even if the run already finished.")
def enqueue(tenant_id: str, alert_id: str, force: bool) -> None:
    """Queue an alert for processing (operations)."""
    from lg_sotf.runtime.ops import enqueue_alert

    settings = _prepare()
    entry_id = _run(enqueue_alert(settings, tenant_id=tenant_id, alert_id=alert_id, force=force))
    click.echo(f"enqueued {entry_id}")


@cli.group()
def dlq() -> None:
    """Inspect and requeue dead-lettered queue entries."""


@dlq.command("list")
@click.option("--limit", type=click.IntRange(1, 1000), default=50, show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Print JSON lines.")
def dlq_list(limit: int, as_json: bool) -> None:
    """List dead letters, oldest first."""
    from lg_sotf.runtime.ops import dlq_list as list_letters

    settings = _prepare()
    letters = _run(list_letters(settings, limit=limit))
    for letter in letters:
        if as_json:
            click.echo(
                json.dumps(
                    {
                        "entry_id": letter.entry_id,
                        "tenant_id": letter.tenant_id,
                        "alert_id": letter.alert_id,
                        "kind": letter.kind,
                        "deliveries": letter.deliveries,
                        "failed_at": letter.failed_at,
                        "reason": letter.reason,
                    }
                )
            )
        else:
            click.echo(
                f"{letter.entry_id}  {letter.tenant_id}  {letter.alert_id}  {letter.kind}  "
                f"{letter.failed_at}  {letter.reason}"
            )
    if not letters and not as_json:
        click.echo("dead-letter queue is empty")


@dlq.command("requeue")
@click.argument("entry_ids", nargs=-1, required=True)
def dlq_requeue(entry_ids: List[str]) -> None:
    """Move dead letters back to the work queue and reset their runs."""
    from lg_sotf.runtime.ops import dlq_requeue as requeue

    settings = _prepare()
    results = _run(requeue(settings, list(entry_ids)))
    for result in results:
        if result.ok:
            click.echo(f"{result.entry_id} -> {result.new_entry_id}")
        else:
            click.echo(f"{result.entry_id} failed: {result.error}", err=True)
    failed = sum(1 for r in results if not r.ok)
    if failed:
        raise click.ClickException(f"{failed} of {len(results)} dead letters were not requeued")


def main() -> None:
    cli(prog_name="lg-sotf")


if __name__ == "__main__":
    main()
