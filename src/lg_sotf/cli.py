"""``lg-sotf`` command line: process roles (api, worker, scheduler, migrate) and operations commands."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Coroutine, List, Optional, TypeVar

import click

from lg_sotf import __version__
from lg_sotf.models.vocabulary import ROLES
from lg_sotf.settings import Settings, get_settings

T = TypeVar("T")

DEFAULT_METRICS_PORT = 9100


def _prepare() -> Settings:
    """Common startup for every command: logging and production safety checks."""
    from lg_sotf.observability.logging import configure_logging

    settings = get_settings()
    configure_logging(settings, stream=sys.stderr)
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
@click.option("--role", type=click.Choice(ROLES), default="admin", show_default=True, help="Role.")
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


@cli.command("reset-mfa")
@click.option("--tenant", "tenant_id", required=True, help="Tenant id.")
@click.option("--email", required=True, help="The user's login email.")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
def reset_mfa(tenant_id: str, email: str, yes: bool) -> None:
    """Remove a user's MFA (lost device) and sign them out; audited. They enroll again at next sign-in."""
    from lg_sotf.runtime.ops import reset_mfa as run_reset_mfa

    settings = _prepare()
    if not yes:
        click.confirm(f"Remove MFA for {email} in tenant {tenant_id} and end their sessions?", abort=True)
    report = _run(run_reset_mfa(settings, tenant_id=tenant_id, email=email))
    state = "removed" if report.was_enabled else "was not enabled; pending enrollment cleared"
    click.echo(f"MFA {state} for {report.email} (id {report.user_id}); {report.revoked_sessions} session(s) revoked")


@cli.command("create-tenant")
@click.option("--id", "tenant_id", required=True, help="Tenant id: 2-63 of a-z, 0-9, '-', '_'.")
@click.option("--name", required=True, help="Display name.")
@click.option("--admin-email", default=None, help="Also create this tenant's first admin.")
@click.option("--password-stdin", is_flag=True, help="Read the admin password from the first line of stdin.")
def create_tenant(tenant_id: str, name: str, admin_email: Optional[str], password_stdin: bool) -> None:
    """Create a tenant (schema-owner connection), optionally with its first admin."""
    from lg_sotf.runtime.ops import create_tenant as run_create_tenant

    if password_stdin and admin_email is None:
        raise click.UsageError("--password-stdin needs --admin-email")
    settings = _prepare()
    password = _read_password(password_stdin) if admin_email is not None else None
    report = _run(
        run_create_tenant(
            settings, tenant_id=tenant_id, name=name, admin_email=admin_email, admin_password=password
        )
    )
    click.echo(f"created tenant {report.tenant_id} ({report.name})")
    if report.admin is not None:
        click.echo(f"created admin {report.admin.email} in tenant {report.tenant_id} (id {report.admin.id})")


@cli.command()
@click.option("--tenant", "tenant_id", required=True, help="Tenant id.")
@click.option("--alert", "alert_id", required=True, help="Alert id.")
@click.option("--force", is_flag=True, help="Reprocess even if the run already finished.")
@click.option(
    "--resume",
    "resume",
    is_flag=True,
    help="Re-send the decision or approval a waiting run missed, rebuilt from the database.",
)
def enqueue(tenant_id: str, alert_id: str, force: bool, resume: bool) -> None:
    """Queue an alert for processing, or re-send a lost resume (operations)."""
    from lg_sotf.runtime.ops import enqueue_alert, enqueue_lost_resume

    settings = _prepare()
    if resume:
        if force:
            raise click.UsageError("--resume and --force cannot be combined")
        entry_id = _run(enqueue_lost_resume(settings, tenant_id=tenant_id, alert_id=alert_id))
    else:
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


def _quiet_eval_logging(settings: Settings) -> None:
    """Per-node INFO logs drown the eval progress lines; keep warnings unless a level was configured."""
    if "log_level" in settings.observability.model_fields_set:
        return
    from lg_sotf.observability.logging import configure_logging

    quiet = settings.model_copy(update={"observability": settings.observability.model_copy(update={"log_level": "WARNING"})})
    configure_logging(quiet, stream=sys.stderr)


@cli.command("eval")
@click.option(
    "--dataset",
    default=None,
    type=click.Path(dir_okay=False),
    help="Labelled JSONL dataset (required unless --from-history).",
)
@click.option(
    "--from-history",
    "from_history",
    is_flag=True,
    help="Backtest: replay the --tenant's analyst-decided alerts through the current pipeline, read-only.",
)
@click.option(
    "--days",
    type=click.IntRange(1, 366),
    default=30,
    show_default=True,
    help="With --from-history: alerts decided in the last N days.",
)
@click.option(
    "--report",
    default="eval-report.json",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="JSON report path (Markdown is written next to it unless --markdown is given).",
)
@click.option("--markdown", default=None, type=click.Path(dir_okay=False), help="Markdown report path.")
@click.option("--thresholds", default=None, type=click.Path(dir_okay=False), help="Gate thresholds (YAML/JSON).")
@click.option("--baseline", default=None, type=click.Path(dir_okay=False), help="Earlier JSON report for regressions.")
@click.option("--split", "splits", multiple=True, help="Only items in this split (repeatable).")
@click.option("--tag", "tags", multiple=True, help="Only items carrying this tag (repeatable; all must match).")
@click.option(
    "--limit",
    type=click.IntRange(1, None),
    default=None,
    help="Evaluate at most this many items (--from-history: default 500, at most 10000).",
)
@click.option(
    "--tenant",
    "tenant_id",
    default=None,
    help="Id of the new tenant to evaluate in (default: generated); with --from-history the tenant to replay.",
)
@click.option("--concurrency", type=click.IntRange(1, 32), default=1, show_default=True, help="Items run at once.")
@click.option(
    "--isolate",
    type=click.Choice(["splits", "none"]),
    default="splits",
    show_default=True,
    help="splits: a fresh tenant per split, so split metrics are independent; none: one tenant for all items.",
)
@click.option(
    "--allow-baseline-mismatch",
    is_flag=True,
    help="Compare with a baseline from a different dataset, selection or report schema (warns instead of exit 2).",
)
@click.option("--validate-only", is_flag=True, help="Check the dataset, thresholds and baseline; run nothing.")
@click.option(
    "--cassettes",
    default=None,
    type=click.Path(file_okay=False),
    help="Directory of per-item cassettes: record each item's tool observations and model replies, or replay them.",
)
@click.option(
    "--cassette-mode",
    type=click.Choice(["replay", "replay-tools", "record"]),
    default="replay",
    show_default=True,
    help="replay: tools and model from the cassettes, no network; replay-tools: tools replayed, model live; "
    "record: a live run, written to the cassettes.",
)
def eval_command(
    dataset: Optional[str],
    from_history: bool,
    days: int,
    report: str,
    markdown: Optional[str],
    thresholds: Optional[str],
    baseline: Optional[str],
    splits: List[str],
    tags: List[str],
    limit: Optional[int],
    tenant_id: Optional[str],
    concurrency: int,
    isolate: str,
    allow_baseline_mismatch: bool,
    validate_only: bool,
    cassettes: Optional[str],
    cassette_mode: str,
) -> None:
    """Run a labelled dataset through ingestion and the workflow, report metrics and gate on thresholds.

    Uses the configured database and Redis (point them at a dedicated evaluation
    database migrated with `lg-sotf migrate`) and creates fresh tenants per run
    (one per split by default). Progress and the summary go to stdout, logs to
    stderr. Exit code 0: passed; 1: a threshold or regression check failed;
    2: could not run (or every item errored).

    With --from-history --tenant T --days N, the items are the alerts analysts
    decided in tenant T in the last N days, replayed through the current
    pipeline and model with every side effect disabled (read-only database,
    no escalations, notifications, actions or alert updates) and scored
    against the analysts' decisions. Point the settings at the tenant's
    database; nothing is written to it.

    With --cassettes DIR, --cassette-mode record writes each item's tool observations and model replies to
    DIR; replay runs the dataset again from them without any network call.
    """
    from dataclasses import replace

    from lg_sotf.eval.command import EXIT_CANNOT_RUN, EvalCommandError, EvalOptions, execute
    from lg_sotf.security.crypto import load_secret_box
    from lg_sotf.security.hashing import SecurityConfigError

    if not from_history and not dataset:
        raise click.UsageError("Missing option '--dataset' (or pass --from-history --tenant T).")
    if limit is not None and from_history and limit > 10_000:
        raise click.UsageError("--limit may be at most 10000 with --from-history.")
    options = EvalOptions(
        dataset=dataset or "",
        report=report,
        markdown=markdown,
        thresholds=thresholds,
        baseline=baseline,
        splits=tuple(splits),
        tags=tuple(tags),
        limit=limit,
        tenant_id=tenant_id,
        concurrency=concurrency,
        isolate=isolate,
        allow_baseline_mismatch=allow_baseline_mismatch,
        validate_only=validate_only,
        from_history=from_history,
        days=days,
        cassettes=cassettes,
        cassette_mode=cassette_mode,
    )
    settings = get_settings() if validate_only else _prepare()
    if not validate_only:
        _quiet_eval_logging(settings)
    try:
        # Enrichment reads tenant-encrypted tool keys with the process's box, as in a worker (ADR-0006).
        options = replace(options, secret_box=None if validate_only else load_secret_box(settings))
        code = execute(settings, options, echo=click.echo)
    except (EvalCommandError, SecurityConfigError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(EXIT_CANNOT_RUN)
    except OSError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(EXIT_CANNOT_RUN)
    sys.exit(code)


@cli.command("eval-scorecard")
@click.argument("reports", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", required=True, type=click.Path(dir_okay=False), help="Markdown scorecard to write.")
@click.option("--json", "json_output", default=None, type=click.Path(dir_okay=False), help="Also write it as JSON.")
@click.option("--title", default=None, help="Title (default: 'Scorecard v1: <fast model>').")
@click.option("--prompt-version", default=None, help="Prompt version or hashes, when the reports do not record them.")
@click.option("--note", "notes", multiple=True, help="An extra limitation to list (repeatable), e.g. the hardware.")
@click.option("--internal", is_flag=True, help="Mark the scorecard internal only (automatic for DeepSeek models).")
def eval_scorecard(
    reports: List[str],
    output: str,
    json_output: Optional[str],
    title: Optional[str],
    prompt_version: Optional[str],
    notes: List[str],
    internal: bool,
) -> None:
    """Summarise `lg-sotf eval` JSON reports (one per dataset, same model) as a scorecard (docs/scorecards/)."""
    from lg_sotf.eval.scorecard import ScorecardError, ScorecardOptions, write_scorecard

    options = ScorecardOptions(title=title, prompt_version=prompt_version, notes=tuple(notes), internal=internal)
    try:
        card = write_scorecard(list(reports), output, options, json_output=json_output)
    except (ScorecardError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    for dataset in card["datasets"]:
        fnr = dataset["malicious_false_negative"]
        click.echo(f"{dataset['dataset']['path']}: malicious false negatives {fnr['k']} of {fnr['n']}")
    click.echo(f"scorecard: {output}" + (" (INTERNAL ONLY)" if card["internal_only"] else ""))


@cli.command("tenant-export")
@click.option("--tenant", "tenant_id", required=True, help="Tenant id.")
@click.option(
    "--output", required=True, type=click.Path(dir_okay=False, path_type=Path), help="ZIP file to write (mode 0600)."
)
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def tenant_export(tenant_id: str, output: Path, force: bool) -> None:
    """Export a tenant's data as a ZIP of JSONL files (secrets removed; audited)."""
    from lg_sotf.compliance.ops import tenant_export as run_export

    settings = _prepare()
    result = _run(run_export(settings, tenant_id=tenant_id, output=output, overwrite=force))
    click.echo(f"exported tenant {tenant_id} to {result.path} ({result.bytes_written} bytes)")


@cli.command("tenant-erase")
@click.option("--tenant", "tenant_id", required=True, help="Tenant id (the tenant must be suspended).")
@click.option("--confirm", required=True, help="Repeat the tenant id to confirm.")
@click.option("--yes", is_flag=True, help="Do not ask for interactive confirmation.")
def tenant_erase(tenant_id: str, confirm: str, yes: bool) -> None:
    """Permanently erase a suspended tenant's data; the hash-chained audit log is kept (audited)."""
    from lg_sotf.compliance.ops import tenant_erase as run_erase

    if confirm != tenant_id:
        raise click.UsageError("--confirm must repeat the tenant id exactly")
    settings = _prepare()
    if not yes:
        click.confirm(
            f"Permanently delete every alert, event, user, source and setting of tenant {tenant_id!r}?", abort=True
        )
    report = _run(run_erase(settings, tenant_id=tenant_id, confirm=confirm))
    click.echo(json.dumps(report.as_dict(), default=str, indent=2, sort_keys=True))


@cli.command("evidence-verify")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--allow-unsigned", is_flag=True, help="Accept a bundle without a signature (digest check only).")
def evidence_verify(path: Path, allow_unsigned: bool) -> None:
    """Verify an evidence pack's bundle_sha256 and HMAC signature with this install's key.

    Exit code 0: valid; 1: the digest or signature does not match (or the
    bundle is unsigned without --allow-unsigned).
    """
    from lg_sotf.compliance.ops import verify_evidence_file
    from lg_sotf.runtime.ops import OperationError

    settings = get_settings()
    try:
        document, result = verify_evidence_file(settings, path)
    except OperationError as exc:
        raise click.ClickException(str(exc)) from exc
    integrity = document.get("integrity") or {}
    click.echo(f"bundle_sha256: {integrity.get('bundle_sha256')} ({'matches' if result.digest_ok else 'MISMATCH'})")
    click.echo(f"signature: {result.signature}")
    ok = result.signed_ok or (allow_unsigned and result.digest_ok and result.signature == "absent")
    if not ok:
        sys.exit(1)


@cli.command("verify-invariants")
@click.option("--json", "as_json", is_flag=True, help="Print the results as JSON.")
def verify_invariants(as_json: bool) -> None:
    """Check this install's safety invariants (docs/invariants.md), read-only.

    Reads the database catalog, the runtime role's grants and the settings as
    the API and workers see them (database.url), in a synthetic dry-run tenant
    that owns no data. Nothing is written and no connector is called.
    Exit code 0: no check failed (skipped checks do not apply to this
    install); 1: at least one failed.
    """
    from lg_sotf.invariants.checks import run_checks
    from lg_sotf.invariants.registry import INVARIANTS

    settings = _prepare()
    results = _run(run_checks(settings))
    failed = [r for r in results if r.outcome == "fail"]
    pending = [inv.id for inv in INVARIANTS if inv.status == "pending"]
    if as_json:
        click.echo(json.dumps({"results": [r.as_dict() for r in results], "pending": pending}, indent=2))
    else:
        for r in results:
            click.echo(f"{r.outcome.upper():4}  {r.invariant}  {r.check:<18} {r.detail}")
        counts = {o: sum(r.outcome == o for r in results) for o in ("pass", "skip", "fail")}
        click.echo(
            f"{counts['pass']} passed, {counts['skip']} skipped, {counts['fail']} failed; "
            f"{len(INVARIANTS)} invariants registered" + (f", pending: {', '.join(pending)}" if pending else "")
        )
    if failed:
        sys.exit(1)


@cli.command("mcp")
def mcp() -> None:
    """Run the Model Context Protocol server over stdio.

    A thin client of the LG-SOTF REST API: set LG_SOTF_MCP__API_URL (the API's
    base URL; https, or http for localhost) and either LG_SOTF_MCP__API_KEY_FILE
    (a file only its owner can read or write) or LG_SOTF_MCP__API_KEY
    in the environment of the MCP client's server entry. The key needs the
    'read' scope, plus 'write' for add_note or 'ingest' for test alerts. It is
    never accepted as an argument. Logs go to stderr; stdout carries protocol
    messages only. See docs/mcp.md.
    """
    from lg_sotf.mcp.command import run_mcp

    run_mcp(get_settings())


def main() -> None:
    cli(prog_name="lg-sotf")


if __name__ == "__main__":
    main()
