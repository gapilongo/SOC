"""The ``lg-sotf eval`` command body: load, check, run, report, gate.

Exit codes: 0 when the run finished and every threshold held (or no
thresholds were given), 1 when the gate found a violation, 2 when the
evaluation could not run or produced nothing to judge (bad dataset,
thresholds or baseline, a baseline from a different dataset or selection,
unwritable report path, database, schema or Redis problem, every item
errored).

With ``from_history`` the items are not read from a dataset file: the
tenant's analyst-decided alerts are replayed read-only through the current
pipeline (:mod:`lg_sotf.eval.history`); reporting and gating are the same.

With ``cassettes`` (a directory) each item's tool observations and model
replies are recorded there, or replayed from it so the run makes no network
call (:mod:`lg_sotf.llm.cassette`).
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence

from lg_sotf.eval.dataset import Dataset, DatasetError, load_dataset
from lg_sotf.eval.gate import ThresholdsError, evaluate_gate, load_thresholds
from lg_sotf.eval.report import (
    REPORT_SCHEMA_VERSION,
    build_report,
    load_report,
    render_markdown,
    summary_lines,
    write_json,
)
from lg_sotf.eval.results import ItemResult
from lg_sotf.eval.runner import ISOLATION_MODES, EvalRun, EvalSetupError, Progress, run_evaluation
from lg_sotf.llm.cassette import CASSETTE_MODES, CassetteError, CassetteMode, CassetteSet
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.eval.history import HistoryRun

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_CANNOT_RUN = 2
MAX_CONCURRENCY = 32


class EvalCommandError(Exception):
    """The evaluation could not run; the message is safe to print."""


@dataclass(frozen=True)
class EvalOptions:
    dataset: str
    report: str
    markdown: Optional[str] = None
    thresholds: Optional[str] = None
    baseline: Optional[str] = None
    splits: Sequence[str] = ()
    tags: Sequence[str] = ()
    limit: Optional[int] = None
    tenant_id: Optional[str] = None
    concurrency: int = 1
    isolate: str = "splits"
    allow_baseline_mismatch: bool = False
    validate_only: bool = False
    from_history: bool = False
    days: int = 30
    cassettes: Optional[str] = None
    cassette_mode: str = "replay"
    # The process's SecretBox, built by cli.py (ADR-0006): enrichment reads tenant-encrypted tool keys with it.
    secret_box: Optional[SecretBox] = None


def markdown_path(options: EvalOptions) -> Path:
    if options.markdown:
        return Path(options.markdown)
    return Path(options.report).with_suffix(".md")


def selection(options: EvalOptions) -> Dict[str, Any]:
    """What was evaluated beyond the dataset file; recorded in ``report.run`` and compared with a baseline."""
    return {
        "splits": sorted(options.splits),
        "tags": sorted(options.tags),
        "limit": options.limit,
        "isolation": options.isolate,
    }


def check_writable(path: Path) -> None:
    """Raise :class:`EvalCommandError` unless ``path`` can be (over)written; leaves no file behind."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.is_dir() or not os.access(path, os.W_OK):
                raise PermissionError(13, "Permission denied", str(path))
            with open(path, "a", encoding="utf-8"):
                pass
            return
        fd, probe = tempfile.mkstemp(prefix=".lg-sotf-eval-", dir=path.parent)
        os.close(fd)
        os.unlink(probe)
    except OSError as exc:
        raise EvalCommandError(
            f"cannot write the report to {path}: {exc.strerror or exc}. Nothing was evaluated. In a container, "
            "mount a directory the container user can write (docker run --user \"$(id -u):$(id -g)\")."
        ) from exc


def baseline_mismatches(baseline: Dict[str, Any], dataset: Dataset, current: Dict[str, Any]) -> List[str]:
    """Reasons why ``baseline`` is not comparable with the current run (empty when it is)."""
    problems: List[str] = []
    if baseline.get("schema_version") != REPORT_SCHEMA_VERSION:
        problems.append(
            f"report schema version {baseline.get('schema_version')!r} differs from {REPORT_SCHEMA_VERSION}"
        )
    raw_ds = baseline.get("dataset")
    ds: Dict[str, Any] = raw_ds if isinstance(raw_ds, dict) else {}
    if ds.get("sha256") != dataset.sha256:
        problems.append("it was produced from a different dataset file (sha256 differs)")
    if ds.get("items") != len(dataset.items):
        problems.append(f"it covers {ds.get('items')!r} items, this run {len(dataset.items)}")
    raw_run = baseline.get("run")
    run: Dict[str, Any] = raw_run if isinstance(raw_run, dict) else {}
    if run.get("selection") != current:
        problems.append(f"its selection {run.get('selection')!r} differs from this run's {current!r}")
    return problems


def find_work_tree(path: Path) -> Optional[Path]:
    """The enclosing git work tree of ``path`` (by looking for ``.git``), if any."""
    for parent in [path, *path.parents]:
        if (parent / ".git").exists():
            return parent
    return None


def _stderr(message: str) -> None:
    print(message, file=sys.stderr)


def history_selection(options: EvalOptions, limit: int) -> Dict[str, Any]:
    return {
        "splits": [],
        "tags": [],
        "limit": limit,
        "isolation": "history",
        "tenant_id": options.tenant_id,
        "days": options.days,
    }


def _load_baseline(options: EvalOptions) -> Optional[Dict[str, Any]]:
    if not options.baseline:
        return None
    try:
        return load_report(options.baseline)
    except (OSError, ValueError) as exc:
        raise EvalCommandError(f"cannot read baseline report: {exc}") from exc


def _check_baseline(
    baseline: Dict[str, Any],
    dataset: Dataset,
    current: Dict[str, Any],
    options: EvalOptions,
    warn: Callable[[str], None],
) -> None:
    problems = baseline_mismatches(baseline, dataset, current)
    if problems:
        message = "baseline is not comparable with this run: " + "; ".join(problems)
        if not options.allow_baseline_mismatch:
            raise EvalCommandError(message + " (pass --allow-baseline-mismatch to compare anyway)")
        warn("Warning: " + message)


def _write_outputs(report: Dict[str, Any], gate_dict: Optional[Dict[str, Any]], json_path: str, md: Path) -> None:
    try:
        write_json(report, json_path)
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(render_markdown(report, gate_dict), encoding="utf-8")
    except OSError as exc:
        # The run already happened (and may have cost money): never lose its results.
        fd, fallback = tempfile.mkstemp(prefix="lg-sotf-eval-", suffix=".json")
        os.close(fd)
        write_json(report, fallback)
        raise EvalCommandError(
            f"cannot write the report ({exc.strerror or exc}); the results were saved to {fallback}"
        ) from exc


def execute(  # noqa: C901
    settings: Settings,
    options: EvalOptions,
    echo: Callable[[str], None] = print,
    warn: Callable[[str], None] = _stderr,
) -> int:
    """Run the command; returns the process exit code. Raises :class:`EvalCommandError` for exit code 2."""
    if not 1 <= options.concurrency <= MAX_CONCURRENCY:
        raise EvalCommandError(f"--concurrency must be between 1 and {MAX_CONCURRENCY}")
    if options.from_history:
        return execute_history(settings, options, echo, warn)
    if options.isolate not in ISOLATION_MODES:
        raise EvalCommandError(f"--isolate must be one of {', '.join(ISOLATION_MODES)}")
    try:
        dataset = load_dataset(options.dataset).select(splits=options.splits, tags=options.tags, limit=options.limit)
    except DatasetError as exc:
        raise EvalCommandError(str(exc)) from exc
    if not dataset.items:
        raise EvalCommandError("no dataset items match the selected splits/tags")
    try:
        thresholds = load_thresholds(options.thresholds) if options.thresholds else None
    except ThresholdsError as exc:
        raise EvalCommandError(str(exc)) from exc
    current_selection = selection(options)
    baseline: Optional[Dict[str, Any]] = None
    if options.baseline:
        try:
            baseline = load_report(options.baseline)
        except (OSError, ValueError) as exc:
            raise EvalCommandError(f"cannot read baseline report: {exc}") from exc
        problems = baseline_mismatches(baseline, dataset, current_selection)
        if problems:
            message = "baseline is not comparable with this run: " + "; ".join(problems)
            if not options.allow_baseline_mismatch:
                raise EvalCommandError(message + " (pass --allow-baseline-mismatch to compare anyway)")
            warn("Warning: " + message)
    if not dataset.synthetic:
        for label, raw in (("dataset", options.dataset), ("report", options.report)):
            tree = find_work_tree(Path(raw).resolve().parent)
            if tree is not None:
                warn(
                    f"Warning: the {label} {raw} is inside the git work tree {tree} and the dataset is not marked "
                    "synthetic; keep labelled customer data and its reports out of version control."
                )
    if options.validate_only:
        echo(f"dataset ok: {len(dataset.items)} items, splits {dataset.splits()}")
        if thresholds is not None:
            echo(f"thresholds ok: {len(thresholds['metrics'])} bounds, {len(thresholds['regressions'])} regression checks")
        if baseline is not None:
            echo("baseline ok")
        return EXIT_OK
    md = markdown_path(options)
    check_writable(Path(options.report))
    check_writable(md)

    def progress(done: int, total: int, result: ItemResult) -> None:
        tail = f" ({result.error})" if result.error else ""
        echo(f"[{done}/{total}] {result.item_id}: {result.status}, predicted {result.predicted or 'n/a'}{tail}")

    run = _run_dataset(settings, dataset, options, progress)
    run_info = {**run.info, "selection": current_selection}
    report = build_report(run.results, dataset=dataset, run_info=run_info)
    gate_dict: Optional[Dict[str, Any]] = None
    if thresholds is not None:
        gate = evaluate_gate(report, thresholds, baseline=baseline)
        gate_dict = gate.as_dict()
        report["gate"] = gate_dict
    _write_outputs(report, gate_dict, options.report, md)
    for line in summary_lines(report, gate_dict):
        echo(line)
    echo(f"report: {options.report}; markdown: {md}")
    if report["metrics"]["scored"] == 0:
        raise EvalCommandError(
            f"every one of the {report['metrics']['items']} items errored; nothing was evaluated "
            "(see the report's item errors)"
        )
    if gate_dict is not None and not gate_dict["passed"]:
        return EXIT_GATE_FAILED
    return EXIT_OK


def cassette_set(options: EvalOptions, dataset: Dataset) -> Optional[CassetteSet]:
    """The ``--cassettes`` directory in ``--cassette-mode``; a replay needs the directory to exist."""
    if not options.cassettes:
        return None
    if options.cassette_mode not in CASSETTE_MODES:
        raise EvalCommandError(f"--cassette-mode must be one of {', '.join(CASSETTE_MODES)}")
    directory = Path(options.cassettes)
    if options.cassette_mode != "record" and not directory.is_dir():
        raise EvalCommandError(f"no cassette directory {directory}; record one with --cassette-mode record")
    mode: CassetteMode = options.cassette_mode  # type: ignore[assignment]
    return CassetteSet(directory, mode, source=f"lg-sotf eval {Path(options.dataset).name}", dataset_sha256=dataset.sha256)


def _run_dataset(settings: Settings, dataset: Dataset, options: EvalOptions, progress: Progress) -> EvalRun:
    """Run the evaluation; setup, database and Redis failures become :class:`EvalCommandError` (exit 2)."""
    import asyncpg
    from redis.exceptions import RedisError

    from lg_sotf.db.errors import DatabaseError, DatabaseUnavailable
    from lg_sotf.errors import OperationError
    from lg_sotf.security.hashing import SecurityConfigError

    cassettes = cassette_set(options, dataset)
    try:
        return asyncio.run(
            run_evaluation(
                settings,
                dataset,
                tenant_id=options.tenant_id,
                concurrency=options.concurrency,
                isolate=options.isolate,  # type: ignore[arg-type]
                progress=progress,
                secret_box=options.secret_box,
                cassettes=cassettes,
            )
        )
    except (EvalSetupError, SecurityConfigError, OperationError, CassetteError) as exc:
        raise EvalCommandError(str(exc)) from exc
    except DatabaseUnavailable as exc:
        raise EvalCommandError(f"database unavailable: {exc}") from exc
    except (DatabaseError, asyncpg.PostgresError) as exc:
        raise EvalCommandError(f"database error: {type(exc).__name__}: {exc}") from exc
    except RedisError as exc:
        raise EvalCommandError(f"redis unavailable: {type(exc).__name__}") from exc


def execute_history(
    settings: Settings,
    options: EvalOptions,
    echo: Callable[[str], None] = print,
    warn: Callable[[str], None] = _stderr,
) -> int:
    """``--from-history``: replay the tenant's analyst-decided alerts read-only, then report and gate."""
    from lg_sotf.eval.history import DEFAULT_HISTORY_LIMIT, MAX_HISTORY_DAYS

    if options.dataset:
        raise EvalCommandError("--from-history replays the tenant's own alerts; do not pass --dataset")
    if options.cassettes:
        raise EvalCommandError("--cassettes applies to a --dataset run, not to --from-history")
    if not options.tenant_id:
        raise EvalCommandError("--from-history needs --tenant (the tenant whose decided alerts are replayed)")
    if options.splits or options.tags:
        raise EvalCommandError("--split and --tag do not apply to --from-history")
    if not 1 <= options.days <= MAX_HISTORY_DAYS:
        raise EvalCommandError(f"--days must be between 1 and {MAX_HISTORY_DAYS}")
    limit = options.limit or DEFAULT_HISTORY_LIMIT
    try:
        thresholds = load_thresholds(options.thresholds) if options.thresholds else None
    except ThresholdsError as exc:
        raise EvalCommandError(str(exc)) from exc
    baseline = _load_baseline(options)
    current_selection = history_selection(options, limit)
    if options.validate_only:
        echo(
            f"history backtest options ok: tenant {options.tenant_id}, last {options.days} days, "
            f"at most {limit} alerts"
        )
        return EXIT_OK
    md = markdown_path(options)
    check_writable(Path(options.report))
    check_writable(md)
    for label, raw in (("report", options.report), ("markdown report", str(md))):
        tree = find_work_tree(Path(raw).resolve().parent)
        if tree is not None:
            warn(
                f"Warning: the {label} {raw} is inside the git work tree {tree}; it describes customer alerts, "
                "keep it out of version control."
            )

    def check(dataset: Dataset) -> None:
        if baseline is not None:
            _check_baseline(baseline, dataset, current_selection, options, warn)

    def progress(done: int, total: int, result: ItemResult) -> None:
        tail = f" ({result.error})" if result.error else ""
        echo(
            f"[{done}/{total}] {result.item_id}: {result.status}, predicted {result.predicted or 'n/a'}, "
            f"analyst {result.expected}{tail}"
        )

    run = _run_history(settings, options, limit, progress, check)
    report = build_report(run.results, dataset=run.dataset, run_info={**run.info, "selection": current_selection})
    gate_dict: Optional[Dict[str, Any]] = None
    if thresholds is not None:
        gate = evaluate_gate(report, thresholds, baseline=baseline)
        gate_dict = gate.as_dict()
        report["gate"] = gate_dict
    _write_outputs(report, gate_dict, options.report, md)
    for line in summary_lines(report, gate_dict):
        echo(line)
    echo(f"report: {options.report}; markdown: {md}")
    if report["metrics"]["scored"] == 0:
        raise EvalCommandError(
            f"every one of the {report['metrics']['items']} replays errored; nothing was evaluated "
            "(see the report's item errors)"
        )
    if gate_dict is not None and not gate_dict["passed"]:
        return EXIT_GATE_FAILED
    return EXIT_OK


def _run_history(
    settings: Settings, options: EvalOptions, limit: int, progress: Progress, check: Callable[[Dataset], None]
) -> HistoryRun:
    """Replay the tenant's decided alerts; backtest and database failures become :class:`EvalCommandError`."""
    import asyncpg

    from lg_sotf.db.errors import DatabaseError, DatabaseUnavailable
    from lg_sotf.eval.history import HistoryBacktestError, run_history_backtest
    from lg_sotf.security.hashing import SecurityConfigError

    assert options.tenant_id is not None  # execute_history checked it
    try:
        return asyncio.run(
            run_history_backtest(
                settings,
                tenant_id=options.tenant_id,
                days=options.days,
                limit=limit,
                concurrency=options.concurrency,
                progress=progress,
                before_replay=check,
                secret_box=options.secret_box,
            )
        )
    except (HistoryBacktestError, SecurityConfigError) as exc:
        raise EvalCommandError(str(exc)) from exc
    except DatabaseUnavailable as exc:
        raise EvalCommandError(f"database unavailable: {exc}") from exc
    except (DatabaseError, asyncpg.PostgresError) as exc:
        raise EvalCommandError(f"database error: {type(exc).__name__}: {exc}") from exc
