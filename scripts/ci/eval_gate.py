#!/usr/bin/env python3
"""The evaluation gate CI runs (ARCH-E2.1): `lg-sotf eval` on the synthetic and phishing sets.

    python scripts/ci/eval_gate.py pr --out eval-gate            # every pull request
    python scripts/ci/eval_gate.py pr --update-baselines         # record the baselines again
    python scripts/ci/eval_gate.py pr --set phishing_v1          # one set only
    python scripts/ci/eval_gate.py nightly --out eval-nightly    # the pinned real model

``pr`` runs both sets with the offline fake model (it forces ``llm.provider=fake``; no model is
ever called) against each set's thresholds and its committed baseline
(tests/fixtures/eval/baselines/). It exits 1 when a threshold or a regression check fails (a
missed attack above the baseline, benign handling below it) and 2 when a set could not run. After
an intended behaviour change, ``--update-baselines`` (``make eval-baselines``) writes the baselines
again; commit them with the change so the reviewer sees which items moved.

``nightly`` runs both sets once with a real model and writes a scorecard. The model comes from
``EVAL_LLM_*`` (repository variables and one secret, see MODEL_ENV). Without ``EVAL_LLM_PROVIDER``
it does nothing and exits 0. It refuses any model that is not hosted in the EU or local, and any
model name that is not pinned. It records and never gates: the exit code is 2 only when a set
could not run.

Both need a migrated database and a Redis, as `lg-sotf eval` does (docs/evaluation.md).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import secrets
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path("tests/fixtures/eval")

EXIT_OK, EXIT_GATE_FAILED, EXIT_CANNOT_RUN = 0, 1, 2


@dataclass(frozen=True)
class GatedSet:
    name: str
    dataset: Path
    thresholds: Path

    @property
    def baseline(self) -> Path:
        return FIXTURES / "baselines" / f"{self.name}.json"


SETS = (
    GatedSet("synthetic_v1", FIXTURES / "synthetic_v1.jsonl", FIXTURES / "smoke_thresholds.yaml"),
    GatedSet("phishing_v1", FIXTURES / "phishing_v1.jsonl", FIXTURES / "phishing_smoke_thresholds.yaml"),
)

# What a baseline keeps of a report: counts and rates that do not change from run to run (no
# latency, cost, timestamp or alert id), for all items and for each split.
BASELINE_METRICS = (
    "items",
    "scored",
    "errors",
    "malicious_items",
    "benign_items",
    "malicious_false_negatives",
    "malicious_false_negative_rate",
    "malicious_auto_closed",
    "malicious_auto_close_rate",
    "benign_auto_close_rate",
    "benign_auto_response_rate",
    "benign_escalation_rate",
    "auto_close_rate",
    "escalation_rate",
    "approval_request_rate",
)

# Repository variable or secret -> the setting it becomes in the nightly run.
MODEL_ENV = {
    "EVAL_LLM_PROVIDER": "LG_SOTF_LLM__PROVIDER",
    "EVAL_LLM_BASE_URL": "LG_SOTF_LLM__BASE_URL",
    "EVAL_LLM_API_KEY": "LG_SOTF_LLM__API_KEY",  # the only secret
    "EVAL_LLM_FAST_MODEL": "LG_SOTF_LLM__FAST__MODEL",
    "EVAL_LLM_DEEP_MODEL": "LG_SOTF_LLM__DEEP__MODEL",
    "EVAL_LLM_STRUCTURED_OUTPUT": "LG_SOTF_LLM__STRUCTURED_OUTPUT",
}
ALLOWED_RESIDENCY = ("eu", "local")


class GateError(Exception):
    """The gate cannot run as configured; the message is safe to print."""


def lg_sotf(args: Sequence[str]) -> int:
    """Run one `lg-sotf` command in this process and return its exit code."""
    import click

    from lg_sotf.cli import cli

    print("$ lg-sotf " + shlex.join(args), flush=True)
    try:
        cli.main(args=list(args), prog_name="lg-sotf", standalone_mode=False)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (EXIT_OK if exc.code is None else EXIT_CANNOT_RUN)
    except click.ClickException as exc:
        exc.show()
        return EXIT_CANNOT_RUN
    return EXIT_OK


def reload_settings() -> Any:
    """The settings as the environment now gives them, with throwaway security keys where none is configured.

    The evaluation creates its own tenants, and nothing reads their rows afterwards; a CI job needs no key
    of its own. Configured keys are never replaced.
    """
    from lg_sotf.settings import get_settings, reset_settings

    reset_settings()
    security = get_settings().security
    if security.encryption_keys and security.indicator_hmac_key:
        return get_settings()
    if not security.encryption_keys:
        os.environ["LG_SOTF_SECURITY__ENCRYPTION_KEYS"] = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    if not security.indicator_hmac_key:
        os.environ["LG_SOTF_SECURITY__INDICATOR_HMAC_KEY"] = secrets.token_urlsafe(48)
    reset_settings()
    return get_settings()


# --------------------------------------------------------------------------- baselines


def outcome(item: Mapping[str, Any]) -> str:
    """``closed:benign``, ``waiting_human``, ...: what automation did with one item."""
    status = str(item.get("status"))
    return f"{status}:{item.get('disposition')}" if status == "closed" else status


def baseline_from_report(report: Mapping[str, Any], gated: GatedSet) -> Dict[str, Any]:
    """The part of a report the gate compares, in a form that only changes when behaviour does."""

    def stable(metrics: Mapping[str, Any]) -> Dict[str, Any]:
        return {key: metrics[key] for key in BASELINE_METRICS}

    return {
        "schema_version": report["schema_version"],
        "description": f"Baseline of the CI evaluation gate for {gated.dataset.name} with the fake model "
        "(scripts/ci/eval_gate.py). Do not edit: record it again with `make eval-baselines`.",
        "dataset": {
            "path": gated.dataset.as_posix(),
            "sha256": report["dataset"]["sha256"],
            "items": report["dataset"]["items"],
        },
        "run": {"llm_provider": report["run"].get("llm_provider"), "selection": report["run"]["selection"]},
        "metrics": stable(report["metrics"]),
        "splits": {name: {"metrics": stable(split["metrics"])} for name, split in report["splits"].items()},
        "outcomes": {item["item_id"]: outcome(item) for item in report["items"]},
    }


def changed_outcomes(report: Mapping[str, Any], baseline: Mapping[str, Any]) -> List[str]:
    """``item: before -> now`` for every item whose outcome differs from the baseline's."""
    before = baseline.get("outcomes") or {}
    now = {item["item_id"]: outcome(item) for item in report.get("items") or []}
    return [f"{i}: {before.get(i, 'absent')} -> {now.get(i, 'absent')}" for i in sorted({*before, *now})
            if before.get(i) != now.get(i)]


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------- pr: fake model, committed baselines


def run_pr_set(gated: GatedSet, out: Path, update: bool) -> int:
    report_path = out / f"{gated.name}.json"
    args = ["eval", "--dataset", str(gated.dataset), "--thresholds", str(gated.thresholds), "--report", str(report_path)]
    if not update:
        args += ["--baseline", str(gated.baseline)]
    code = lg_sotf(args)
    report = read_json(report_path) if code != EXIT_CANNOT_RUN else None
    if update:
        if code != EXIT_OK or report is None:
            print(f"::error::{gated.name}: the run failed or did not pass its thresholds (exit code {code}); "
                  "the baseline was not written")
            return code or EXIT_CANNOT_RUN
        gated.baseline.parent.mkdir(parents=True, exist_ok=True)
        gated.baseline.write_text(json.dumps(baseline_from_report(report, gated), indent=2) + "\n", encoding="utf-8")
        print(f"{gated.name}: baseline written to {gated.baseline}")
        return EXIT_OK
    moved = changed_outcomes(report, read_json(gated.baseline) or {}) if report is not None else []
    if moved:
        print(f"{gated.name}: {len(moved)} item(s) ended differently than in the baseline:")
        for line in moved:
            print(f"  {line}")
        if code == EXIT_OK:
            print("  No gated metric regressed. If the change is intended, record the baselines again "
                  "(make eval-baselines) and commit them.")
    if code == EXIT_GATE_FAILED:
        print(f"::error::Evaluation gate failed on {gated.name}: see the gate lines above. If the change is "
              "intended, record the baselines again (make eval-baselines) and commit them with it.")
    elif code != EXIT_OK:
        print(f"::error::The evaluation of {gated.name} could not run (exit code {code}).")
    return code


def run_pr(out: Path, update: bool, only: Sequence[str] = ()) -> int:
    os.environ["LG_SOTF_LLM__PROVIDER"] = "fake"  # over any .env: this gate never calls a model
    if reload_settings().llm.provider != "fake":
        raise GateError("the pull-request gate runs the fake model only")
    codes = [run_pr_set(gated, out, update) for gated in SETS if not only or gated.name in only]
    return EXIT_CANNOT_RUN if EXIT_CANNOT_RUN in codes else max(codes)


# --------------------------------------------------------------------------- nightly: pinned EU or local model


def apply_model_env(env: Mapping[str, str]) -> bool:
    """Copy ``EVAL_LLM_*`` into the settings' environment; False when no model is configured."""
    if not (env.get("EVAL_LLM_PROVIDER") or "").strip():
        return False
    for source, target in MODEL_ENV.items():
        value = (env.get(source) or "").strip()
        if value:
            os.environ[target] = value
        else:
            os.environ.pop(target, None)
    os.environ["LG_SOTF_LLM__PROMPT_CACHING"] = "false"
    return True


def check_model(settings: Any, env: Mapping[str, str]) -> Any:
    """The configured model, or :class:`GateError` when it is not a pinned EU or local one."""
    from lg_sotf.onboarding.llm_profiles import configured_model

    for name in ("EVAL_LLM_FAST_MODEL", "EVAL_LLM_DEEP_MODEL"):
        pinned = (env.get(name) or "").strip()
        if not pinned:
            raise GateError(f"{name} is not set: name the exact model, so every night measures the same one")
        if pinned.lower().endswith("latest"):
            raise GateError(f"{name}={pinned} is a moving alias; pin a model version")
    model = configured_model(settings)
    if model.residency not in ALLOWED_RESIDENCY:
        raise GateError(
            f"the nightly run takes an EU-hosted or local model only; provider {model.provider} with this base URL "
            f"is classified '{model.residency}' (lg_sotf.onboarding.llm_profiles)"
        )
    if model.residency == "eu" and settings.llm.api_key is None:
        raise GateError("EVAL_LLM_API_KEY (a repository secret) is not set")
    return model


def run_nightly(out: Path, env: Mapping[str, str]) -> int:
    from lg_sotf import __version__
    from lg_sotf.eval.scorecard import ScorecardError, ScorecardOptions, write_scorecard

    if not apply_model_env(env):
        print("::notice::No evaluation model is configured (the repository variable EVAL_LLM_PROVIDER is "
              "not set); nothing was run. See docs/evaluation.md, \"Evaluation gate in CI\".")
        return EXIT_OK
    model = check_model(reload_settings(), env)
    print(f"model: {model.provider} ({model.residency}), fast {model.fast_model}, deep {model.deep_model}")
    reports: List[Path] = []
    codes: List[int] = []
    for gated in SETS:
        report_path = out / f"{gated.name}.json"
        codes.append(lg_sotf(["eval", "--dataset", str(gated.dataset), "--report", str(report_path)]))
        if codes[-1] == EXIT_OK:
            reports.append(report_path)
    if reports:
        commit = (env.get("GITHUB_SHA") or "")[:12]
        options = ScorecardOptions(
            title=f"Nightly scorecard: {model.fast_model} / {model.deep_model} ({model.residency})",
            prompt_version=f"lg-sotf {__version__}" + (f" at commit {commit}" if commit else ""),
            notes=(f"Nightly CI run, provider {model.provider}, hosted: {model.residency}. Synthetic sets only.",),
        )
        try:
            write_scorecard(reports, out / "scorecard.md", options, json_output=out / "scorecard.json")
        except (ScorecardError, OSError) as exc:
            raise GateError(f"cannot write the scorecard: {exc}") from exc
        print(f"scorecard: {out / 'scorecard.md'}")
        summary = env.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write((out / "scorecard.md").read_text(encoding="utf-8") + "\n")
    return EXIT_OK if all(code == EXIT_OK for code in codes) else EXIT_CANNOT_RUN


# --------------------------------------------------------------------------- entry point


def main(argv: Optional[Sequence[str]] = None, env: Optional[Mapping[str, str]] = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    pr = sub.add_parser("pr", help="fake model against the committed baselines")
    pr.add_argument("--out", default="eval-gate", help="directory for the reports")
    pr.add_argument("--update-baselines", action="store_true", help="write the baselines instead of comparing")
    pr.add_argument("--set", dest="only", action="append", default=[], choices=[gated.name for gated in SETS],
                    help="only this set (repeatable; default: every set)")
    nightly = sub.add_parser("nightly", help="the pinned EU or local model; writes a scorecard")
    nightly.add_argument("--out", default="eval-nightly", help="directory for the reports and the scorecard")
    args = parser.parse_args(argv)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    try:
        with contextlib.chdir(REPO_ROOT):  # dataset, thresholds and baseline paths are relative to the repository
            if args.mode == "pr":
                return run_pr(out, args.update_baselines, args.only)
            return run_nightly(out, os.environ if env is None else env)
    except GateError as exc:
        print(f"::error::{exc}")
        return EXIT_CANNOT_RUN


if __name__ == "__main__":
    sys.exit(main())
