# Reporting: value, accuracy on your data and detection tuning

Most claims about AI in the SOC outrun the evidence. LG-SOTF reports what it
did **on your own alerts and your analysts' decisions**, with sample sizes,
confidence ranges and an explicit "insufficient data" state, so you can
prove (or disprove) value against your baseline instead of taking it on
faith.

| What | Where | Who |
|---|---|---|
| Value: automation outcomes, analyst hours saved, time to verdict, MTTA/MTTR, SLA breaches, cost per alert | `GET /api/v1/reports/value?from=&to=[&format=csv]`, Reports > Value, Overview figures | viewer |
| Accuracy: AI verdict against the analyst's final decision | `GET /api/v1/reports/accuracy?from=&to=`, Reports > Accuracy | viewer |
| Detection tuning: noisy rules, tune-or-suppress suggestions | `GET /api/v1/reports/detections?from=&to=[&format=csv]`, Reports > Detections | viewer |
| Propose a suppression for a detection | `POST /api/v1/reports/detections/propose-suppression` | analyst (`write` API keys) |
| Monthly report (print to PDF) | `GET /api/v1/reports/monthly?month=YYYY-MM[&format=json]`, Reports > Open monthly report | viewer |
| Backtest a model on your history | `lg-sotf eval --from-history --tenant T --days N` | operator (CLI) |
| Blind audit: production false-negative rate among auto-closed alerts | `GET /api/v1/reports/blind-audit?from=&to=`, Reports > Blind audit | viewer |
| Label blind-audit samples | Blind audit page, `/api/v1/blind-audit/items` | analyst (user accounts) |
| Draw a blind-audit sample | `lg-sotf audit-sample --tenant T`, `POST /api/v1/blind-audit/runs`, Blind audit page | admin (not under an MSSP grant), operator (CLI) |

`from`/`to` are UTC dates (inclusive). The default window is the 30 days
ending today; a window may cover at most 366 days (`400 invalid_window`
otherwise).

## Value report

The cohort is the alerts **ingested** in the window, counted on the UTC day
they were ingested.

| Metric | Definition |
|---|---|
| `alerts_ingested` | Alerts stored in the window. Duplicates dropped at ingestion are not stored and not counted (see Limits). |
| `handled_without_human` | Closed, with no analyst decision on the alert and no person approving or rejecting one of its response actions. Includes alerts closed by a suppression rule or by a cached analyst verdict. |
| `needed_human` | An analyst decided it, a person approved or rejected one of its actions, or it is waiting for an analyst or for an approval. |
| `in_progress` | Neither yet: new, queued, processing or failed. |
| `handled_without_human_rate` | `handled_without_human / (handled_without_human + needed_human)`. Alerts in progress are left out, not counted either way. `null` when the denominator is 0. `handled_without_human_rate_ci` adds `n` and the 95% Wilson interval. |
| `analyst_hours_saved` | `handled_without_human x reporting.minutes_per_alert / 60` (see below). |
| `auto_closed_benign` | Handled without a human and closed as benign. |
| `auto_contained` | Handled without a human and closed as malicious after a policy-chosen response whose actions completed through a connector. |
| `auto_contained_dry_run` | The same, in dry-run mode: nothing was changed on a real system. |
| `escalated` | The alert was attached to an escalation at some point (including alerts grouped into another alert's escalation). |
| `human_decided` | An analyst decision closed the alert (directly or inherited from a grouped escalation). |
| `suppressed_by_rule`, `verdict_cache_hits` | Closed at the gate by a suppression rule / by the cached benign verdict analysts gave twice to the same detection and behaviour (verdict key) in the last 7 days. |
| `grouped_into_escalation` | Attached to an existing escalation instead of opening a new one (deduplication of analyst work). |
| `mean_time_to_verdict_s` | Ingestion to the first automated verdict: the triage agent finishing, or the close for alerts the gate closed before triage. Over `verdicts` alerts. |
| `mttr_s` (`mttr_auto_s`, `mttr_human_s`) | Ingestion to close, over the cohort's closed alerts (those handled without a human / those an analyst decided). |
| `mtta_s` | Escalation created to claimed, over escalations **created** in the window (`escalations_created`, `acknowledged`). |
| `sla_breaches` | SLA sweep actions in the window: an escalation raised a level or expired (`escalation.sla_escalated` / `escalation.sla_expired` in the audit log). `escalations_breached` counts distinct escalations. |
| `llm_cost_usd`, `llm_cost_per_alert_usd` | LLM cost recorded on the window's days (`llm_usage_daily`, every model and agent) and that cost over `alerts_ingested`. |

Totals are computed from sums, never by averaging daily averages. Every day
of the window is present in `days`, with zeros for quiet days.

### Analyst hours saved: the formula, honestly

```
analyst_hours_saved = handled_without_human x minutes_per_alert / 60
```

`minutes_per_alert` is the tenant setting `reporting.minutes_per_alert`
(default 15, 1 to 480; admins set it under Tenant settings > Reporting or
with `PATCH /tenant/settings {"reporting": {"minutes_per_alert": 20}}`,
which is audited). Set it to what triaging one alert costs your analysts
today, measured if you can.

It is an **estimate** and is labelled as one everywhere:

* It assumes every alert automation handled would otherwise have taken an
  analyst the full `minutes_per_alert`. Many noisy alerts are closed in
  seconds by an experienced analyst, and some would never have been looked
  at; both make the figure an upper bound.
* It credits nothing for the enrichment, correlation and summary prepared
  for escalated alerts, which usually shorten the analyst's work: in that
  respect it is a lower bound.
* Suppression-rule and verdict-cache closes count as handled: a person wrote
  the rule or made the earlier decision, but nobody looked at this alert.
  They are broken out so you can exclude them.

## Accuracy report ("accuracy on your data")

The samples are alerts whose **final analyst decision** (the latest one
other than `needs_more_info`) was recorded in the window.

* **Analyst class:** `true_positive` -> malicious; `false_positive` and
  `benign_positive` -> benign.
* **AI class:** the analysis verdict on the alert's **first** escalation,
  that is what the AI concluded before any analyst input (a
  `needs_more_info` round re-runs analysis with the analyst's notes, so the
  later verdicts are not independent). Without an analysis verdict, the
  escalation's threat score (or confidence) is banded with the routing
  thresholds: below `routing.close_max_threat` (30) -> benign ("low"), from
  `routing.response_threshold` (80) -> malicious, otherwise inconclusive.
* **Confusion matrix:** rows analyst class, columns AI class.
* **Headline, `false_negative_rate`:** AI said benign (or low) on alerts the
  analyst confirmed as true positives, over analyst-malicious samples.
* `agreement_rate`: AI class equals analyst class, over all samples (an
  inconclusive AI verdict never agrees). `false_positive_rate`: AI said
  malicious on analyst-benign samples. `ai_inconclusive_rate`.
* Every rate comes with its sample size and a **95% Wilson interval**: next
  to each `<name>_rate` field is `<name>_rate_ci`, `{rate, n, ci_low,
  ci_high}` (`agreement_rate_ci`, `false_negative_rate_ci`,
  `false_positive_rate_ci`, `ai_inconclusive_rate_ci`; the feedback rates
  carry `n`, `ci_low` and `ci_high` themselves). The older
  `agreement_ci95` and `false_negative_ci95` pairs are unchanged. Fewer than
  **30** samples is `status: "insufficient_data"`: the numbers are shown,
  and the UI and the monthly report say "Not enough data (n=12; at least 30
  needed)", the wording every report uses for a small sample.
* **By model:** `provider/model` of the analysis agent (else the triage
  agent) recorded on the alert. Since this release every agent's provider
  and model are stored in `alerts.summary.llm_usage.by_agent.<agent>`
  (`provider`, `model`); older alerts show as `unrecorded` (they made LLM
  calls, model unknown) and alerts assessed without any LLM call as
  `rules only`.
* **Structured feedback:** rates of the analyst's `triage_correct`,
  `analysis_accurate` and `correlation_helpful` answers over every feedback
  row in the window (needs_more_info included), with the number of answers;
  fewer than 10 answers is insufficient data.

What it does **not** tell you: only alerts the AI escalated have an analyst
decision, so this measures the AI on the alerts it sent to a human. A good
false-negative rate here does not prove that no threat was closed
automatically. To measure that, use the backtest below (or a labelled
dataset with `lg-sotf eval`), which replays decided alerts and checks what
automation would close, or the blind audit below, which measures it in
production.

## Blind audit: missed threats among auto-closed alerts

Auto-closed alerts are never looked at again, so a threat the AI closed is
invisible to the accuracy report. The blind audit puts a uniform random
sample of them back in front of an analyst **without the AI's verdict**, so
the label is not anchored on it, and estimates the production
false-negative rate from the labels. It is also the proof-of-value
"label a random sample" flow.

**Sampling.** A run draws from its **frame**: every alert *closed* in the
run's window with no person involved (no analyst decision, no person
approving or rejecting one of its actions) and an AI disposition other than
`malicious`. Built-in sample alerts and alerts sampled before are left out.
Each alert of the frame gets the key `md5("<seed>:<alert id>")` and the run
takes the alerts with the smallest keys, so every subset of the frame is
equally likely. The **seed is chosen by the server** and recorded with the
run (`seed_source: "server"`); nobody can pick a seed that steers what is
drawn. The run stores its window, seed, size rule and `frame_size`.

Runs **follow each other without gaps**: a run starts exactly where the
tenant's last run ended (only the tenant's first run takes a `from`), so no
alert is in two frames and no closed alert falls between runs; asking for
another start is `409 window_not_contiguous`. A window ends at most 5
minutes before the database's clock, so a close still committing is never
missed. Time no run covers yet (before the first run, or since the last
one) is listed in the report as `uncovered`.

The size is `ceil(sample_rate x frame)`, at least `ceil(min_per_week x days
/ 7)`, at most the frame and 2,000 per run; an explicit `size` replaces both
(for example "label 200 random alerts" in a proof of value). Runs start:

* from the scheduler, week by week (Monday 00:00 UTC) from where the last
  run ended, catching up missed weeks, for tenants with the setting on:
  `PATCH /tenant/settings {"blind_audit": {"enabled": true, "sample_rate": 0.02, "min_per_week": 5}}`
  (off by default; rate 2%, at least 5 a week);
* on demand: `lg-sotf audit-sample --tenant T [--to ...] [--size 200]
  [--json]`, `POST /api/v1/blind-audit/runs` (the tenant's own admins; not
  MSSP staff under a grant) or "Draw a sample now" on the Blind audit page.

A **dry run** (`--dry-run`, or `"dry_run": true`) draws and returns the
sample without recording anything; it is the only place for a seed of your
choosing (`--seed`). It keeps alerts an earlier run sampled in its frame,
so a recorded run's window and seed re-draw that run's sample exactly.

**Labelling.** The Blind audit page (analysts and admins, signed in as
themselves) shows each sample's source, times, entities, normalized fields
and source event, and asks for `malicious`, `benign` or `unsure` (keys M,
B, U; N for the next sample). Items carry no alert id. **From the moment
an alert is sampled until it is labelled, its AI side is withheld from
everyone in the tenant, admins and platform admins included:**

* `GET /alerts/{id}` and `GET /alerts` return `hidden_for_blind_audit:
  true` with `disposition`, `confidence`, `threat_score` and `priority`
  null, `summary` `{"hidden_for_blind_audit": true}` and no `findings`; a
  `disposition` filter never returns the sample. MCP tools read the same
  routes;
* its timeline returns only its ingestion and notes (the workflow's events
  would show its path, for example gate straight to close);
* its escalations and response actions are not served (`404`, and left out
  of lists) and audit entries about it come back with `details` replaced and
  `redacted: true`;
* its evidence pack withholds the alert's verdict, the workflow events, the
  agents, investigation, enrichment, correlation, oversight, escalation,
  action, feedback and audit sections;
* WebSocket events about it go out without data;
* it cannot be reprocessed (`409 hidden_for_blind_audit`): a new run would
  write a new verdict;
* it is left out of the value, detection and dashboard figures, and other
  alerts' correlation digests no longer name it or count its disposition
  (the correlation agent leaves it out of new digests; digests stored
  earlier are filtered when served).

**Blindness starts when the alert is sampled.** Until then its verdict was
visible like any alert's: an analyst may have seen it in the console or the
live feed, and exports taken earlier include it. Comparing a value or
detection CSV export taken before a run with one taken after reveals the
dispositions of the sampled alerts in aggregate. Free-text reasoning another
alert's analysis wrote before the sample was drawn is not rewritten. MSSP
staff under a grant may label; their labels are attributed to their
organisation.

The label response, and later reads, add `reveal`: the AI's class when the
alert was sampled, the agreement, confidence, threat score, routing code,
close reason and reasoning. A label is given once (`409` after). A
**malicious** label opens a normal escalation for the alert (routing code
`blind_audit`), drops the cached verdict of its fingerprint, and is audited
(`blind_audit.labelled`, `escalation.created`); sampling is audited as
`blind_audit.sampled`. **Deciding that escalation re-triages the alert**: an
alert whose run has ended is queued again through the reprocess path
(`alert.reprocess_requested`), and its new run starts at the analyst's
decision, so the alert gets the analyst's disposition and
`analyst_decision`, and a response is planned where the autonomy policy
allows (the value report and the history then count it as decided by a
person).

**The estimate** (`GET /reports/blind-audit`, Reports > Blind audit) covers
the runs whose window overlaps the report window. It is **stratified**: each
run is a stratum weighted by its frame, because runs draw different shares
of their frames (the weekly minimum, a proof-of-value size) and pooled
labels would be biased:

* `false_negative_rate`: `p = sum(N_h p_h) / sum(N_h)` over the runs with a
  malicious-or-benign label, where `N_h` is a run's frame and `p_h` its
  malicious labels over malicious and benign labels; `n` is the number of
  such labels. Its 95% interval is Wilson's on Kish's effective sample size
  `N^2 / sum(N_h^2 / n_h)` (`effective_n`): exact for one run, and still
  above zero when no label was malicious. The variance behind it is
  `sum((N_h/N)^2 p_h (1 - p_h) / n_h (1 - n_h/N_h))`. Fewer than **30**
  labels is `insufficient_data`, shown as "Not enough data (n=12; at least
  30 needed)";
* `estimated_missed` (with `_low` and `_high`): `sum(N_h p_h)` and the
  interval scaled to those frames (`estimated_frame`);
* `worst_case_rate` and `worst_case_missed` (with `_high`): unsure and
  pending samples counted as malicious;
* `status` is `incomplete` (and `complete` false) until every sample of
  every run is labelled;
* `strata`: each run with its own rate and Wilson interval; `runs`;
  `uncovered`; `labels_by_organisation` (`null` for the tenant's own people,
  else the MSSP organisation that labelled under a grant).

## Detection tuning report

A **detection** is a source plus its rule name (`normalized.rule_name`; the
alert title when the source sends none, shown as such). For alerts ingested
in the window, per detection: `volume`, `decided` (a disposition exists),
`benign`, `benign_rate` (benign / decided; `benign_rate_ci` adds `n` and the 95% Wilson interval), `malicious`, `auto_closed`
(closed benign without an analyst), `analyst_false_positive`,
`analyst_benign_positive`, `analyst_true_positive`, the median and maximum
severity and the highest severity an analyst confirmed benign. The 200
busiest detections are listed (`truncated` says if there are more).

Suggestions (heuristics, with the reasoning in `reason`):

| Suggestion | When |
|---|---|
| none | fewer than 10 decided alerts, or less than 80% benign |
| `candidate_suppression` | at least 95% benign, no malicious alert and no analyst true positive, at least 3 analyst-confirmed benign decisions, median severity below high |
| `tune_rule` | at least 80% benign but not a suppression candidate: some alerts were malicious, the benign verdicts rest mostly on automation, the detection is high severity, or the benign rate is under 95% |

A suppression hides future alerts wholesale, so it needs analyst-confirmed
evidence; benign verdicts reached by automation alone are never enough (the
model's own verdict must not launder itself into a rule).

**Propose suppression** (Reports > Detections, analyst and above) goes
through the same suggestion service as a false-positive decision: the rule
is created **disabled**, expires after 90 days, is audited as
`suppression.suggested` and only an admin can enable it (Suppressions). It
matches the detection's source and rule name (or title) and only severities
up to the highest one an analyst confirmed benign in the window, never a
more severe alert of the same detection. Proposing the same detection again
returns the existing unexpired rule. The API refuses (`422
no_confirmed_benign`) a detection without an analyst-confirmed benign alert
in the window.

## Monthly report and exports

* `GET /reports/monthly?month=2026-09` (default: the current month) returns
  one self-contained HTML page (inline CSS only, no scripts, links or
  external assets; alert text and the tenant name are escaped) with the
  tenant name, the value tiles and daily chart, the accuracy summary with
  its caveats, the 25 busiest detections and the definitions. The
  response's Content-Security-Policy allows only that stylesheet, by hash.
  `format=json` returns the three reports for the month. In the UI, *Open
  monthly report* shows a printable page (Print or save as PDF) and
  *Download HTML* saves the self-contained file.
* `format=csv` on `/reports/value` (one row per day, every value metric) and
  `/reports/detections` (one row per detection). A rate's interval is three
  columns at the end, `<rate>_n`, `<rate>_ci_low` and `<rate>_ci_high`. Text cells that a
  spreadsheet could evaluate as a formula (starting with `=`, `+`, `-`, `@`,
  tab or carriage return) are prefixed with `'`.

## Backtest: try a model on your own history

```sh
# Settings point at the tenant's database (used read-only) and at the model to try.
LG_SOTF_LLM__PROVIDER=openai LG_SOTF_LLM__DEEP__MODEL=... \
  lg-sotf eval --from-history --tenant acme --days 30 --report ~/lg-sotf-eval/acme-openai.json
# The current model over the same decisions, compared with that run:
lg-sotf eval --from-history --tenant acme --days 30 --report ~/lg-sotf-eval/acme-current.json \
  --baseline ~/lg-sotf-eval/acme-openai.json --thresholds ~/lg-sotf-eval/thresholds.yaml
```

The items are the tenant's alerts whose final analyst decision was recorded
in the last N days (at most `--limit`, default 500, maximum 10 000, oldest
first); the expected label is that decision. Each alert is replayed through
the **current** triage, correlation and analysis agents and routing policy,
and the result is scored with the evaluation metrics and report
(docs/evaluation.md): the malicious false-negative rate is the share of
analyst-confirmed threats the current pipeline would close on its own.
`waiting_human` means the replay would escalate, `waiting_approval` that the
policy would plan a response. Two runs over the same decisions share the
dataset hash, so one can be the other's `--baseline`.

Side effects are disabled by construction, not by convention:

* every database transaction is read-only (PostgreSQL rejects a write) and
  RLS-bypassing system transactions are refused;
* the replay stops at the routing decision: no escalation, response plan,
  action, approval request, notification, event or alert update is created,
  so response execution (dry-run or not) never runs;
* agents do not record LLM accounting or indicator sightings, no tenant
  token budget is reserved and usage is not written to `llm_usage_daily`;
* Redis (queue, verdict cache, event bus) is not used.

Unlike a dataset run, `--from-history` is allowed with
`environment=production`, because it writes nothing. The report and its
Markdown list alert ids of customer alerts: keep them outside the
repository (the CLI warns otherwise).

## Performance

Every report aggregates in SQL over a bounded window using existing
per-tenant indexes (alerts by ingestion time, escalations by creation time,
the audit log by time, analyst feedback by creation time, response actions
by creation time, LLM usage by day; the first triage event per alert is an
index probe that skips partitions older than the window), so no migration
was needed. Results are cached in Redis for 60 seconds per tenant, report
and window (`{prefix}:t:{tenant}:cache:reports:...`); the Overview figures
share the dashboard summary's 15-second cache. A year-long report on a large tenant
can take seconds the first time; prefer monthly windows for routine use.

## Limits

* **Sample alerts** (the onboarding "load sample alerts", source
  `demo:samples`) are left out of the value, accuracy, detection and
  backtest figures and the Overview figures. Escalation, SLA-breach and LLM
  cost figures come from their own tables and still include them.
* **Ingest duplicates** are dropped before they are stored, so they are not
  in these reports; they are counted in the Prometheus metric
  `lgsotf_ingest_events_total{outcome="duplicate"}`.
* **Time attribution:** alerts count on their ingestion day, escalations on
  their creation day, SLA breaches and LLM cost on the day they happened. A
  window's edges therefore do not line up exactly across metrics.
* **Reprocessed alerts** keep summary fields from their earlier run (for
  example an escalation id) and are counted once, with their latest status.
* **Accuracy** covers escalated alerts only and scores the first escalation's
  verdict; attached (grouped) alerts are not samples of their own.
* **Model attribution** exists only for alerts processed after this release.
* **Blind audit**: samples waiting for a label are left out of the value,
  detection and dashboard figures until labelled, so those figures change
  when a run is drawn and again when its samples are labelled. Blindness
  covers the time after sampling only (see "Blind audit" above).
* **Backtest context:** suppression rules and the verdict cache are skipped
  (both derive from the decisions being scored). Correlation and history
  lookups see the tenant's data as of each alert's ingestion (sightings
  before it; related alerts' outcomes only if they were closed by then), but
  external threat-intelligence lookups answer as of today, and model calls
  are real and billed to the configured provider.
* **Hours saved** is an estimate (see above), and the suggestions in the
  detection report are heuristics for a person to review, never applied
  automatically.
