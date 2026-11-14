# Console v2: design

Design for issue #372 (PRD-2.7). It covers the investigation view, the case page, the approval inbox, the work queue,
the platform shell and the overview. Nothing here is product code; the engineers build from it.

| File | What it is |
|---|---|
| [`console-v2.html`](console-v2.html) | The clickable prototype. One file, inline CSS and JavaScript, fonts embedded, no network request. Open it in a browser. |
| [`screens/`](screens/) | Each screen in light and dark at 1440 and 390 px, plus five interaction states. |
| [`screenshots.cjs`](screenshots.cjs) | Re-takes the screenshots and checks the prototype (see section 6). |

Screens switch by hash: `#queue`, `#investigation`, `#case`, `#approvals`, `#overview`, `#shell`. `?theme=light` or
`?theme=dark` pins a theme; without it the file follows the system setting, and the button in the top bar cycles
System, Light, Dark.

All content is one invented scenario at 10:04 on 14 November 2026: an MSSP ("Brightwater SOC") with six tenants; a
Word attachment that starts an encoded PowerShell and leads to an LSASS dump at Northwind Logistics (CASE-2291); a
password spray with one success at Maritima Ferries; a routine package install the AI closed.

## 1. The ten decisions, and why

1. **The headline is the verdict, as a sentence.** The alert title becomes a small page title; the largest text on
   the page says what happened and the line under it says why the alert is with a person. An analyst should be able
   to stop reading there. Today the reason is one line inside a timeline in a 380 px panel.
2. **Three voices, never mixed.** *Observed* (a tool returned it) is monospace on a recessed surface with a double
   rule, its outcome (`returned n rows`, `returned nothing`, `failed`) and its hash. *Claimed* (the model wrote it) is
   plain text with a ring marker. *Decided* (a check, the policy or a person) has a diamond or a filled dot. The same
   three markers are used in the steps, the case timeline and the approval record. This is the evidence record of
   #356 made visible, and it is why the page never shows model reasoning as a trace.
3. **Each claim sits beside its fact, and the decisive token is highlighted.** People rarely open citations, and
   explanations alone raise acceptance of wrong answers; what lowers over-reliance is making the check cheaper than
   trusting. So the log line is on the page, next to the claim, with a yellow highlighter on the few characters
   that matter. The highlighter is the one loud colour on the page and it is reserved for this.
4. **A rejected claim stays on the page, struck through.** Claim 6 ("no sign of lateral movement") rests on a lookup
   that returned nothing; the checker rejects it and the page says so. Showing the rejection is how the rule "an
   empty result is never benign evidence" (ADR-0014, Amendment 2) becomes something an analyst can see working.
5. **"What is not established" is a column of its own, in three kinds.** Checked and found nothing (collapsed to one
   line), not checked, could not check for this customer. Each kind has its own shape. It sits beside the claims on
   a wide screen and after them on a phone.
6. **No percentages. Four outcomes, each tied to what happens next, with the measured track record.** Closed by AI
   and backed by evidence; closed by AI on the model's word (audit required); needs review, not proven either way;
   needs your decision, likely malicious. Beside the verdict the page shows how often analysts confirmed that
   outcome for this tenant, drawn as countable squares (31 of 34), and refuses a rate when the sample is small.
7. **One key decides.** A decision bar stays at the bottom of the investigation: `T`, `B`, `F`, `N`, a note, and
   `Ctrl+Enter` to record and open the next item. The bar says what the chosen verdict sets in motion before it is
   recorded. `V` hides the verdict and the claims so the reader judges from the evidence first; blind audits open
   that way.
8. **One queue, 24 rows per screen instead of 6 to 7.** One line per item at 28 px (28 rows at 24 px), sorted by
   deadline, with the reason it needs a person in the row. The preview opens beside the list and the list keeps its
   essential columns. Look-alikes are one row with a count; bulk decide is offered only for them.
9. **Flat sheet, hairlines, no cards.** Content sits on the page; structure comes from rules, a numbered margin
   (01 to 06, the same order on every investigation) and type. This is deliberate distance from today's tiles and
   from the usual dark dashboard: the page should read like a record an auditor can follow, at a density an analyst
   can work in for eight hours. Corners are 3 px, the dark theme is graphite and not black, and there is no
   gradient, glow or decorative colour.
10. **Scope is a shell control and part of the address.** All tenants, a tenant group, one tenant; every page
    honours it; lists gain a tenant column in a wider scope; a detail page always names its tenant. Brand is three
    values (name, logo, one accent) and severity, state and verdict colours cannot be branded.

Decisions that need a product owner's yes because they change behaviour, not layout:

* **MSSP staff decide for a tenant under their own name.** The prototype records "Inès Moreau, Brightwater SOC, for
  Northwind Logistics". Today decisions are refused while acting on another tenant.
* **Approve-all stays absent on purpose.** Batch approval exists only for identical actions (same action, same
  alert, same risk, same guardrail result). Batch reject follows the same rule.
* **A reason is optional on approve and required on reject, reopen and flag.**
* **The default theme follows the system.** Today dark is the default. Both remain first-class.

## 2. Screens

| Screen | Hash | What to look at |
|---|---|---|
| Investigation (`/alerts/:id`) | `#investigation` | Sections 01 to 06; click a claim number or press `1` to `6`; open "Query and full result"; `V`; the decision bar |
| Queue | `#queue` | `J` `K` or arrows, `Enter`, `Space`, `X`, `C`; sort by a header; density; select the `×9` row for bulk decide; scope |
| Case (`/cases/:key`) | `#case` | The table of nine alerts with who or what closed each; Reopen and Flag ask for a reason |
| Approval inbox | `#approvals` | Groups by tenant then alert; tick two "Block address" rows (batch allowed), then a different one (batch refused); Approve or Reject opens the reason |
| Overview | `#overview` | "Needs you now", then who or what closed the rest and how that is verified; the tenant table follows the scope |
| Platform shell | `#shell` | Scope, search, notifications, brand (live), the second service in three states, the unlicensed page |

Everywhere: `Ctrl+K` or `/` opens search and commands; `G` then `Q`, `A`, `O`, `C`, `S` goes to a screen.

## 3. Components and their states

New components are marked **new**; the others exist in `src/lg_front/src/components/` and change as described.

| Component | Used in | States |
|---|---|---|
| `VerdictHeader` **new** | Investigation, queue preview | outcome (4 kinds), verdict hidden, still investigating (skeleton lines), investigation failed (falls back to "No investigation ran: the model saw only the alert") |
| `TrackRecord` **new** | Investigation | counted squares (n up to 60), fraction and bar (n above 60), too few for a rate (n below 30), no data yet |
| `ClaimRow` **new** | Investigation | selected, backed, rejected by the checker (struck through, reason shown), no fact cited ("Unsupported"), rule of the skill true (blocks a close) |
| `Observation` **new** (replaces `FindingItem` and `FindingRow`) | Investigation, approvals, queue preview | returned rows, returned nothing, failed, incomplete (window still open), payload erased (hash only), raw query open or closed |
| `CommandExplain` **new** | Inside an observation | decoded by code, explained by the model, no explanation available |
| `NotEstablished` **new** | Investigation, blind-audit card | three kinds, each empty ("Nothing in this kind"), empty lookups collapsed or listed |
| `StepList` **new** (replaces both `eventSummary` copies) | Investigation, case timeline | actor: code, model, check or policy, person; with or without produced facts |
| `ActionTable` **new** | Investigation, approvals | waiting, you can approve, needs an admin (locked, says who was told), blocked by policy, approved (running, verified, failed), rejected, selected |
| `ReasonRow` **new** | Approvals, case | optional, required, invalid (empty where required), submitting |
| `DecisionDock` **new** (replaces `DecisionForm`) | Investigation | no verdict, verdict chosen (effect line), note missing, not claimed ("Claim to decide"), read-only for a viewer, version conflict |
| `BatchBar` **new** | Queue, approvals | hidden, identical items (enabled), single item, mixed items (disabled, says why) |
| `QueueTable` (from `VirtualTable`) | Queue | row: cursor, selected, deadline under 10 min, look-alike group; density 24, 28, 44 px; preview open or closed; empty view; loading (skeleton rows); error |
| `SavedViews` **new** (replaces four tab implementations) | Queue | selected, with count, "Save view" |
| `PreviewPane` **new** | Queue | row shown, no row, hidden below 1180 px |
| `ClosedBy` **new** | Case, alerts list | AI backed by evidence, AI on the model's word, suppression rule, earlier analyst verdict, analyst; with "Linked" tag; reopened; flagged |
| `SeverityTag` (changed) | Everywhere | critical to info as 4 to 0 bars plus the word; critical and high in bold |
| `OutcomeTag` **new** | Queue, case, approvals | the four outcomes, waiting for approval, being investigated |
| `ScopeControl` **new** (replaces `TenantSwitcher`) | Shell | all, group, tenant; open; acting-as banner; scope no longer exists |
| `CommandPalette` **new** | Shell | empty query, results by kind, commands only (`>`), nothing matches |
| `Notifications` **new** | Shell | unread count, list, empty |
| `Rail` (from `Sidebar`) | Shell | item: default, current, with count, locked; group: licensed, not licensed (operator), absent (customer), unavailable |
| `NotLicensed` **new** | Shell | not licensed, licence check failed |
| `HandledBar` **new** | Overview | stacked bar with its table; one category only; no alerts in the window |
| `VoiceTag`, `Keycap`, `Chip`, `Notice` | Everywhere | static |

Keyboard: every action has a visible control. Single-key shortcuts act only outside text fields and can be switched
off (command palette, "Single-key shortcuts"), which is what WCAG 2.1.4 asks; the product also needs the remap
setting. Focus is always visible (2 px ring), row targets are at least 24 px high, buttons at least 28 px (32 px on a
phone, 44 px in the decision bar). Status changes are announced through one live region.

## 4. Token changes against `src/lg_front/src/theme/tokens.css`

Names and format (RGB triplets) are unchanged. The prototype's `:root` block can be pasted over the token file.

### Changed values

| Token | Dark today | Dark proposed | Light today | Light proposed | Why |
|---|---|---|---|---|---|
| `--c-canvas` | `#0A0E13` | `#14181E` | `#F5F7FA` | `#FBFCFD` | Content now sits on the canvas, not on cards. Graphite instead of near-black lowers glare over a shift. |
| `--c-sidebar` | `#0D1218` | `#0F1317` | `#EDF0F4` | `#F1F3F6` | The rail is the only surface darker than the page. |
| `--c-raised` | `#10151C` | `#1B2028` | `#FFFFFF` | unchanged | Used for popovers and the decision bar only. |
| `--c-raised-2` | `#161D27` | `#222935` | `#F0F2F6` | `#EEF1F5` | Hover and chips. |
| `--c-selected` | `#1A2433` | `#1A2D4E` | `#E1EAF8` | `#E3EBFA` | Now derived from the brand accent (24% and 12% over the canvas). |
| `--c-subtle` | `#1C232D` | `#262D38` | `#E2E6EC` | `#E3E7ED` | Hairlines carry the structure, so they need to be seen. |
| `--c-strong` | `#2A3442` | `#343D4B` | unchanged | unchanged | |
| `--c-control` | `#647084` | `#6F7B8F` | unchanged | unchanged | Keeps 3:1 on the lighter dark surfaces. |
| `--c-body` | `#C4CBD6` | `#C9D0DA` | unchanged | unchanged | |
| `--c-muted` | `#838D9C` | `#8E98A8` | unchanged | unchanged | Keeps 4.5:1 on `raised-2` and on a selected row. |
| `--c-tint-*` (dark) | `#2A1619` `#271F0E` `#0F2419` `#14213A` | `#2E1A1D` `#2B2310` `#13281D` `#18263F` | unchanged | unchanged | Follow the lighter canvas. |
| `--c-accent`, `--c-accent-hover`, `--c-on-accent`, `--c-link`, `--c-focus` | literals | `var(--brand-*)` | literals | `var(--brand-*)` | Same default values; they now read the brand. |

`--c-eyebrow` folds into `--c-muted`. Severity, state, feedback and `--c-link-hover` keep today's values. The selector
changes from "dark by default" to: light on `:root`, dark under `@media (prefers-color-scheme: dark)` guarded by
`:root:not([data-theme="light"])`, and dark again under `:root[data-theme="dark"]`.

### Added

| Token | Light | Dark | Use |
|---|---|---|---|
| `--brand-accent`, `--brand-accent-hover`, `--brand-on-accent` | `#2F6FE4`, `#2560CC`, `#FFFFFF` | same | The one colour an MSSP sets |
| `--brand-link-light`, `--brand-link-dark` | `#1D57C7` | `#8AB6FF` | Derived from the accent when the brand is saved |
| `--brand-selected-light`, `--brand-selected-dark` | `#E3EBFA` | `#1A2D4E` | Derived: accent at 12% and 24% over the canvas |
| `--c-observed` | `#F2F4F8` | `#0E1116` | Surface of an observation |
| `--c-mark`, `--c-mark-fg` | `#FFE58A`, `#0E141B` | `#5A4700`, `#FFEBB0` | The highlighter inside an observation |
| `--c-data-1` to `--c-data-4` | `#2A78D6` `#1BAF7A` `#6250D6` `#6B7585` | `#3987E5` `#199E70` `#9085E9` `#9AA4B2` | Who or what closed an alert: AI, suppression rule, earlier verdict, a person. "On the model's word" is `data-1` hatched. |
| `--row-h` | 24, 28 (default), 44 px | | Row density |
| `--r-control` | 3 px | | Corner radius of controls; surfaces have none |
| `--rail-w`, `--top-h` | 220 px, 48 px | | Shell |

### Contrast (WCAG 2.2: text 4.5:1, controls and marks 3:1)

| Pair | Light | Dark |
|---|---|---|
| `fg` on canvas / raised / selected | 18.0 / 18.5 / 15.5 | 14.8 / 13.6 / 11.4 |
| `body` on canvas / observed | 13.0 / 12.1 | 11.5 / 12.2 |
| `secondary` on canvas / observed / selected | 7.7 / 7.2 / 6.6 | 8.1 / 8.6 / 6.3 |
| `muted` on canvas / sidebar / raised-2 / observed / selected | 5.6 / 5.2 / 5.1 / 5.3 / 4.8 | 6.1 / 6.4 / 5.0 / 6.5 / 4.7 |
| `link` on canvas / raised-2 / selected | 6.3 / 5.7 / 5.4 | 8.7 / 7.1 / 6.7 |
| `control` on canvas / raised-2 | 3.6 / 3.3 | 4.2 / 3.4 |
| `on-accent` on accent | 4.65 | 4.65 |
| `mark-fg` on `mark` | 14.8 | 7.6 |
| Severity marks on canvas: critical, high, medium, low, info | 4.8, 4.3, 4.0, 4.6, 4.5 | 6.4, 8.7, 11.9, 8.6, 7.1 |
| Severity marks on raised-2 (lowest: medium) | 3.6 | 9.8 |
| State marks on canvas: waiting, approval, ok, bad | 4.1, 5.2, 4.5, 5.1 | 9.7, 7.5, 10.5, 7.9 |
| `danger-fg`, `warn-fg`, `ok-fg` on their tints | 6.2, 6.8, 5.8 | 9.7, 11.2, 10.8 |
| Data marks on canvas: 1, 2, 3, 4 | 4.3, 2.7, 5.6, 4.5 | 4.9, 5.2, 5.7, 7.1 |
| Brand presets, white on accent: blue, teal `#0F766E`, rust `#B4471B` | 4.65, 5.47, 5.44 | same |
| Brand presets, link on canvas | 6.3, 6.3, 6.3 | 8.7, 10.0, 9.5 |

`--c-data-2` is under 3:1 on the light canvas. It is only used in the stacked bar, where every segment is also a
labelled table row and segments are separated by a gap; the colour never carries the category alone. The three data
hues were checked for colour-vision deficiency as neighbours (worst pair ΔE 17 dark, 23 light).

`src/theme/tokens.test.ts` must gain the new pairs, and must run on a brand's derived values when a brand is saved:
a failing accent is refused with the failing pair named (shown on `#shell`).

## 5. What each screen element needs from the API

"Has" names the field in `docs/openapi.json`. "New" is something the backend must add. Field names in the New column
are proposals.

### Investigation

| Element | Has | New |
|---|---|---|
| Page title, severity, tenant, time | `AlertDetailOut.title`, `.severity`, `.tenant_id`, `.occurred_at`, `.source_name` | Tenant name on the alert (`tenant_name`), a readable reference (`ref`, for example `ALR-48213`) |
| Deadline, owner | `EscalationOut.sla_deadline`, `.assigned_to_email`, `.version` | |
| Outcome category | Partly: `AlertDetailOut.status`, `.disposition`, `EscalationOut.routing` | `outcome`: `ai_closed_evidence`, `ai_closed_audit`, `needs_review`, `needs_decision`, plus `outcome_reason` (code and sentence) |
| Verdict sentence | `EscalationOut.ai_reason`, `.ai_reason_source` (free text in `summary` today) | `investigation.summary` (typed, written for the reader), `investigation.summary_source` |
| "5 of 6 claims backed" | none | `investigation.check`: `claims_total`, `claims_backed`, `claims_rejected` (the checker report of #356) |
| Subject chips | `AlertDetailOut.entities_preview[]` (`EntityRefOut.kind`, `.value`), `.category` | ATT&CK techniques as a typed list; an entity filter on `GET /alerts` for the pivot |
| Track record | `GET /reports/blind-audit` and `/reports/accuracy` give tenant-wide rates | `GET /reports/outcomes?tenant=&outcome=&skill=&days=`: `decided`, `confirmed`, `overturned`, `min_samples`, per outcome and per skill |
| Claims | none (`summary.analysis.reasoning` is an untyped string list) | `claims[]`: `id`, `text`, `stance` (`malicious`, `benign`, `context`), `observation_ids[]`, `check` (`backed`, `rejected`, `unsupported`), `check_reason`, `indicator` (true when a skill rule fired on it) |
| Observations | `FindingOut`: `kind`, `target`, `source`, `status`, `checked_at`, `data` (no id) | `observations[]`: `id`, `title`, `tool`, `template`, `outcome` (`success`, `empty`, `failed`), `complete`, `rows`, `row_cap`, `input_sha256`, `output_sha256`, `excerpt` (lines with highlight ranges), `payload` (raw, on demand), `erased` |
| Highlight inside an excerpt | none | `excerpt[].marks[]` as character ranges, set by the query template, never by the model |
| Command explanation | none | `observations[].explain`: `decoded` and `decoded_by` (`code`), `parts[]` (`token`, `meaning`), `explained_by` (`model`) |
| Not established | none | `not_established`: `empty[]` (observation ids), `not_checked[]` (`what`, `why`), `unavailable[]` (`what`, `why`, `fix_href`, `kind`: `no_source` or `tool_failed`) |
| Steps | `GET /alerts/{id}/events`: `AlertEventOut.ts`, `.event_type`, `.node`, `.actor_type`, `.data` | `steps[]`: `ts`, `actor` (`code`, `model`, `check`, `policy`, `person`), `text`, `produced`; cost, tool calls and budget of the run; `chain_verified_at` |
| Proposed response | `GET /escalations/{id}/response-preview`: `PreviewActionOut.action_type`, `.target`, `.risk`, `.reversible`, `.irreversible_note`, `.inverse_action`, `.guardrail` (`PreviewGuardrailOut.verdict`, `.reason`), `.can_preapprove`, `.role_lock`, `.without_preapproval` | Reach on the preview (`blast_radius` exists on `ActionOut`, not on the preview); target detail (connector object, for example the device id) |
| Decision | `POST /escalations/{id}/decision`: `DecisionIn.decision`, `.notes`, `.approved_actions`, `.version` | `decision` value `needs_more_information`; the effect line needs `linked_ai_closed` (count) on the alert |
| Evidence record export | `GET /alerts/{id}/evidence` (`EvidencePackOut`, `.integrity.bundle_sha256`) | OCSF Detection Finding export and chain verification result (#356) |

### Queue

| Element | Has | New |
|---|---|---|
| Rows | `GET /escalations`: `EscalationOut.id`, `.alert_id`, `.alert_severity`, `.summary`, `.reason`, `.ai_reason`, `.sla_deadline`, `.assigned_to_email`, `.entities_preview`, `.rule`, `.source_name`, `.created_at` | Alert title on the row (`alert_title` exists only on `PlatformEscalationOut`), `outcome`, `case_key`, `tenant_name` |
| All tenants and groups | `GET /platform/escalations` (`PlatformEscalationOut.tenant_name`, `.overdue`) | The same list filtered by scope (`scope=all`, `group:<id>`, `tenant:<id>`); tenant groups as an object |
| Look-alike rows | `GET /escalations/groups`: `EscalationGroupOut.rule`, `.size`, `.escalation_ids`, `.earliest_sla_deadline` | Grouping by rule, source entity and finding (today by rule only); `group_id` on the row |
| Sort | `order` on `GET /escalations` (two fixed orders) | `sort` by deadline, severity, title, tenant, outcome |
| Saved views | none | `GET/POST /views` per user: name, scope, filters, sort, density; shareable by an admin |
| Preview | everything above | A light `GET /alerts/{id}/investigation?brief=1`: summary, first observation, counts of the three not-established kinds, action count |
| Claim, bulk claim, bulk decide | `POST /escalations/{id}/claim`, `/escalations/bulk/claim`, `/escalations/bulk/close` (`BulkCloseIn.decision`, `.notes`, `.propose_suppression`), `/escalations/bulk/propose-suppression` | Server-side check that a bulk close covers one look-alike group |
| View counts | `GET /alerts/counts` (`AlertCountsOut.by_status`), `DashboardOut.unassigned_escalations`, `.my_claimed` | Counts per saved view in the current scope |

### Case

| Element | Has | New |
|---|---|---|
| The case | `AlertOut.case_key` (text only), `EscalationOut.related_alert_ids` | `GET /cases/{key}`: `key`, `title`, `summary`, `status`, `owner`, `opened_at`, `opened_by` (`policy`, `person`), `link_reason`, `sla_deadline`, `tenant_id`, entity list |
| Alert rows | `AlertOut.title`, `.severity`, `.status`, `.occurred_at`, `.closed_at`, `.entities_preview` | Per alert: `closed_by` (`ai_evidence`, `ai_model`, `suppression`, `cached_verdict`, `analyst`), `closed_by_ref` (rule id, user, earlier decision), `close_reason` (sentence), `linked` (`related_threat`, from #369), `outcome` |
| Suppression detail | `SuppressionOut.name`, `.created_by`, `.expires_at`, `.created_at` | Last review date |
| Reopen | `POST /alerts/{id}/reprocess` (admin, no reason) | `POST /alerts/{id}/reopen` with `reason`; analyst may call it; the alert is marked never-close |
| Flag | none | `POST /alerts/{id}/flag` with `reason`; adds the alert to the next blind-audit sample |
| Timeline | `GET /alerts/{id}/events` per alert | `GET /cases/{key}/timeline`: merged, each entry with `actor` and a plain sentence |
| Pending response | `GET /actions?alert_id=` (`ActionOut.status`) | Filter by `case_key` |

### Approval inbox

| Element | Has | New |
|---|---|---|
| Action, target, risk | `ActionOut.action_type`, `.target`, `.risk_level`, `.connector`, `.params`, `.status`, `.created_at`, `.requested_by` | Target detail and a readable target for tickets |
| Reach | `ActionOut.blast_radius` (`BlastRadiusOut.target_kind`, `.scope_hosts`, `.executed_last_hour`, `.hourly_limit`, `.tenant_executed_last_hour`, `.tenant_hourly_cap`) | A sentence of consequence (`reach_note`, for example "used by 3 backup jobs") |
| Can it be undone | `ActionOut.reversible`, `.irreversible_note`, `.rollback` | |
| Guardrail, checked now | `ActionOut.guardrail` (`GuardrailOut.verdict`, `.reason`, `.evaluated`, `.approval_reason`), `.blocked_reason` | |
| Who may approve | derived from `.risk_level` and `MeOut.role` | `approval_role` and `notified[]` on the action |
| Alert context on the group | none on the action (only `alert_id`) | `alert`: `title`, `severity`, `outcome`, `case_key`, `summary`; `tenant_name` |
| Evidence as it stands | none | `evidence_now`: the decisive observation (id, excerpt, hash) and `changed_since_proposed[]` |
| Grouping, all tenants | `GET /actions` is per tenant | Scope on the list; `group_key` (same action type, alert, risk, guardrail result) for batch |
| Approve, reject | `POST /actions/{id}/approve`, `/reject` (the body carries no reason) | `reason` on both; the server stores `evidence_snapshot_sha256` with the decision; batch endpoint that accepts one `group_key` only |
| Autonomy per tenant | `TenantSettingsOut` (autonomy policy) | A one-line summary per tenant for the group header |
| Oversight figures | none | `GET /reports/oversight`: decided, outcome changed by the person, window (#375) |

### Overview

| Element | Has | New |
|---|---|---|
| Needs you now | `DashboardOut.my_claimed`, `.unassigned_escalations`, `.unassigned_breaching`, `.next_sla_deadline`, `.pending_approvals`, `.pending_approvals_total`, `.pending_approvals_by_risk` | Blind-audit items waiting (count of `GET /blind-audit/items`); all of it by scope |
| Closed without a person | `DashboardOut.alerts_total`, `.handled_without_human`, `.needed_human`, `.by_disposition`, `.window_hours` | `closed_by` breakdown (five kinds); decided count and median time for those that reached a person |
| Blind audit | `GET /reports/blind-audit`: `BlindAuditEstimate.labelled`, `.malicious`, `.false_negative_rate`, `.worst_case_rate`, `.min_samples` | |
| Planted attacks | none | `seeded`: `planted`, `closed_by_ai`, `supports_below` (#334) |
| Safety net | none | `reopened_after_confirmation`, `linked_left_closed` in the window (#369) |
| By tenant | `GET /platform/tenants` (`TenantSummaryOut`, `TenantStatsOut`) | Per tenant: needs a person, due under 15 min, approvals, closed without a person, overturned of audited (90 d), autonomy summary, last event per source |

### Shell

| Element | Has | New |
|---|---|---|
| User, role | `MeOut.email`, `.role`, `.is_platform_admin`, `.tenant_id`, `.home_tenant_id`, `.tenant_name` | Display name; `modules[]` (licensed services) and `module_status` (`ok`, `unavailable`); acting-as delegation |
| Scope | `GET /platform/tenants` | Tenant groups; scope in the URL (`/s/all`, `/s/g/<group>`, `/s/<tenant>`), restored on load |
| Search | title search on `GET /alerts` | `GET /search?q=&scope=`: entities, alerts, cases, with counts; pages and commands come from the module manifest |
| Notifications | none (live WebSocket events exist) | `GET /notifications`: kind, sentence, tenant, link, read state |
| Brand | none | `brand`: `name`, `logo_url`, `accent` in runtime config; derived values computed and contrast-checked on save |
| Rail counts | `DashboardOut` | A count hook per module (review, section 4.4) |

## 6. Checks

`screenshots.cjs` loads every screen in both themes at 1440 and 390 px and fails loudly on a page error, a console
error, any request that is not `file:` or `data:`, or sideways overflow of the page. It also drives the keyboard
path (J, Ctrl+K, X, Enter, V, T) and counts the queue rows that fit in 1440 by 900: 24 at the default density, 28
dense. Run it with the frontend's Playwright:

```
node docs/design/console-v2/screenshots.cjs src/lg_front/node_modules docs/design/console-v2/console-v2.html docs/design/console-v2/screens
```

Not checked here and left for the build: axe on the real components, a screen reader pass, focus order through the
inline reason row, and the queue with thousands of rows (the prototype renders 28).

## 7. Limits of the prototype

* The content is invented. Figures are consistent with each other but measure nothing.
* Only `#investigation` for ALR-48213 is drawn in full; every queue row opens it.
* Rail items without a screen say so when clicked.
* Fonts are the latin subsets of Inter and JetBrains Mono (SIL Open Font License 1.1), the same `@fontsource` files
  the product ships, embedded as data URIs at the end of the file.
