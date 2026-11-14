# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Wazuh evidence tools (`lg_sotf.tools.wazuh`, INT3.4): four registered
  tools that read what surrounds an alert on the tenant's own Wazuh indexer
  and answer with typed evidence facts (schema 1.1). The analysis does not
  call them yet; the investigation executor uses them in a later release.
  - `wazuh.host_activity`: what a host's alerts show around a moment (up to
    60 minutes before and after): counts by rule group and technique, the
    highest rule level, and the 50 highest alerts.
  - `wazuh.logon_fanout`: every logon of one source address, source host,
    user or target host over up to 24 hours: failures, successes, lockouts,
    distinct users, sources and hosts, and the time from the first failure
    to the first success after it. Windows and sshd. A caller cannot narrow
    it to an outcome or a logon type, so a fact never reports zero for what
    it did not read. Windows user and host names are matched and counted
    whatever case they were typed in.
  - `wazuh.process_lineage`: a process's parents (up to 8) and what it
    started, down to what its children started. Name the process by its
    GUID when the alert has one; an image gives one fact per process that
    matches, and none is complete when there are several.
  - `wazuh.prevalence`: on how many of the tenant's agents a file hash, a
    process image, a service's image path or a service name was seen over up
    to 30 days.
  - The tools are query templates. A caller gives typed, bounded values and
    never a query, a field or an index; every search is checked against an
    allow-list before it is sent, and the only request the client can make
    is `POST /<index>/_search` on the index pattern of the Wazuh source the
    alert came from, with that source's credentials, through the install's
    destination rules. Only the scheme, the host and the port of the
    source's `base_url` are used: for the tools, a `base_url` with a path or
    a query is refused. They need the permission the pull source needs and
    nothing more. Switch them off for a tenant with
    `tools.wazuh_indexer.enabled: false`.
  - A call that finds nothing is `empty`. An indexer that is down, refuses
    the credentials, answers only part of a search that matched nothing, or
    holds no index for the pattern is `failed` with a fixed reason; so is
    any answer but an HTTP 200, and a response without an aggregation that
    was asked for. A fact is `complete` only when every shard answered
    every search, no cap cut what the fact lists or how far a process's
    parents were followed, its time window had closed and the index reached
    back to the window's start.
  - Limits found on a Wazuh 4.14 indexer are in docs/evidence-facts.md:
    process lineage needs the manager to raise Sysmon process creations, a
    file hash is searched in file-integrity events only, and values are
    compared whole and case-sensitively.
- The offline event store answers the same tools
  (`lg_sotf.eval.wazuh_events.EventStoreBackend`), so evaluation and tests
  get the facts from the corpus telemetry. A live test checks that a Wazuh
  4.14 indexer gives the same facts.

- **The case page** (`/cases/<id>`): one case, its alerts, and who or what
  closed each one and why. A case is the escalation with its alerts, and its
  id is the escalation's id. The page answers "what did the AI close on this
  host while this case was open, and why" in one place.
  - **Alerts, oldest first,** each with its state and who closed it: the AI
    on approved evidence, the AI on the model's word, a suppression rule, an
    earlier analyst verdict, or an analyst. Beside it is the recorded
    reason: the rule of the decision policy and the closure tier for an AI
    close, the blind-audit result, the analyst's decision and note.
  - **Linked by the safety net:** alerts the AI closed that were linked to
    the case and left closed, with why; and alerts that were reopened, with
    who or what confirmed the threat.
  - **Response:** the actions on the ledger with their status (waiting for
    an approval, blocked by a guardrail with its reason, ran, failed, dry
    run). An action that waits is approved or rejected here, by the rules of
    the Approvals page.
  - **Timeline and entities:** the case's and its alerts' events in one
    list, in plain words, and what the alerts share (hosts, users, addresses).
  - **Decision:** the decision bar of the investigation view records the
    decision on the case (T, B, F, N, a note, Ctrl+Enter). J and K move
    through the alerts and Enter opens one; they follow the single-key
    switch.
- `GET /api/v1/cases/{id}` (beta): the read model behind the page. It only
  reads stored data. `not_available` names what the stored data cannot say
  yet (a readable case reference, a case summary, flagging an alert for
  audit, a reason on an approval), and those fields are absent, never
  estimated. An alert that waits for its blind-audit label shows what its
  source sent and nothing of the AI's side.

### Changed

- A tool can now say that its answer was cut (`Tool.whole` in the tool
  registry): a result is `complete` only when it is below its row cap and
  the tool does not say a cap inside the source, an open time window or the
  source's retention cut it.
- INV-14, "Evidence tools are read-only, templated and capped", is now
  enforced: it was pending until the Wazuh templates and their allow-list
  tests existed.
- A shadow run may read the tenant's own Wazuh indexer through the evidence
  tools. It is the second reviewed read a shadow run is allowed (after the
  local health listener): it tells no third party anything and changes
  nothing. Every other outbound request of a shadow run is still refused.

- A row of the **Queue** opens the case page. The older decision page
  (`/escalations/<id>`) still opens from the Escalations list and from
  existing links.
- The investigation view names the alert's case in its breadcrumb, as a
  link to the case page, also for an alert the safety net linked to a case.

- The README describes the product as it ships in 1.3: only the latest release is listed as new, the capabilities of earlier releases are under Features, and both diagrams follow the workflow graph and the 1.3 closing rule. The product tour is re-recorded on console v2 and the pictures of the previous console are replaced.

## [1.3.0] - 2026-11-14

Three things change for an operator in this release.

- **The AI can close the alerts it judges benign.** Each tenant chooses
  (`ai_closure.tier`, `off` by default). Critical alerts and a fixed list of
  never-close classes always go to a person. Every such close is marked for
  audit, a blind audit measures what was missed, and a safety net links
  AI-closed alerts to a later threat's case and reopens them once that
  threat is confirmed.
- **The console is rebuilt on the console v2 design**: a new shell (menu,
  tenant in the address, search and commands), a new look on every page, a
  new Overview, a work queue, and an investigation view that explains the
  AI's decision.
- **The investigation has its foundations**: a stored trace of every model
  and tool step, a tool registry with typed outcomes, the evidence-fact
  schema 1.1 and telemetry for the evaluation corpus.

Also new: the MSSP organisation model with grants the customer holds, a
first-run setup wizard and proof-of-value runs, shadow mode to compare a
candidate model with production, signed images, release trains, and upgrades
that CI rehearses on every change. Read
[Upgrade notes for 1.3](#upgrade-notes-for-13) before you upgrade.

### Added

#### AI closure of benign alerts (decision policy v3)

- **A per-tenant autonomy tier**, `ai_closure.tier` in the tenant settings:
  `off` (the default) or `auto_full_audit`. With the tier `off`, nothing
  closes on the models' word alone. At `auto_full_audit`, an info, low,
  medium or high alert that the deep analysis judges benign closes on the
  models' word, at any certainty and below the response policy's threat
  score, unless the fast tier called it a likely or confirmed threat. Only a
  tenant admin can change the tier, never under an MSSP grant, and the audit
  event records the tier set.
- **What never closes on the models' word**, at any tier:
  - critical alerts;
  - credential access, by ATT&CK tactic or technique (T1531 included, where
    Wazuh maps its Windows logon failures) or by the vendor's own
    authentication-failure rules: a Wazuh rule in the groups
    `authentication_failed`, `authentication_failures`, `invalid_login` or
    `login_denied`, and the rules 6250 (Asterisk) and 44733
    (FortiAuthenticator). ATT&CK tactics are matched whatever their
    spelling, so Sentinel's `CredentialAccess` counts like Wazuh's
    `Credential Access`;
  - log clearing, security-tool tampering and ransomware behaviour;
  - persistence through an object the attacker creates and names (scheduled
    tasks, services, autostart entries, WMI subscriptions, accounts);
  - a Wazuh alert whose rule cannot be read, or whose groups list had to be
    cut. The workflow state keeps the vendor rule (`raw.rule`: id, level,
    description, groups, ATT&CK) when an oversized raw event is dropped;
  - an alert with text written to steer a model;
  - an alert whose entities have a recent true positive: an
    analyst-confirmed malicious history, a related alert closed as
    malicious, or rule evidence of a threat;
  - an alert a model normalised, and an alert the safety net reopened;
  - a verdict the rules produced because a model was not consulted.
- **Every such close is marked.** It has the decision code `model_closed`
  and the close reason `ai_closed:audit_required`, so an analyst can find
  and audit every one. A related alert the models closed alone is shown to
  later models as `ai_closed_unaudited`, never as `benign`, so one persuaded
  close cannot vouch for the next.
- **A catalogue of routine Wazuh noise**, reviewed and versioned, keyed by
  vendor and detection rule id: package installs and updates (dpkg 2901,
  2902; yum 2932, 2933), Windows software installs (60612), Defender scan
  and signature status (62107, 62108, 62130) and a single web 4xx (31101).
  When the catalogue knows the rule, the close's decision reason names the
  family and the catalogue version. The catalogue reads only the rule id of
  the vendor's own event, and only on an alert the Wazuh normalizer built:
  never the title, the description or rule-name text.
- **The safety net.** When an alert becomes a threat, the platform looks at
  every alert the models closed alone in the previous 24 hours that shares a
  host, user or address with it.
  - *A model judged the threat* (an escalation a model judged a threat, a
    response the workflow only proposes or, in dry-run mode, only
    simulates): the AI-closed alerts are **linked** to that threat's case.
    They are listed in the case as related alerts, marked `linked` and
    audited `alert.linked`. They stay closed. A benign decision on the case
    leaves them closed by AI and due for audit, and their evidence pack and
    NIS2 draft show no analyst decision. A merely *suspicious* alert is a
    doubt, not a threat, and links nothing.
  - *The threat is confirmed*: the AI-closed alerts are **reopened**,
    including the ones linked earlier, however long ago they closed. A
    confirmation is an analyst true positive, an analyst's own approval of a
    response action (console or Slack), a blind-audit malicious label, or a
    response action that really ran when the workflow carried it out alone
    under your autonomy policy. A dry run is a simulation and confirms
    nothing.
  - A reopened alert is folded into the threat's open case: attached as a
    related alert and set to `waiting_human` under that one case (no new
    run, no new escalation), and the analyst's decision on the case settles
    it. Without an open case it is queued for its own review run at once. It
    is audited `alert.reopened` (reason `related_threat`) and never closes
    on the models' word again.
  - Metrics: `lgsotf_retro_linked_total` (by `path`),
    `lgsotf_retro_reopened_total` (confirmed reopens only, by `path`) and
    `lgsotf_retro_reopen_failures_total`.
- **Blind audit of auto-closed alerts.** A uniform random sample of the
  alerts automation closed goes to analysts with the AI verdict hidden, so
  the production false-negative rate can be measured without bias.
  - Analysts label each sample malicious, benign or unsure on the new Blind
    audit page (keys M, B, U and N); only then is the AI's verdict,
    confidence, routing and reasoning shown, with the agreement. A malicious
    label opens a normal escalation for the alert; deciding it re-triages
    the alert with the analyst's decision.
  - From the moment an alert is sampled until it is labelled, its verdict is
    withheld from everyone in the tenant: the alert routes and MCP (alerts
    carry `hidden_for_blind_audit`), its timeline (ingestion and notes
    only), its escalations, response actions and audit details, its evidence
    pack and live updates. It cannot be reprocessed, and it is left out of
    the value, detection and dashboard figures and of other alerts'
    correlation. Blindness starts at sampling: earlier views and exports
    showed the verdict like any alert's.
  - Samples are drawn every week when the tenant setting `blind_audit` is on
    (2% of auto-closed alerts, at least 5 a week by default; off until
    enabled), on demand with `lg-sotf audit-sample --tenant T` (also the
    proof-of-value random sample, for example `--size 200`), or from the
    Blind audit page. Runs follow each other without gaps, end 5 minutes
    before now, and use a seed the server picks and records; `--dry-run`
    re-draws a run with a given seed and records nothing.
  - Reports > Blind audit and `GET /api/v1/reports/blind-audit` show the
    false-negative rate among auto-closed alerts, stratified over the
    sampling runs, with its 95% interval and sample size, the estimated
    number of missed threats, a worst case counting unsure and unlabelled
    samples as malicious, an "incomplete" mark until every sample is
    labelled, uncovered time, labels by organisation for MSSP grants, and
    "Not enough data (n=…)" below 30 labels. New beta endpoints under
    `/api/v1/blind-audit`. Migration `0014`.

#### Console v2

The console follows the console v2 design (`docs/design/console-v2/`).

- **The shell**, the frame every page lives in.
  - *The rail.* Pages are in five groups: Work, Detect and respond, Assure,
    Configure and Platform. The Queue is where work waits; the older
    Escalations list left the rail (its address `/escalations` still works,
    and the decision page leads back to the queue unless you came from that
    list). Three entries have the design's names and open the same pages as
    before: "AI usage and cost" (LLM usage), "People and keys" (Users and
    API keys) and "Tenants" (MSSP console). Counts are plain numbers next to
    a page's name, the signed-in person is at the bottom (account security,
    row density and sign out are in their menu), and on a narrow screen the
    rail opens from the menu button. No page moved to another address.
  - *The tenant is part of the address.* A platform admin chooses the tenant
    to work in with the control at the left of the top bar, and the address
    becomes `/s/<tenant>/...`. A reload, a new tab and a shared link now
    open the same tenant; before, they fell back to the home tenant without
    saying so. Someone who has one tenant and opens another tenant's address
    is told so and shown nothing under it.
  - *Search and commands.* One field in the top bar, also opened with Ctrl+K
    (Cmd+K) or `/`, finds pages, alerts by title, and (for a platform admin)
    tenants. Each alert says which tenant it is in. `>` lists commands. A
    command that changes something never runs from the field: it opens the
    page where the act is confirmed. The `/` key can be switched off with
    the command "Single-key shortcuts".
  - *Notifications.* The bell lists only what needs an act now: escalations
    past their deadline, a deadline in the next 15 minutes, actions waiting
    for your approval and, for admins, a source the API reports as failing
    or degraded. Each line names the tenant and opens the page where the act
    happens.
  - *Brand.* The console's name, logo and one accent colour come from one
    `brand` object in the runtime configuration (`/config.js`). The accent
    is checked for contrast before it is used; one that fails is refused
    with the failing pair named, and the product's colours stay.
  - *A service that is not licensed.* A service module can declare a group
    of its own in the rail. Where the licence does not include it, a
    platform admin sees the group locked and labelled "Not licensed", with a
    page that says so; a customer tenant's users do not see it. No second
    service is shipped yet.
  - The top bar no longer repeats the page's name; the browser tab names the
    page and the console.
- **The look**, on every page at once.
  - *A flat sheet.* Content sits on the page and hairlines carry the
    structure; sections have a title over a rule and no box. The dark theme
    is graphite, not black.
  - *Denser lists.* A row is 28 px by default (it was 44 px) and 44 px with
    "Comfortable rows" (it was 56 px), so the alert list shows about half as
    many rows again on a screen. Buttons and fields are 28 px high, 24 px
    inside a table row, and still grow to 44 px on touch screens.
  - *Severity is four bars and the word*, critical and high in bold; it was
    a coloured square. A state is a mark whose shape says what kind it is
    (waiting, waiting for approval, running, done, failed) and the state in
    words; it was a grey pill with a coloured dot.
  - *Labels read as sentences.* A status such as `waiting_human` reads
    "Waiting human", not "Waiting Human". The words are written by the app,
    not title-cased by the stylesheet, so a screen reader and a copy get the
    same text as the screen.
  - What a tool returned (JSON, an observation) is monospace on a recessed
    surface with a double rule on its left; toasts appear at the bottom
    centre.
  - *The theme follows your system setting by default.* It was dark by
    default. The control in the top bar steps System, Light, Dark, and your
    own choice is remembered as before.
- **The Overview**, flat and in a new order.
  - *Needs you now* comes first, one line and one action each: what you hold
    and its first deadline, the response actions your role may approve, what
    nobody has claimed, and the sampled AI closes waiting for a blind-audit
    label. An item opens its investigation view.
  - *Closed without a person* says in one sentence how many of the window's
    finished alerts no person touched and how many reached one, with a bar
    and the table it is drawn from.
  - *How the AI's closes are verified* shows the blind audit of the last 30
    days: closes eligible, sampled, labelled, and labelled malicious by an
    analyst who could not see the AI's verdict, with the missed-threat rate
    and its 95% interval once the sample carries one.
  - Then the next deadlines and, for admins, platform health. The severity
    strips and the six window tiles are gone; alerts by status moved into
    platform health.
  - Every figure says what it counts and over which window, and a share, a
    rate or a mean over too few observations is withheld in words. A figure
    the API does not report yet (who or what closed each alert, planted
    attacks, the safety net) reads "not measured yet" and shows no number.
  - On a phone the Overview's tables become stacked records, so nothing
    scrolls sideways.
- **The work queue** (`/queue`): one dense list of what needs a person,
  soonest deadline first.
  - *More on one screen:* 22 rows at 1440 by 900 in the default density (25
    in Dense), against 6 to 7 on the Escalations page. Three row densities
    (Dense, Compact, Two lines), remembered per user.
  - *Each row* shows the deadline (overdue and under ten minutes are marked
    in words), the severity, what the item is and why it needs a person, and
    what the analysis made of it so far.
  - *Views* are tabs with counts: Needs a person, Mine, Unassigned, Deadline
    under 15 min, Likely malicious. "Save view" keeps the current view,
    filters and density under a name, per user in the browser.
  - *Preview:* the highlighted row opens beside the list, which stays in
    view.
  - *Keyboard:* `J` and `K` move, `Enter` opens the item, `Space` shows or
    hides the preview, `X` selects, `C` claims.
  - *Bulk:* selected rows can be claimed together. Deciding several at once
    is offered only for look-alike alerts, which the API does not group yet,
    so the Look-alikes view stays hidden until it does.
  - The queue shows the tenant you are acting on.
- **The investigation view**: every alert opens on a full page
  (`/alerts/<id>`, "Open full page" in the alert's side panel) that explains
  the AI's decision in the same order for every alert.
  - First the outcome, in one of four categories tied to what happens next
    (closed by AI; closed by AI, sampled for audit; needs your decision:
    likely malicious; needs your decision: unsure), the verdict as a
    sentence, and why the alert is with a person or why it was closed: the
    closure policy's blockers, or the approved benign signals the rules
    found, and who or what closed it (the AI, a suppression rule with its
    name, a cached analyst verdict with the earlier alert it came from, or
    an analyst), with the time.
  - Then the alert's description and its entities; the claims of the
    analysis, each beside what the lookup it names returned; what is not
    established, in three kinds (checked and found nothing, not checked,
    could not check for this customer); the steps of the investigation in
    plain words; and the response as it stands, with the exact target of
    every action.
  - The page keeps three voices apart: what a tool returned, what the model
    wrote, and what a check, the policy or a person decided. A claim that
    names no lookup, or only a lookup that returned nothing, is marked
    **Unsupported**: nothing found is never counted as proof.
  - The **track record** of the alert's outcome is shown as counted squares
    ("Analysts confirmed 31 of 34 alerts sent to a person as likely
    malicious"), a bar above 60 alerts, and the words "too few for a rate"
    under 30. Never a percentage.
  - Each observation shows its sources, its verdict and, where the trace
    store has the call, its hash.
  - A decision bar stays at the bottom of the page. `T`, `B` or `F` chooses
    the verdict, the bar says what that verdict sets in motion (which ticked
    actions run, how many wait for approval) before anything is recorded,
    and `Ctrl+Enter` records it and opens the next escalation. **Needs
    more** (`N`) records `needs_more_info`: the bar asks for a note and says
    that no verdict is recorded, the analysis runs again and reads the note,
    the alert comes back to an analyst as a new escalation, and no response
    action runs. Single-key shortcuts act only outside text fields and can
    be switched off; the choice is kept per user on the browser.
  - **Hide the verdict** (`V`) withholds the verdict, the claims and the
    model's assessment so you can judge from the evidence first; an alert in
    a blind-audit sample always opens this way.
  - An entity chip (host, user, address, domain, hash) opens the alert list
    searched for that value. The search is the list's title search over the
    last 30 days; the API has no entity filter yet.
  - "Not yet available" is said only for what the read model lists as
    pending: highlight ranges, the model's citations and the checker's
    verdicts. How many hosts or users an action reaches is not shown until
    the API returns it.
  - An API that does not serve the read model yet (it answers 404) still
    gets the page: it is built from the alert, its escalation, its timeline
    and the response preview.
- **The decision page** shows the expected response plan under the
  investigation, so "Record decision" stays in view, and the form says how
  many actions are pre-approved. Every action in the plan names its exact
  target (the process, host, user or address), next to its risk and whether
  it can be undone. An action the plan sends without a target cannot be
  pre-approved there: it says why and is left for the Approvals page.
- **The investigation read model**, `GET /api/v1/alerts/{id}/investigation`
  (beta), is what the investigation view reads. It only reads stored data:
  it calls no model and writes nothing.
  - *Outcome:* one of the four categories, the reason in plain words, why
    the AI may not close the alert on its own, and who or what closed it.
  - *Summary, claims and observations:* the conclusion, marked as written by
    the model or by the rules; each claim with what it points to and the
    lookups it rests on; each lookup with a typed outcome (`success`,
    `empty`, `failed`), a bounded excerpt and, where the trace store has the
    call, its input and output hashes. An empty or failed lookup never backs
    a claim.
  - *Steps, track record and response:* what the investigation did; how
    often people confirmed this outcome category for the tenant over 90
    days, as counts, with a rate only from 30 verdicts on; and the proposed
    actions with their exact targets.
  - `pending_harness` names the fields that stay empty until the
    investigation harness fills them.
  - Text an attacker can shape (claim texts, targets, excerpt lines) is
    returned as data, cut to a stated length, and never put into a sentence.
    An alert that waits for its blind-audit label shows nothing of the AI's
    side.
- Each page has its own error screen, so an error on one page no longer
  replaces the whole app. When a new version has been deployed and an old
  page bundle can no longer be loaded, the page says "A new version is
  available" and offers a reload.

#### Investigation: trace, tools and evidence

These are the foundations of the investigation harness. In this release the
analysis agent's own lookups run through them; the Wazuh evidence tools are
not part of 1.3.0.

- **An investigation trace.** Every model call and every
  threat-intelligence or history lookup of an alert's investigation is
  stored, in order, with the prompt and model (or tool), token counts,
  latency, outcome and the SHA-256 of what went in and came out, plus a
  redacted, size-capped digest of the result. Evidence packs show the steps
  in a new **Investigation trace** section (HTML) and under `investigation`
  (JSON). The trace is kept and deleted with its alert, and is part of the
  tenant data export. Migration `0011` adds the `investigation_steps` table.
- **Prompt versions.** Every model call records which prompt version it
  sent. Each prompt has a name (such as `triage.assess`) and a short hash of
  its text and output schema, so a changed hash means the model was asked
  something different. The alert's model provenance, evidence packs, the
  `llm.call` log event and evaluation reports show the prompt name and hash
  next to the provider and model.
- **A tool registry** (`lg_sotf.tools.registry`). Every lookup the analysis
  agent makes is a declared tool called through one registry. A tool does
  not load without a read-only risk class (there is no write class), a
  strict and bounded parameter model, row, time and window caps and a
  declared egress. Every call validates its parameters first, enforces the
  caps, holds the tool to the egress it declared and is recorded in the
  trace.
  - The VirusTotal and AbuseIPDB lookups (`reputation.<provider>`) and the
    alert-history lookup (`platform.history`) run through it.
  - Every tool result carries a typed outcome: `success`, `empty` (the query
    ran and matched nothing) or `failed` (refused, timed out, raised, over
    the row cap, or no answer from the source). A failed call can no longer
    be mistaken for "no rows". `complete` is false when a result holds as
    many rows as its cap.
  - The trace stores the same outcome for the step (migration `0018`). A
    history lookup that finds no earlier alert is now stored as `empty`, not
    `success`.
  - Every tool result carries the SHA-256 of its input and of its output:
    the hashes of its stored trace step. The output hash no longer changes
    when the same answer comes from the cache.
- **The evidence-fact schema 1.1**, a published contract for the typed
  observations investigation tools return, which verdicts will cite by id.
  It is a JSON Schema 2020-12 file with a SemVer version,
  `schemas/evidence-fact/v1.json`, with an example per kind, and CI refuses
  a change that is not matched by the right version bump. It covers IP,
  domain, URL and file reputation, process lineage (with `children`, the
  processes a process started), sign-in history, related alerts,
  `host_activity` (what a host did around an alert), `logon_fanout` (how
  many accounts, sources and hosts a logon pattern touched) and `prevalence`
  (how widely a file, an image, a service or a command is seen). `complete`
  is false when the source cut a result or its time window had not closed,
  so that "nothing was found" is never read from a partial answer. Every
  list holds at most 50 items and every text field has a maximum length. The
  tools that produce the host, logon and prevalence facts come in a later
  release. See docs/evidence-facts.md.
- **Telemetry for the evaluation corpus.** An investigation needs what
  surrounds an alert, and `corpus_v1` held alerts only.
  - `corpus_v1_events.jsonl.gz`: 291 context events around the corpus alerts
    of the Windows logon-failure and service-install families.
  - `corpus_skills_v1.jsonl.gz`: 196 labelled alerts of those two families
    with their own context events. 28 are context-abuse attacks that sit
    inside what the tenant declared: a spray from the admin workstation,
    PsExec by an admin account followed by discovery, an "updater" service
    outside the patch window, a service account used interactively.
  - Gold evidence for both (`*_gold.json`): per item, the benign hypothesis
    the telemetry supports, the malicious indicators and never-close
    conditions that are true, and the documents they rest on.
  - `lg_sotf.eval.tool_fixtures.EventStore`: an in-memory store of a
    dataset's alerts and events that answers indexer-style queries as of a
    moment, so a replayed investigation never sees the future.
  - `scripts/load_corpus_telemetry.py` loads the telemetry around chosen
    corpus items into a lab's Wazuh indexer with timestamps moved to the
    present. The indexer URL and credentials come from the environment and
    are never printed, and the script refuses a host that was not passed
    with `--host`. See docs/evaluation.md.
- **Safety invariants.** `lg-sotf verify-invariants` checks this install's
  safety invariants, read-only, in a synthetic dry-run tenant: forced
  row-level security on every tenant table, a runtime role that cannot
  bypass it, an append-only audit log, the response kill switch, the routing
  policy for high-severity alerts, log redaction and evidence-pack sealing.
  It exits 1 when a check fails; `--json` prints the results as JSON.
  `docs/invariants.md` lists the invariants, each with its rationale, owner,
  threat-model rows and the tests that prove it: twelve are enforced, and
  two are registered as pending until their stories merge (INV-13,
  "Autonomy is earned per skill and tenant and lost on any miss", and
  INV-14, "Evidence tools are read-only, templated and capped"). CI fails
  when a named test is missing or an enforced invariant's test is skipped.

#### MSSP organisations and delegated access

- **Organisations and grants.** A tenant can be an MSSP *organisation* with
  named staff members, and a customer tenant can give an organisation (or
  one of its members) a role in it, with a reason and an expiry of at most a
  year. Grants belong to the customer: only the customer can create or
  revoke them, the organisation can only read its own, and no other tenant
  sees them (row-level security). Migration `0012`. Tenant exports include
  `tenant_grants.jsonl`, `organisations.jsonl` and
  `organisation_members.jsonl`. See docs/mssp.md.
- **Reading under a grant.** A member of an organisation acts in a customer
  tenant by sending `X-Tenant-ID` with their own sign-in. Every read route
  serves the customer's data under the grant's role (capped at the member's
  own role) and answers 403 without a live grant. Revoking a grant takes
  effect on the next request.
- **Deciding under a grant.** An MSSP analyst acting under a grant can
  decide escalations (one at a time or with bulk close) and approve, reject,
  roll back, retry and verify actions, within the grant's role. Claiming an
  escalation and creating or changing users, MFA, API keys and grants stay
  refused under a grant. A platform admin's tenant switch still cannot claim
  or decide.
- **Two audit chains.** Every request under a grant is recorded in the
  customer's audit log (`grant.tenant_access`), and every audit entry
  written under a grant is recorded in both chains: the customer's, naming
  the organisation and grant, and the organisation's as `delegated.<action>`
  with the customer entry's id and hash. Giving and revoking a grant is
  audited in both chains too.
- **Live updates, automation and MCP.** `/ws?tenant=<customer>` streams a
  granted customer's events and closes when the grant is revoked or expires;
  an organisation's API key acts under a grant to the whole organisation
  with its scopes capped by the grant's role (never `ingest`);
  `LG_SOTF_MCP__TENANT_ID` pins the MCP server to one customer tenant.
- **Endpoints:** `PUT /platform/organisations/{tenant_id}`,
  `/organisation/members`, `GET /organisation/grants`, and `GET`/`POST
  /tenant/grants` with `POST /tenant/grants/{id}/revoke` for the customer's
  admins. `GET /auth/me` returns `grant_id`.
- A generated cross-tenant leak suite covers every API operation, MCP tool
  and the WebSocket channel. The limits on what a grant allows are under
  [Security](#security).

#### Onboarding and proof of value

- **A first-run setup wizard** for the install's admin (the platform admin
  `lg-sotf migrate` creates). Until setup is done the Overview invites them
  to it; five steps confirm the account, name the organisation and the first
  tenant, pick a language-model profile (an EU-hosted Mistral profile is
  preselected, local Ollama or your own model server are offered; the wizard
  shows the settings that select it and tests the model configured now),
  send the sample alerts and wait for the first verdict. It ends on the
  proof-of-value wizard. The wizard never changes the running model, which
  stays install configuration. API: `GET` and `PUT /onboarding/setup`, `POST
  /onboarding/setup/complete`, audited as `onboarding.setup_saved` and
  `onboarding.setup_completed`.
- **A proof-of-value install profile.** `scripts/pov.sh --siem-host HOST`
  (or `make pov SIEM=HOST`) starts a stack that can only read. Every
  response action is blocked or recorded as dry run, whatever a tenant admin
  sets; pull sources that mark or move mailbox messages are refused; and
  outbound connections go only to the SIEM host(s) and the model endpoint
  (local Ollama by default, or an EU-hosted endpoint). Helm users layer
  `deploy/helm/lg-sotf/values-pov.yaml`. See docs/pov.md.
- Two install-level settings behind that profile:
  `ingestion.allowed_destination_hosts`, an egress allow-list for sources,
  integrations, response webhooks, Microsoft Graph, enrichment providers and
  the LLM endpoint (unset by default, so nothing changes for existing
  installs), and `ingestion.read_only_sources`, which refuses the
  `m365_mailbox` and `imap` sources.
- **Proof-of-value runs**, started without the command line. An admin opens
  **Proof of value** > *New proof of value* (a three-step wizard: the days
  of history to replay, the days of shadow period, review and start) or
  calls `POST /api/v1/pov/runs` (beta). The scheduler then runs the backtest
  over the alerts analysts decided in the history window and stores its
  result on the run (alerts replayed, confirmed threats, how many the triage
  would have closed, with sample sizes and intervals); the shadow period
  that follows links the tenant's reports over its dates. `GET
  /api/v1/pov/runs` and `GET /api/v1/pov/runs/{id}` show the status; `POST
  /api/v1/pov/runs/{id}/cancel` ends a run early. A run only reads: it
  changes no alert, creates no escalation, response action or notification,
  and its backtest runs in read-only transactions. One run in progress per
  tenant, at most 3 created in 24 hours, 500 alerts per backtest. Migration
  `0019` adds the `pov_runs` table (tenant row-level security, in the tenant
  data export and erasure).
- **Guided Wazuh setup.** Sources > Connect Wazuh step by step checks a
  Wazuh connection before the source is saved and says what to change. For
  the indexer it checks, in order, the settings, that the install may reach
  the host and the indexer answers, the TLS certificate, the sign-in, the
  permission on the alerts index, the index itself and the clocks. A failed
  check names what is missing, for example the index pattern and the
  permission `indices:data/read/search`, the CA certificate, or the host to
  add to the PoV allow-list. For alerts pushed by the Wazuh manager it
  checks the push source and that the API key has the `ingest` scope. API:
  `POST /onboarding/connectors/wazuh/check` (the tenant's own admins, 20
  runs per tenant per minute), audited as `source.setup_checked`. See
  docs/onboarding.md.
- **Declared scanners and test files.** The tenant setting
  `triage.known_scanners` lists the host names, IP addresses or CIDR ranges
  of your own vulnerability scanners: an alert whose activity comes from one
  gets the `known_scanner` false-positive signal. Triage also recognises the
  EICAR anti-virus test file by hash (`eicar_test_file`).

#### Models

- OpenAI-compatible cloud APIs that refuse OpenAI's tool calling, such as
  DeepSeek's V4 thinking models, now work with the `openai` provider: set
  `llm.base_url` and `llm.structured_output: json_mode` (deploy variable
  `LLM_STRUCTURED_OUTPUT`). Replies are parsed as JSON with one repair
  attempt and metered under the provider's own model name. OpenAI itself,
  with no `llm.base_url`, keeps tool calling.
- DeepSeek prices in the built-in price table (`deepseek-flash`, its retired
  name `deepseek-v4-flash`, and `deepseek-v4-pro`), including the cache-hit
  price. Prices can now have peak windows. Before this, DeepSeek usage
  showed as $0 and logged `llm.price_unknown`.

#### Shadow mode

- **Shadow runs.** System code can run a candidate pipeline (another model,
  prompt or graph) on a real alert beside the production run. The shadow run
  records what it would have done (notifications, escalation, response plan,
  alert changes, live UI events, a safety-net reopen) in the new
  `shadow_effects` table instead of doing it. Migration `0013`; the table is
  in the tenant data export and follows alert retention.
- **A shadow agreement report.** `lg-sotf shadow-run --tenant T --candidate
  profile.yaml --window 7d` replays a tenant's recently decided alerts
  through a candidate model profile in shadow mode and reports how often it
  takes the same route as production (overall and per route, with n and a
  95% confidence interval), a confusion matrix, the alerts the candidate
  would have closed where production escalated (listed first), escalate and
  plan_response differences, candidate failures, new escalations, different
  response plans, and the cost and latency difference per alert. A candidate
  run that fails, or whose model answers are unusable so the rules decide,
  counts as a disagreement and is listed; the report says when there is not
  enough to judge the candidate on. Platform admins can also read the report
  at `GET /api/v1/platform/shadow/reports/{id}` (beta). Migration `0015`
  adds the `shadow_verdicts` table (append-only, tenant row-level security,
  deleted with its alert, in the tenant data export, not in the evidence
  pack).
- **A SELECT-only database role for shadow runs.** New settings
  `database.shadow_url` (the shadow role's login), `database.shadow_role`
  (the role `lg-sotf migrate` grants `SELECT` on the tenant tables, except
  the credential tables, and nothing else) and `database.shadow_pool_max`.
  Without `database.shadow_url` shadow runs refuse to start; they never fall
  back to the runtime role. Production compose: set `LGSOTF_SHADOW_PASSWORD`
  before the first start to create `lgsotf_shadow`, grant it and give its
  login to the worker. Helm: the new `secrets.shadowSecret` (key
  `LG_SOTF_DATABASE__SHADOW_URL`, loaded into the worker only) and
  `settings.database.shadow_role`. For an existing database, create the role
  by hand (docs/deployment.md, section 4).
- New setting `security.shadow_candidate_llm_hosts`: the LLM hosts a shadow
  candidate profile may call besides production's own. It is read from the
  production settings only; a candidate profile cannot extend it. `lg-sotf
  shadow-run` refuses a candidate on any other host before reading any
  alert, and stores the candidate's host (never its key) on each verdict row
  and in the report (`candidate_host`; migration `0017`).
- Shadow LLM calls use slots of their own, one per model tier and worker
  process by default (`llm.fast.shadow_max_concurrency`,
  `llm.deep.shadow_max_concurrency`), so a live call never waits for a
  shadow call.
- Each `lg-sotf shadow-run` is audited in the tenant
  (`tenant.shadow_replayed`) and in the platform tenant
  (`platform.tenant_shadow_replayed`), with the report id, candidate label
  and host, window and number of alerts.

#### Evaluation

- **Scorecards.** `lg-sotf eval-scorecard` turns the JSON reports of
  `lg-sotf eval` (one per dataset, same model) into a one-page scorecard in
  Markdown and JSON: the malicious false-negative rate first, with counts
  and an interval, then closure, escalation, per-class precision and recall,
  cost and latency per item, the model and prompt version, and the
  limitations. A DeepSeek scorecard is marked internal only when one of its
  datasets is not synthetic: real alerts must never go to DeepSeek's hosted
  API. Two scorecards are in `docs/scorecards/`: v1, a local `qwen2.5:7b` on the
  synthetic and phishing sets, and v2, DeepSeek V4 (open weights) on the
  520-alert attack-emulation corpus, measured through the hosted API on
  synthetic alerts only. Both were measured before decision policy v3; read
  the figures and their limits there.
- **Intervals on every rate.** Every rate in the evaluation reports, the
  scorecard and the Reports pages comes with its sample size and a 95%
  Wilson interval, so a rate over a handful of alerts no longer reads like a
  firm number. Eval reports carry `metrics.intervals`, which the gate can
  check. The `/reports/*` responses add a `<rate>_ci` field next to each
  rate, with `rate`, `n`, `ci_low` and `ci_high`, and the CSV exports add
  `_n`, `_ci_low` and `_ci_high` columns at the end. Existing fields and
  columns are unchanged. A sample too small to read is shown everywhere as
  "Not enough data (n=…)".
- **What reports lead with.** Every evaluation report and scorecard leads
  with two numbers: the benign closure rate (with n and a 95% interval) and
  malicious auto-close (with n and an exact one-sided 95% upper bound). A
  table attributes each automatic close to rules, the model, history, the
  verdict cache, a suppression rule or a completed response, and every
  malicious alert closed by any of them is listed by id. Reports record, per
  item, what the routing decision read (`decision_inputs`).
- **An attack-emulation corpus**, `corpus_v1`
  (`tests/fixtures/eval/corpus_v1.jsonl.gz`): 520 labelled Wazuh 4.14
  alerts, 208 malicious and 312 benign. The malicious alerts come from
  Atomic Red Team tests chained into Caldera-style campaigns; the benign
  ones are routine noise and look-alikes that trip the same rules (an
  authorised scanner, IT using PsExec, Ansible editing root's crontab,
  updaters dropping executables). Every alert names its ATT&CK technique
  and, where one exists, its Atomic Red Team test, and uses the real rule
  ids, levels, groups and MITRE mappings of the Wazuh v4.14.8 ruleset. A
  seeded generator (`python -m tests.fixtures.attack_corpus`) rebuilds the
  file byte for byte. The corpus declares its authorised scanner as a tenant
  would. CI replays it through the real pipeline from committed cassettes
  (fake model, no network) and gates it: no malicious alert closed by
  automation in any log source.
- **An adversarial corpus**, `tests/fixtures/eval/adversarial_v2.jsonl`: 97
  synthetic alerts in seven families that try to steer the model through log
  fields, through threat-intelligence and history answers, by asking for a
  response or a close, with encoding tricks (Base64, look-alike letters,
  invisible characters, instructions split across fields), and by naming an
  attack's object or rule after routine activity (`title-camouflage`,
  `activity-camouflage`), plus benign look-alikes such as the security
  team's own test strings. Its gate runs in CI with the fake model: no
  malicious alert of the adversarial split may be closed by automation and
  no benign one may be routed to a response.
- Evaluation items can carry a `family`, an `injection` spec (what the
  injected text asks for) and `tool_fixtures` (canned threat-intelligence
  and history answers, used only by `lg-sotf eval`). Reports add a
  per-family table and three rates: `malicious_auto_close_rate`,
  `benign_escalation_rate` (false escalations) and `injection_followed_rate`
  (how often the model did what injected text asked). Thresholds can check
  `families.<name>.<metric>`.
- **Cassettes.** `lg-sotf eval --cassettes DIR --cassette-mode record`
  writes each item's tool observations and model replies to one JSON Lines
  file per item. The default `replay` mode runs the dataset again from them
  with no network call and the same verdicts; `replay-tools` replays the
  tools and calls the configured model, to compare a new model or prompt on
  the same observations. A call the cassette does not hold fails the item
  (`CassetteMiss`) instead of going out. Cassettes are redacted with the
  trace digest's rules before they are written. `lg-sotf eval --dataset` and
  cassette replays read gzip-compressed files.
- **An analyst oracle.** `lg-sotf eval --oracle propose|accept` is a
  measurement mode in which two simulated analysts, taking turns, decide
  every escalation at once from the dataset's labels, through the same
  decision path as the API, with items in event-time order. It shows how
  much the verdict cache, the tenant's entity history and suppression rules
  could close with perfect, instant analysts. `accept` also enables the
  suppression rules the decisions suggest.
- Datasets can declare the tenant's context (`_meta.tenant_context`): IT
  admin accounts and groups, helpdesk accounts, automation accounts and
  hosts, jump hosts, patch windows and the authorised scanner. Nothing
  applies it yet; reports show how many benign alerts it covers and how many
  attacks it covers too.
- A loader for the public AIT Alert Data Set (2.29 million Wazuh alerts, CC
  BY 4.0): `python -m tests.fixtures.aitads fetch DIR` and `build DIR --out
  FILE` sample `aitads_v1`. See `docs/evaluation.md#ait-ads` for what its
  labels can and cannot say.
- **Evaluation gates in CI.** Every pull request runs the synthetic and
  phishing sets with the offline fake model and compares the result with a
  committed baseline: one more missed attack, or one fewer benign alert
  closed, fails the build (`make eval-gate`, `make eval-baselines`). A
  nightly run uses one pinned real model, set with repository variables
  (`EVAL_LLM_*`) and skipped until they are set; only a model hosted in the
  EU or run locally is accepted. See "Evaluation gate in CI" in
  docs/evaluation.md.

#### API

- **Stability tiers.** Every operation in the OpenAPI document carries
  `x-stability`: `stable` (ingest, alerts, escalation review, actions,
  sources, suppressions, users, API keys, audit, auth and the health
  probes), `beta` (platform administration, tenant settings, reports,
  integrations, compliance exports, triage groups and bulk actions, MFA,
  usage, metrics) or `internal` (the dashboard summary and onboarding
  screens). A stable operation is deprecated for at least 6 months, and over
  two minor releases, before it is removed or changed incompatibly. A
  deprecated route answers with `Deprecation` (RFC 9745), `Sunset` (RFC
  8594) and `Link: <...>; rel="deprecation"` headers and is marked in the
  OpenAPI document. No route is deprecated yet. A CI gate (`api-compat`)
  fails on a breaking change to a stable operation. See "Stability and
  deprecation" in docs/api.md.
- **Triage in bulk.** `GET /escalations/groups` groups the open and claimed
  escalations by their alert's source and detection rule, largest group
  first, with the number unassigned and overdue, the earliest deadline, the
  confidence range and the count per severity; `GET /escalations` takes
  `source_id` and `rule` to list one group. `POST /escalations/bulk/claim`
  claims up to 50 escalations and `POST /escalations/bulk/close` closes up
  to 50 as false positive (or benign positive) with one note. Each
  escalation is claimed or decided exactly as with the single-escalation
  endpoints (same permissions, version check, audit entry and
  notifications), and the response reports each one: one that fails does not
  stop the others. `POST /escalations/bulk/propose-suppression` proposes one
  disabled suppression rule from up to 50 escalations an analyst decided
  false positive or benign positive, all or nothing; an admin enables it.
- `GET /escalations/{id}/response-preview` shows the response plan a
  true-positive decision would produce, without running or recording
  anything: for each action its risk, whether it can be rolled back, the
  connector that would run it, the guardrail verdict, whether it would run
  automatically or wait for approval, and whether your role may pre-approve
  it (high and critical risk need an admin).
- `GET /escalations` can sort by SLA with `order=sla_deadline`. New filters:
  `assigned_to=none`, `overdue=true` and `decided_by` (a user id or `me`).
  Escalations carry `assigned_to_email`, `decided_by_email`, a digest of
  their alert (`rule`, `source_id`, `source_name`, `alert_severity`,
  `entities_preview`), `ai_reason` with `ai_reason_source` (the model or the
  rules) and `routing` (the routing code, the confidence, and the review
  band and analysis threat score when a band decided it). Escalations opened
  before this release have no `routing` or `ai_reason_source`.
- Alerts carry `source_name`, `entities_preview` and the format whose
  normalizer built them (`normalized.normalizer`; models never see it). The
  alert list takes `closed_from` and `closed_to`. `GET /alerts/counts`
  returns the alert count per status in one call. Alert details list
  `findings`: each evidence lookup of the analysis agent with its source and
  `checked_at`.
- Response actions carry `blast_radius`, `reversible` and
  `irreversible_note`. Actions waiting for approval carry `guardrail`: the
  verdict of the guardrails checked again now against the tenant's current
  policy, with the reason, and why a human must approve. Blocked actions
  carry the guardrail that blocked them.
- `GET /dashboard/summary` describes the escalation and approval queues
  (`overdue_escalations`, `unassigned_escalations`, `unassigned_breaching`,
  `next_sla_deadline`, `open_escalations_by_severity`,
  `pending_approvals_total`, `pending_approvals_by_risk`), two figures for
  the caller (`pending_approvals`, `my_claimed`) and `llm_model`. `GET
  /auth/me` returns `tenant_name`. `GET /onboarding/status` returns
  `first_verdict`.

#### Platform, upgrades and releases

- **Runs survive upgrades.** Runs waiting for an analyst or an approval now
  survive upgrades that change the workflow graph. Each run records the
  graph version it started on (`workflow_runs.graph_version`, migration
  `0010`), and workers keep the previous graph next to the current one, so a
  waiting run resumes and is decided on the graph it started on. A run on a
  graph version the worker does not have fails with `UnknownGraphVersion`
  and is retried, then dead-lettered; it is never run on a different graph.
- **Every change is tested against a real upgrade.** A CI job
  (`scripts/ci/upgrade_rehearsal.sh`) runs the previous release on a fresh
  database until some alerts wait for an analyst and one waits for an
  approval, migrates the database with the new release as the schema owner,
  and decides every waiting alert through the new release's API. It runs
  again from the latest LTS release when that is not the previous release.
  An install rehearsal drives the setup from an empty database to the first
  triaged alert against a 30-minute budget.
- **Release trains.** Every Thursday, the head of `main` becomes a partner
  release candidate `vX.Y.Z-rc.N`, and the `:partner` image tags move to it.
  From Actions > *Release train*, a candidate is promoted to the stable
  `vX.Y.Z` and, if chosen, to the LTS channel (git tag `lts-X.Y`, image tags
  `:lts` and `:lts-X.Y`). A commit is tagged only when its CI passed,
  including the upgrade and install rehearsals, and when its images pass the
  same signature and provenance checks as a deploy. Releases with a Security
  changelog entry say so in their GitHub release title. *Release images* and
  *Deploy* accept release-candidate tags. See docs/releases.md for the
  channels, cadence, support windows and backports, and for how to pin and
  verify a release.
- **Break-glass access for platform operators.** `POST
  /api/v1/auth/break-glass` opens a platform-admin API session from a sealed
  credential when nobody can sign in the normal way. It is off by default.
  An operator turns it on by setting
  `LG_SOTF_AUTH__BREAK_GLASS_CREDENTIAL_HASH` (the hash printed by the new
  `lg-sotf break-glass-credential` command); it also needs SMTP
  (`integrations.smtp_host`, `smtp_from`) and `integrations.enabled`, so the
  alert can be mailed. While off, the route is not mounted.
  `docs/runbooks/break-glass.md` has the procedure, what to do when the
  alert is unexpected, how to rotate the credential and a drill checklist.
  Migration `0020`.
- The Wazuh connector is tested against a real Wazuh 4.14 indexer, not only
  a fake: `make test-wazuh-up` starts an indexer lab and `make test-wazuh`
  runs live contract tests for authentication, paging and resuming, severity
  mapping, empty windows and malformed documents (docs/testing.md).
- `docs/ai-system-card.md`, the AI system card for compliance and security
  reviewers: intended and out-of-scope uses, the model profiles and where
  each one runs, every kind of model call and the read-only tools, what the
  AI decides and what people decide, the safety invariants, the evaluation
  evidence with its intervals and known gaps, logging, data handling and the
  human oversight design. It maps the system to the EU AI Act and to NIS2
  Art. 21(2) and Implementing Regulation 2024/2690. It is not legal advice.
- `docs/microsoft-skus.md`, the Microsoft SKU coverage matrix: every
  Microsoft Graph, Defender for Endpoint and Log Analytics API LG-SOTF
  calls, with the licence it needs on Microsoft 365 Business Premium, E3 and
  E5, the application permission it is granted and the Microsoft Learn page
  that states the requirement. The lab-evidence column stays pending until
  the Microsoft lab tenant exists.

#### Design records

These record decisions; they add no feature in this release.

- [ADR 0014](docs/adr/0014-investigation-skills.md): investigation skills
  and autonomy earned per skill and tenant. Nothing closes on a skill yet.
- [ADR 0015](docs/adr/0015-frontend-module-model.md): the frontend module
  model. The web console is now built from service modules, each a folder
  under `src/lg_front/src/modules/` with a typed manifest, its own API slice
  and named extension points; a lint rule keeps a module from reaching into
  another's files. It is still one build and one image, and the security
  operations pages are the only module.
- [ADR 0016](docs/adr/0016-vulnerability-operations-center.md): the
  Vulnerability Operations Center as the first service to be added next to
  the SOC. It is a design; no VOC code ships.

### Changed

#### Triage and routing, for every tenant whatever its tier

- Every info, low and medium alert now goes through analysis. Before, a
  strong correlation (or a low confidence) sent it straight to the decision
  on a correlation-raised confidence, which could plan a response or hold a
  benign alert in the grey zone without any analysis.
- Correlation is evidence, not a score boost: related alerts, bursts and
  alert rates go to the analysis model and into the alert summary, but they
  no longer raise the alert's confidence. A response plan therefore needs
  the analysis threat score (or trusted triage evidence), never correlation
  alone.
- The grey zone (30 to 70) is tested on the analysis threat score, not on
  the confidence from before the analysis.
- A low-threat benign verdict closes an alert with approved benign evidence:
  the false-positive signals triage takes only from what an attacker cannot
  write (the detection rule's name, the EICAR test file, a test-environment
  source, a scanner you listed in `triage.known_scanners` or an
  authenticated internal sender). The rules' threat score no longer has to
  be below 30, which no Wazuh alert could reach.
- The per-tenant tool switch fails closed. A third-party lookup runs only
  when `tools.<provider>` is absent from the tenant's settings or its
  `enabled` is absent or exactly `true`. A value such as `"false"` or `0`, a
  setting that is not a mapping, or settings that cannot be read keep the
  lookup off. Before, only `enabled: false` switched it off.
- An HTTP 404 from AbuseIPDB is now an error, not "unknown address". A
  VirusTotal answer without analysis statistics is now an error, not a
  verdict with zero detections.

#### Operations

- The pipeline metrics (`lgsotf_node_seconds`, `lgsotf_llm_calls_total`,
  `lgsotf_llm_tokens_total`, `lgsotf_llm_cost_usd_total`,
  `lgsotf_llm_refusals_total`, `lgsotf_llm_skipped_total`,
  `lgsotf_enrichment_lookups_total`, `lgsotf_llm_slot_wait_seconds`) have a
  new `mode` label (`live` or `shadow`). Add `mode="live"` to your alerts
  and dashboards; the examples in `docs/operations.md` do.
- The worker and the scheduler now refuse to start when
  `security.encryption_keys` is set but holds a key that is not a valid
  Fernet key, as the API already did. Before, they ran without a key, and
  every action, notification, ticket and source poll that needed a stored
  credential failed later. Unset keys still start every role.
- The command line now applies the API's password policy to the passwords it
  sets (`lg-sotf create-admin`, `lg-sotf create-tenant --admin-email` and
  the bootstrap admin of `lg-sotf migrate`): at most 1,024 characters and at
  least 4 different characters, besides the minimum length. Generated
  bootstrap passwords already comply.
- Roles are listed from least to most privileged (`viewer`, `analyst`,
  `admin`) in the choices of `lg-sotf create-admin --role` and in the
  "expected one of" message. The roles and the `admin` default are
  unchanged.
- Building the web app from source (`src/lg_front`) now needs Node.js 22.12
  or later. The frontend image already built on Node 22, so container
  deployments are unaffected.

#### API

- The OpenAPI document now lists the allowed values of every response field
  drawn from a vocabulary (alert `status` and `severity`, escalation
  `level`, action `status`, `risk_level` and `action_type`, user `role`, API
  key `scopes`) as an `enum`. Responses are unchanged, and clients must
  still accept values they do not know: a newer release can add one. The
  evidence pack, `GET /readyz`, `GET /tenant/response/routes` and `GET
  /integrations/microsoft/catalog` now publish the shape of their JSON body.
- An action whose stored `verification` state the API process does not know
  is returned as is, instead of failing the request with a 500.

#### Console

- The LLM usage page checks the date window before it sends the request,
  with the same message as the reports page.
- While the phone menu is open, keyboard focus stays inside it, and Escape
  closes it.
- The Reports and MSSP console tabs look like the Alerts view tabs and
  answer to Home and End; on the decision page the Entities tab says "IP
  addresses" where it said "Ips".

#### For contributors

- Pull requests add a changelog fragment in `changelog.d/` instead of
  editing `CHANGELOG.md`; `python scripts/changelog.py fold` moves the
  fragments into the changelog at release time.
- `npm run lint` refuses a raw hex colour or an arbitrary size utility in
  the web app; the type scale, radii, control heights and row densities are
  in `src/lg_front/src/theme/tokens.css` next to the colours.
- `python scripts/export_invariants.py` also writes the invariants table of
  the AI system card, and CI fails when the card is stale.
- The regression checks of `smoke_thresholds.yaml` and
  `phishing_smoke_thresholds.yaml` are exact for the benign auto-close rate
  (`max_decrease: 0`, was 0.05).

### Deprecated

- `observability.otlp_endpoint` (`LG_SOTF_OBSERVABILITY__OTLP_ENDPOINT`) is
  ignored. It is still accepted, so existing configurations load, and every
  process logs `observability.otlp_endpoint_deprecated` at startup while it
  is set. Remove it; a later release drops the setting.

### Removed

- OpenTelemetry tracing. The exporter it configured never sent anything: no
  code created spans. The OpenTelemetry SDK and OTLP exporter (and their
  protobuf dependencies) are no longer installed; `opentelemetry-api` stays,
  as a dependency of FastAPI and the Anthropic client. `configs/*.yaml`, the
  production compose file, `.env.example` and the Helm example no longer
  mention an OTLP endpoint. Logs and Prometheus metrics are unchanged.
  `docs/adr/0008-remove-tracing.md` records the decision and how tracing
  would be added back.

### Fixed

- Claiming an escalation whose SLA has expired now works. Before, every
  click answered "Someone else changed this escalation first" and nothing
  changed. The escalation stays expired, so the missed SLA is kept in the
  queue and in reports, and you become its owner. The audit entry records
  the claim as late (`after_sla_expiry`).
- A claim on an escalation that is already decided or closed now says so
  instead of reporting a change by someone else. The API answers `409
  invalid_transition` for it; a stale version on an active escalation is
  still `409 conflict`.
- A change is no longer left in place when its audit log entry cannot be
  written. The change and its entry are now saved together: either both are
  there or neither is, and the request can simply be retried. This covers
  MFA enrollment, disabling MFA, recovery codes, the role update of a single
  sign-on account, creating, updating and deleting alert sources,
  suppression rules and integrations, integration connection tests, creating
  users and API keys, revoking API keys, the getting-started checklist
  steps, and, on the command line, `create-admin`, the bootstrap admin of
  `migrate`, `enqueue` and `dlq requeue`.
- Provisioning a tenant (`POST /platform/tenants`, `lg-sotf create-tenant`)
  no longer leaves a half-created tenant behind. The tenant, its settings,
  its first admin and its audit entries are saved together, so a failure
  leaves nothing behind and a retry succeeds.
- Sign-out could leave the session alive when the page was reloaded while
  `POST /auth/logout` was in flight. The web app now reports signed out only
  after the API answers, starts no refresh meanwhile, and sends the logout
  with `keepalive`. Logout also revokes every token the presented one was
  rotated into.
- An LLM call that failed unexpectedly no longer leaves its token estimate
  counted against the tenant's daily LLM budget until the end of the UTC
  day. Every outcome now settles the reservation, including a call cancelled
  by a node timeout.
- A run no longer fails when an upgrade migrates the database while it is in
  flight. The worker's transactions on runs are run again once when a
  prepared statement went stale (`db.stale_statement_retry`,
  `lgsotf_db_stale_statement_retries_total`). Before, the message waited for
  the visibility timeout (20 minutes by default).
- A worker could hang on graceful shutdown until it was killed. Shutdown now
  cancels its liveness and usage-flush loops repeatedly until they stop.
- `GET /users` now lists every account of the tenant. Before, it stopped at
  the first 1,000 accounts by email without saying so.
- Notifications, ticketing requests and response-action webhooks no longer
  build a new TLS context for every request, which blocked other work while
  the CA bundle loaded. One context per process is reused, and one per
  distinct `ca_cert_pem`, so an integration with its own CA still trusts
  only that CA.
- The "LLM errors" and "Run failures" alerts in the operations guide now sum
  both sides of their ratio before dividing. The old expressions paged on a
  single error. If you copied either expression into your Prometheus rules,
  replace it.
- `lg-sotf mcp` honours every form of `Retry-After` when it retries a read:
  fractional seconds and HTTP dates, as well as whole seconds.
- The scheduler's SLA escalation and expiry entries are redacted and logged
  like every other audit entry.
- Backtests (`lg-sotf eval --from-history`) start each replay from the same
  initial state as the workflow.
- An evaluation no longer depends on the hour it runs: the runner ingests
  each email report at its own `Date` header, or at a fixed noon when it has
  none. Production still stamps a pushed report with the time it arrives.
- Web UI: Jira and ServiceNow ticket links show on the Escalations page when
  more than one page of escalations is loaded. The page now asks for tickets
  in batches of 50.
- Web UI: the Actions page explains the `internal_sender`, `invalid_email`,
  `invalid_message`, `rejected_by_reviewer` and `rejected_with_remaining`
  block reasons instead of showing the raw codes.
- Web UI: a successful API answer that is not JSON, such as the app's own
  `index.html` served by a misrouted proxy, shows an error card ("The API
  response could not be read") with the request id instead of a raw
  `SyntaxError`.
- Web UI: `/account` is no longer reachable by typing the URL while a
  platform admin acts on another tenant.
- Web UI: an integration of a kind this version does not know is listed with
  its own name and cannot be edited, instead of opening the Slack form.
  Tenant quotas the API does not report show "-".
- Web UI: repeating an action that fails the same way no longer stacks
  identical notifications.
- Web UI: the account menu button includes the initials it shows in its
  accessible name (WCAG 2.5.3), and on a phone the language-model test
  results under Tenant settings can be reached with the keyboard.

### Security

- **Published images are signed.** Each `ghcr.io/gapilongo/lg-sotf` and
  `lg-sotf-frontend` digest carries a keyless cosign signature and a SLSA
  build-provenance attestation, both from the `Release images` workflow on
  `main`. The deploy workflow verifies both before it deploys, and stops if
  either check fails. This means the workflow can no longer deploy images
  built before this change; roll back to those on the VM instead. To verify
  an image yourself, including on an air-gapped host, see `docs/security.md`
  (section 9) and `docs/air-gapped.md`.
- **Builds verify every input.** Every Python requirements file is
  hash-locked for all platforms and installed with `pip install
  --require-hashes` in the image build, CI and `make dev`; re-lock with
  `make lock`. Every base image is pinned by digest, including the
  PostgreSQL, Redis and Caddy defaults in the compose files.
  `PYTHON_BASE_IMAGE`, `NODE_IMAGE` and `NGINX_IMAGE` default to the pinned
  images; set them only to use a mirror. The frontend runs on
  `nginx-unprivileged:1.31-alpine-slim`; the old `1.28-alpine` tag no longer
  received updates and carried fixable critical CVEs.
- **A CVE gate.** CI scans both images with Trivy and fails on any critical
  or high CVE that has a fix. Reviewed exceptions live in `.trivyignore`,
  and each one expires within 90 days. `pip-audit` also checks the build and
  CI tool locks.
- **SBOMs and VEX on every release.** Every release carries CycloneDX SBOMs
  as assets (the Python lock, the frontend's production npm packages, and
  both images for amd64 and arm64) and an OpenVEX document
  (`security/vex.json`) that lists the CVEs scanners report in the images
  but that do not affect LG-SOTF, with the reason for each. Every asset is
  validated against its schema and has a build-provenance attestation;
  `docs/security.md` (section 9) shows how to download, verify and use them.
- **A dependency policy**, `docs/dependency-policy.md`. A new Python, npm,
  image or action dependency must pass an admission checklist. Vulnerable
  dependencies are patched within these times: critical 7 days, high 14,
  medium 30, low the next minor release. Advisories are triaged within 2
  business days. Dependabot runs every Monday for every ecosystem, so merged
  updates ship on Thursday's partner train.
- **The verdict cache and suggested suppression rules are keyed by
  behaviour.** The verdict cache could close a malicious alert at the gate
  because it matched alerts by fingerprint alone (rule, hosts, users, IPs,
  hashes, domains): on one host, a ransomware `PSEXESVC` service matched an
  Edge update service an analyst had closed as benign.
  - The cache now uses a verdict key: the fingerprint plus the process
    image, command line, service name and image path, user/uid, parent
    process, the objects an attacker creates and the request context,
    compared in full.
  - Alerts with no process, command, service or created object, alerts in a
    never-close class and alerts normalised by a model never close from the
    cache and get no suggested rule. Model-normalised alerts also skip
    suppression rules.
  - A cached verdict closes an alert only after two different analysts
    decided it benign within 7 days, at the alert's severity or higher. One
    analyst's decisions, including a bulk close, count once. It is never
    used for critical alerts, nor within 7 days of a confirmed threat on
    that key or on any alert with the same fingerprint.
  - Suppression rules suggested from false-positive decisions match the
    alert's verdict key instead of its fingerprint, so enabling one no
    longer suppresses a different service or command on the same host.
  - When a threat is confirmed on an alert, every enabled suppression rule
    that would close that alert is disabled and recorded as
    `suppression.revoked` in the audit log. A failure is logged as an error
    and counted in `lgsotf_revocation_failures_total`.
  - Migration `0016` disables every enabled suggested rule that matches a
    fingerprint alone (audited `suppression.revoked`, reason
    `fingerprint_suggestion`), and the gate ignores such rules even if they
    are enabled again. Replace them with rules on `verdict_key`.
  - A benign decision on a grouped escalation closes an attached alert only
    when it has the same verdict key as the reviewed alert; otherwise the
    attached alert gets its own escalation.
  - Cached verdicts written before this change are no longer read, so
    repeats are investigated until two analysts have decided them again.
    `DELETE /tenant/verdict-cache` removes the old ones now.
- **Triage no longer reads benign words from alert titles** ("test",
  "update", "maintenance", "scheduled" ...). Integrations build titles from
  the names of the objects involved, and an attacker who named a scheduled
  task "Windows Update Test" could get a malicious alert closed on the rules
  alone. False-positive evidence now comes only from the detection rule's
  name (with quoted values and every attacker-named value masked out), EICAR
  hashes, the tenant's known scanners and the source id.
- **Rule-name words that name the activity a rule detects** (`scheduled`,
  `update`, `backup`, `scan`, `monitoring`) are no longer false-positive
  evidence on their own: a new scheduled task is persistence and a disabled
  monitor is defence evasion. They count only with a trusted qualifier: a
  word of benign intent in the same rule name (`test`, `selftest`,
  `maintenance`, `health_check`), a test-like source id or, for `scan`, one
  of your `triage.known_scanners`.
- **A declared scanner counts only as the source of the activity** (a source
  address or host field of the event, such as `srcip` or the Windows logon
  source), never when it is the host or address the activity reached. An
  attack on your scanner is still an attack.
- **Approved benign evidence has limits.** It no longer closes an alert past
  text written to steer a model, analyst-confirmed malicious history, rule
  evidence of a threat or a related alert closed as malicious. A declared
  scanner or a test source never closes credential access, log clearing,
  tampering, ransomware or named persistence.
- **Failure logs never carry the exception message.** An unhandled API error
  (`api.unhandled_error`) is no longer logged with a traceback, which quoted
  exception messages and source lines. The record keeps `error_type` and now
  carries `error`, `stack` (the innermost 15 frames as `module:lineno in
  func`, without source text) and `cause_types`; the other failure logs gain
  the same three fields. To find where a 500 came from, search
  `event=api.unhandled_error` and read `stack` instead of a `Traceback`.
- **Error text that is stored or shown is redacted before it is cut to
  length**: a run's and a source's `last_error`, an outbox delivery's and a
  ticket sync's error, a ticketing receiver's error body, the ticket
  connector's `detail`, eval and backtest item errors, and the MCP server's
  messages for errors the API returned. Before, a token straddling the cut
  could slip past the redaction patterns, and some of these were never
  redacted.
- **OIDC sign-in** reads the identity provider's discovery and key (JWKS)
  documents up to their 256 KiB limit and stops there. Before, the API
  downloaded the whole response into memory and only then checked its size.
- **MSSP grants.** Nothing created or changed under a grant outlives it or
  acts as a customer user.
  - Under a grant, integrations, sources and tenant settings cannot be
    created or changed, sources and suppression rules cannot be deleted, and
    only suppression rules created under a grant can be changed. A Slack app
    recorded as written under a grant never approves or rejects.
  - Suppression rules written under a grant name it and end with it:
    revoking a grant ends them, and the suppression gate ignores rules of a
    grant that is no longer live.
  - A grant row can only be revoked, once, and nothing the organisation does
    deletes it. A tenant can give at most 10 grants a minute.
  - An organisation's API key uses a grant only when the customer set
    `allow_api_keys`, while the member who created it is still a member and
    their account is enabled, and no further than the creator's own role.
  - A delegated WebSocket closes when the organisation's own tenant is
    suspended.
  - Reads under a grant are recorded in the organisation's chain too
    (`delegated.grant.tenant_access`). `GET /audit` under a grant hides the
    customer's grant register and other organisations' details, and entries
    cut for a caller under a grant carry `redacted: true`. `GET
    /organisation/grants` answers for organisations only and does not show
    the customer's reason.
- **Shadow runs cannot cause an effect outside the platform.**
  - Every egress path (HTTP clients, so Slack, webhooks, tickets and
    Microsoft; mail; the notification outbox; response connectors; WebSocket
    events; the work queue) refuses or records the call in shadow mode. An
    architecture test finds the egress call sites in the source and fails on
    any that is not covered.
  - A shadow run reads the database only as the SELECT-only role
    `lgsotf_shadow`, from a connection pool of its own, in read-only
    transactions; its Redis client sends reads only. A statement that slips
    past the shadow statement guard fails at the database for lack of
    privilege.
  - `lg-sotf migrate` refuses a shadow role that could write or bypass
    tenant isolation, that holds an `INSERT` or `UPDATE` grant on a single
    column, or that is a member of any other role. `lg-sotf shadow-run`
    refuses to start when `database.shadow_url` is unset or unusable, and a
    database or shadow-role failure during a replay stops it.
  - A shadow run never bills the tenant or spends its LLM token budget,
    never calls a threat-intelligence provider (it reads the lookup cache
    only) and never moves production metrics.
  - A candidate profile expands `${VAR}` only in `llm.api_key`, and only
    from a `CANDIDATE_` variable, so it cannot send a process secret to an
    endpoint of its choice. A candidate on another provider or `base_url`
    never gets production's LLM API key, and it cannot set the shadow slots.
  - Reading a shadow report is audited as `platform.shadow_report_viewed` in
    the platform admin's home tenant.
- **Break-glass.** Every break-glass sign-in is audited
  (`auth.break_glass_used`: account, source address, reason) and mailed to
  every active platform admin of the install. Both are written before the
  session is issued; if either fails, the sign-in fails. A session lasts
  `auth.break_glass_ttl_s` (10 minutes by default, at most 15) and has no
  refresh token. It never acts under an MSSP grant, and every audit entry it
  writes carries `auth_method: break_glass`. Failed attempts are audited
  (`auth.break_glass_failed`) and rate-limited per client address. An alert
  that cannot be mailed is retried; one that is given up is logged as an
  error and counted in `lgsotf_security_alerts_undelivered_total`.
- **The guided Wazuh checks** never return, log or audit the entered
  password, user name or API key, and an unknown API key, a mistyped one and
  another tenant's key get the same answer. The indexer is reached through
  the install's destination policy.

### Upgrade notes for 1.3

Upgrading from 1.2.3:

- **Migrations `0010` to `0020`** run with `lg-sotf migrate` as the schema
  owner, before the new version starts (the compose `migrate` service and
  the Helm pre-upgrade job do this). They apply in the order 0010 to 0017,
  0019, 0020, 0018.

  | Migration | What it does |
  |---|---|
  | `0010` | `workflow_runs.graph_version`: the graph a waiting run started on |
  | `0011` | `investigation_steps`: the investigation trace |
  | `0012` | `organisations`, `organisation_members`, `tenant_grants` |
  | `0013` | `shadow_effects`: what a shadow run would have done |
  | `0014` | `blind_audit_runs`, `blind_audit_items` |
  | `0015` | `shadow_verdicts`: the shadow agreement report |
  | `0016` | Disables enabled suppression rules suggested from a fingerprint alone |
  | `0017` | The candidate's LLM host on each shadow verdict |
  | `0018` | `empty` and `failed` outcomes on investigation steps |
  | `0019` | `pov_runs`: proof-of-value runs |
  | `0020` | Break-glass alerts: mailed outbox rows without an integration |

  `0016` is the only one that changes your data: each rule it disables is
  audited as `suppression.revoked`. Review the list and replace the rules
  you still want with rules on `verdict_key`.
- **Upgrade the scheduler together with the API.** An older scheduler cannot
  read the new `email` outbox rows.
- **No new setting is required.** New settings are optional and off or unset
  by default: `ai_closure.tier` (tenant), `blind_audit` (tenant),
  `triage.known_scanners` (tenant), `database.shadow_url` and
  `database.shadow_role`, `security.shadow_candidate_llm_hosts`,
  `ingestion.allowed_destination_hosts`, `ingestion.read_only_sources` and
  `LG_SOTF_AUTH__BREAK_GLASS_CREDENTIAL_HASH`.
- **AI closure stays off.** Nothing closes on the models' word until a
  tenant admin sets `ai_closure.tier` to `auto_full_audit`. The blind audit
  is a separate tenant setting (`blind_audit`), also off until enabled: turn
  it on with the tier, so that the closes are sampled.
- **Triage and routing change for every tenant**, with the tier off too.
  Every info, low and medium alert is analysed, so expect more deep-tier
  model calls. Alerts whose only benign evidence was a word in the title or
  an activity word in the rule name now reach the model and, when needed, an
  analyst. If your scanners raise alerts that used to close, list them in
  `triage.known_scanners`; they count only as the source of the activity.
  The verdict cache starts empty in effect, and closes a repeat only after
  two different analysts decided it benign.
- **The console.** The "Escalations" entry left the menu: the Queue replaces
  it, and `/escalations` still opens the older list. A platform admin who
  works in another tenant now has that tenant in the address,
  `/s/<tenant>/...`; addresses without it open the home tenant as before.
  The theme follows the system setting unless a user already chose one, and
  rows are denser ("Comfortable rows" restores the larger ones).
- **Metrics and alert rules.** Add `mode="live"` to the pipeline metrics in
  your alerts and dashboards. Replace the "LLM errors" and "Run failures"
  expressions if you copied them from the operations guide.
- **Tracing.** Remove `observability.otlp_endpoint`; it is ignored.
- **Configuration that is now refused.** The worker and the scheduler do not
  start with an invalid Fernet key in `security.encryption_keys`. A tenant's
  `tools.<provider>.enabled` must be exactly `true`, or absent, for the
  lookup to run. CLI-set passwords must pass the API's password policy.
- **Deploys verify signatures.** The deploy workflow refuses images built
  before signing was introduced. To roll back to one of those, do it on the
  VM (docs/cicd.md, section 11).
- **Building from source** needs Node.js 22.12 or later, and Python
  dependencies install with `--require-hashes` (`make dev`).

## [1.2.3] - 2026-11-05

### Fixed

- Evidence packs and NIS2 incident drafts for an alert that was attached to
  another alert's escalation now include that escalation, its decision and
  its audit entries. Before, they matched only escalations whose primary
  alert was the one exported, so the pack for an attached alert omitted the
  decision that closed it.
- The GDPR tenant export now includes `indicator_sightings.jsonl`: the
  indicator values seen on each alert as displayed (IP addresses, email
  addresses, user and host names). The manifest's `excluded` list now names
  workflow run bookkeeping as well, and a test fails when a new
  tenant-scoped table is neither exported nor listed as excluded.
- `DATABASE_URL` and `REDIS_URL` are now true fallbacks. Before, an exported
  `DATABASE_URL` or `REDIS_URL` overrode the URL from init arguments, the
  YAML config file and `.env`, contrary to the documented precedence.

- Web UI: **Load more** on a list no longer loses the page it is loading
  when a live update arrives at the same time. The live refresh cancelled the
  in-flight request and refetched only the pages already shown; it now waits
  for the page to arrive. This was also the cause of an intermittent e2e
  failure.
- A `Retry-After` header of `inf`, `nan` or a very large number no longer
  reaches retry sleeps or schedules: non-finite values are ignored and every
  hint is capped at one hour. Enrichment now uses the same parser as the
  other HTTP clients (it also accepts fractional seconds).

### Changed

- `make lint` type-checks the same packages as CI (adds `integrations` and
  `mcp`); a test keeps the two lists in step.
- API-key authentication uses the shared `verify_api_key` helper instead of
  an inline comparison (same constant-time check).
- `docs/architecture.md` package layout, connector list and tracing note
  match the code; `docs/operations.md` no longer says traces are exported
  (the exporter is configured, but no spans are created yet).

### Removed

- Dead code with no production callers: the `ConfigManager` facade
  (`lg_sotf.core.config`) and `lg_sotf.utils.llm`, the unused tool
  orchestrator layer (`lg_sotf.tools.base`, `cache`, `orchestrator`), the
  legacy `AgentRegistry` and unused `BaseAgent` methods, seven unused
  exception classes, the duplicate `lg_sotf.main` entry module (use
  `lg-sotf` or `python -m lg_sotf`), and small unused helpers.
- The unused `aiohttp` and `aiofiles` runtime dependencies (and aiohttp's
  dependency stack) from the package and the container image.
- 22 empty legacy test files and packages and unreferenced alert fixtures.
- Web UI: unused exports and live-event state that re-rendered consumers on
  every event.

## [1.2.2] - 2026-11-05

### Fixed

- Lookalike-domain detection now catches brand domains spelled with a
  Cyrillic `і`, Greek `ι` or dotless `ı` in place of `i` (for example
  `mіcrosoft`). The comparison folded those letters to `i` but folded ASCII
  `i` to `l`, so the two spellings never matched.
- `lg-sotf dlq requeue` now really starts a dead letter with
  a fresh delivery count. The copy kept the exhausted `retries` counter, so
  a requeued resume could be dead-lettered again on its first failure.
- Jira and ServiceNow ticket creation and comments are no longer resent
  after a read timeout or a 5xx answer, which could open a duplicate
  ticket or post a comment twice. They are still retried when the request
  never reached the server (connection refused or timed out, HTTP 429);
  otherwise the error goes to the caller, whose retry looks for the ticket
  first.
- Alerts normalized by the LLM fallback now carry the `secrets_redacted`
  flag when redaction replaced values in them.
- Splunk sources reject an invalid `max_event_lag_s` or `search_timeout_s`
  (null, text, negative, NaN, infinite or out of range) with a field-named
  config error. Before, null failed with an HTTP 500 and NaN made the job
  wait loop poll forever. Values must now be numbers: 0 to 30 days for the
  lag, 1 to 3600 seconds for the search timeout.

### Changed

- The reference configs (`configs/*.yaml`) carry only keys the code reads.
  Keys under `tools.virustotal` were misnamed and ignored: they are now
  `timeout_s` and `requests_per_minute`. In `development.yaml` VirusTotal
  sat under `tools.intel` and its key was never used. `ingestion.
  llm_normalization` is now the real switch, `ingestion.llm_fallback`.
  Obsolete blocks that looked like controls but did nothing are removed:
  `agents.response` (`dry_run_mode`, `auto_approve_*`; the real switch is
  `response.dry_run`), `agents.ingestion`, `agents.human_loop`, and the
  `tools` retry and cache keys. A new test fails when a reference config
  sets a key in `agents`, `routing`, `tools` or `ingestion` that nothing
  reads.

### Security

- Pinned dependencies updated for published advisories: aiohttp 3.14.4,
  certifi 2026.10.18, langgraph-checkpoint-postgres 3.1.3 (with
  langgraph-checkpoint 4.3.0), langgraph-sdk 0.4.6, OpenTelemetry
  1.45.1 / 0.66b1 and pyasn1 0.6.5.

## [1.2.1] - 2026-10-01

### Fixed

- A model call that fails fast with a transient provider error (HTTP 429,
  5xx such as Gemini's "503 high demand", or a refused connection) is now
  retried twice within the call (about 2 s and 6 s apart). Before, the
  analysis step's retry budget allowed a single attempt, so such an error
  failed the run and the alert waited about 20 minutes for redelivery.
  Timeouts are still left to the node policy.

## [1.2.0] - 2026-10-01

MCP for testers and analysts: Phases 0 and 0.5 of the approved MCP
architecture (`docs/design/mcp-architecture.md`). Security first: MCP reads,
does safe writes and proposes; it never approves, rejects, rolls back or
retries actions, decides escalations, or changes settings, sources,
integrations, users, keys or MFA.

### Added

- Seven new `lg-sotf mcp` tools: `whoami`, `get_verdict`, `list_actions`,
  `get_action`, `ingest_test_alerts`, `wait_for_verdict` and `get_test_run`.
  From Claude Code, a tester on a dry-run dev or UAT install can send up to 25
  canonical test alerts with expected labels, wait for triage, read verdicts,
  routes, reasoning and proposed actions, and score the run (accuracy, route
  and escalation accuracy, mismatches, contamination). Analysts gain read
  access to verdicts and the response-action ledger.
- `LG_SOTF_MCP__API_KEY_FILE`: the key is read from an owner-only file and
  never sits in the launching shell.
- `examples/mcp/.mcp.json`: a committable Claude Code entry (docker, image
  `v1.2.0`, key file mounted read-only, no URL or credential).
- `docs/mcp.md`: the tester workflow, the QA-tenant runbook and the security
  model; `docs/design/mcp-architecture.md`: the full design and its phases.
- Web app: "Connect an AI client" help on the API keys card.

### Changed

- Every MCP tool result strips invisible, bidi and control characters, and
  escapes `>` as well as `<` inside the untrusted-data block.
- `add_note` is annotated as destructive, so clients ask before calling it.
- One malformed message no longer ends the stdio session; a long
  `wait_for_verdict` no longer blocks other requests and stops when cancelled.

### Upgrade notes for 1.2

- Test alerts sent through MCP are triaged like real ones in this release.
  Use them only on an install with `response.dry_run=true` (the default) and
  in QA tenants without integrations, as the runbook in `docs/mcp.md` says.
  Server-side rehearsal routing for MCP-ingested alerts comes in Phase 1a.

## [1.1.0] - 2026-10-01

Approved response actions now run directly in the customer's Microsoft
environment, and LG-SOTF proves they happened.

### Added

- **Microsoft direct response** (`docs/microsoft.md`): a `microsoft`
  integration per tenant (its own app registration, client secret or
  certificate, write-only and encrypted; global, US Government, GCC High,
  DoD and China clouds with fixed Microsoft hosts, never a tenant-supplied
  URL). A connection test reports token, permissions and readiness per
  capability, including Exchange RBAC for Applications setups.
- **Per-action routing**: each action type goes to the Microsoft connector,
  the SOAR webhook, ticketing or dry run (`GET /tenant/response/routes`); the
  dry-run kill switches always win, and a tenant dry run makes Microsoft
  rehearse an action without changing anything.
- **Microsoft 365 mail** (`docs/microsoft-mail.md`): `purge_message` finds the
  reported message by Internet Message-ID in each recipient mailbox (from the
  alert or message trace) and removes it; `restore_message` rolls it back;
  `notify_reporter` sends a fixed update from the SOC mailbox.
  `block_sender` stays on the SOAR webhook (no Microsoft API exists).
- **Entra ID** (`docs/microsoft-entra.md`): `disable_user` (rollback
  `enable_user`), `revoke_sessions`, `reset_password` (random, never stored,
  change forced at next sign-in) and `confirm_compromised` (rollback
  `dismiss_user_risk`). A guard refuses privileged targets and protected
  assets, including aliases and object ids.
- **Defender for Endpoint** (`docs/microsoft-defender.md`): `isolate_host`
  (rollback release), IP/domain/URL and file indicators with expiry (rollback
  deletes only LG-SOTF's indicators), stop-and-quarantine, and investigation
  package collection.
- **Verification**: executed actions are re-checked against Microsoft until
  proven or failed (`action.verification_failed` event, a badge in the UI,
  `POST /actions/{id}/verify`).
- **Rollback and retry**: `POST /actions/{id}/rollback` records an inverse
  action under the same approvals; `POST /actions/{id}/retry` resumes failed
  or partial Microsoft actions. Approvals that arrive after the alert's
  workflow ended run in a background job; approvals older than
  `response.approval_ttl_s` expire.
- **SOAR templates** (`docs/soar-playbooks.md`): a dependency-free reference
  receiver (`examples/soar/receiver`) and an importable n8n workflow, plus
  recipes for Tines, Shuffle and Tracecat.

### Fixed

- Phishing: a link's visible text is no longer a block target. Only real link
  targets, the sender infrastructure and reply-to domains can be blocked.

### Upgrade notes for 1.1

- Migration `0009` adds ledger columns for routing, verification and rollback
  and builds its indexes concurrently. Its downgrade is refused while a
  Microsoft integration exists.
- Stranded approvals from 1.0 older than `response.approval_ttl_s` are
  blocked as `approval_expired` instead of executed.
- Nothing runs against Microsoft until a tenant adds a Microsoft integration,
  enables capabilities and turns dry run off. Live behaviour was tested
  against faithful API fakes, not a real tenant: validate in a lab tenant
  first (see the open items in `docs/microsoft.md`).
- CI now lints, type-checks and scans `examples/` and type-checks
  `src/lg_sotf/integrations`.

## [1.0.0] - 2026-09-30

The first commercial release: the multi-tenant platform rebuild (tracked as
0.2.0, never released on its own) plus the Release 1 product features below.

### Added in 1.0

- **Phishing triage** (`docs/phishing.md`): user-reported email ingestion
  from `POST /api/v1/ingest/email`, a Microsoft 365 reporting mailbox
  (`m365_mailbox` source, Graph) and any IMAPS mailbox (`imap` source);
  a hardened MIME parser (nothing rendered, attachments hashed not stored,
  explicit caps); phishing signals in triage and analysis (SPF/DKIM/DMARC,
  reply-to and return-path mismatch, display-name impersonation, lookalike
  and punycode domains, deceptive links, risky attachments); actions
  `purge_message`, `block_sender`, `notify_reporter`; tenant settings
  `phishing`; a 39-item synthetic phishing evaluation set.
- **Integrations hub** (`docs/integrations.md`): Slack, Microsoft Teams
  (Workflows), SMTP email and HMAC-signed webhook (`lg-sotf.event.v1`)
  notifications for escalations, SLA breaches, pending approvals, action
  outcomes and critical alerts, through a transactional outbox with retries,
  backoff, dead-lettering and a delivery log; Jira (Cloud and Data Center)
  and ServiceNow tickets, one per escalation, with decision comments and
  external-resolution notes; `create_ticket` executes through them; Slack
  interactive approve/reject under the web app's authorization rules.
- **Self-hosted models** (`docs/local-llm.md`, `docs/air-gapped.md`):
  `ollama` and `openai_compatible` providers, plain HTTP only for private
  hosts, `llm.structured_output` with one schema-guided repair, local usage
  metered at zero cost, `POST /api/v1/tenant/llm/test` and a "Test model"
  button, `docker/docker-compose.ollama.yml`, and verified air-gap
  bundle/load scripts; Gemini list prices.
- **Quick start** (`docs/quickstart.md`): `make quickstart` /
  `scripts/quickstart.sh` with 16 synthetic demo alerts and the measured time
  to first verdict (2 min 13 s on the reference run, 2.1 s after ingest).
- **Reports** (`docs/reporting.md`): value (handled without a human, analyst
  hours saved via `reporting.minutes_per_alert`, time to verdict, MTTA/MTTR,
  SLA breaches, cost per alert), accuracy against analyst decisions
  (false-negative rate headline, confusion matrix, confidence ranges,
  per-model breakdown), detection tuning with one-click suppression
  proposals, a printable monthly report, CSV exports, dashboard value tiles,
  and `lg-sotf eval --from-history` (side-effect-free backtest).
- **MSSP operations** (`docs/mssp.md`, `docs/onboarding.md`): MSSP console
  with per-tenant activity, SLA risk and quota usage; suspend and reactivate
  (ingest, API keys, sessions and workers honour it, queued work is kept);
  daily alert, source and user quotas; `usage_daily` metering and monthly
  usage export; tenant profiles and policy copy; a tenant switcher;
  per-tenant retention within install bounds; a getting-started checklist
  with one-click sample alerts.
- **Identity** (`docs/identity.md`): TOTP MFA for local accounts with
  recovery codes, admin and CLI reset (`lg-sotf reset-mfa`), a tenant
  `security.require_mfa` policy and `auth.require_mfa_for_platform_admins`;
  OIDC role mapping from group claims and just-in-time provisioning.
- **Compliance** (`docs/compliance.md`): signed case evidence packs
  (`GET /alerts/{id}/evidence`, `lg-sotf evidence-verify`) with per-step
  model provenance, the human-oversight trail and audit-chain proof; NIS2
  incident report drafts for each Article 23 stage; streamed tenant data
  export and erasure (`lg-sotf tenant-export`, `tenant-erase`).
- **MCP server** (`docs/mcp.md`): `lg-sotf mcp`, a stdio Model Context
  Protocol server over the REST API with a scoped API key.

### Upgrade notes for 1.0

- Migrations `0004` to `0008` run with the `migrate` role as usual.
- Platform admins must enrol an authenticator app at their next sign-in in
  staging and production. Set
  `LG_SOTF_AUTH__REQUIRE_MFA_FOR_PLATFORM_ADMINS=false` to postpone it.
- The scheduler now also delivers notifications and syncs tickets; it must
  keep running (one leader) for integrations to work.
- Response execution stays in dry run by default.

### Fixed in 1.0

- Gemini "503 high demand" and "429 resource exhausted" errors are now retried
  like other providers' transient errors, instead of failing the run until
  the message is redelivered (found in the Dev smoke test).

### Platform rebuild (previously 0.2.0)

A ground-up rebuild of the proof of concept into a multi-tenant platform
that can be operated in production. Nothing of the 0.1 runtime is
compatible: configuration, storage, APIs and deployment all changed. There is
no automated migration from 0.1 data.

#### Added

- **Process model**: one container image with `lg-sotf api`, `worker`,
  `scheduler` and `migrate` roles, plus operator commands (`create-tenant`,
  `create-admin`, `enqueue`, `dlq list|requeue`, `version`, `eval`).
- **Typed settings** (`lg_sotf.settings`): environment variables
  `LG_SOTF_<SECTION>__<KEY>`, optional `.env` and YAML with `${VAR}`
  expansion; startup safety checks refuse unsafe staging/production
  configuration (missing or published secrets, fake model, wildcard CORS,
  insecure cookies, development database password).
- **PostgreSQL system of record** with Alembic migrations: tenants, users,
  sessions, API keys, sources, alerts, alert timeline, workflow runs,
  escalations, analyst feedback, response action ledger, suppression rules,
  indicator sightings, daily LLM usage, audit log; monthly partitions for
  the timeline and audit log; retention jobs.
- **Tenant isolation** with row-level security on every tenant table, a
  non-owner runtime role, `SECURITY DEFINER` credential lookups, and
  tenant-scoped Redis keys, checkpoints and caches.
- **Durable runtime**: Redis Streams work queue (high/normal priority),
  consumer groups, dead-letter queue, worker leases and liveness keys,
  recovery of crashed workers, stale and orphaned run sweeps, a
  leader-elected scheduler, graceful drain.
- **Checkpointed workflow engine** (LangGraph with the Postgres
  checkpointer): gate (suppression rules, verdict cache), triage,
  correlation, analysis, policy decision, escalation with analyst interrupt,
  response planning, approval interrupt, execution, close; per-node timeouts
  and retry policies; idempotent side effects.
- **Ingestion service** with deterministic normalizers for Splunk,
  CrowdStrike, Microsoft Sentinel, Wazuh, AWS GuardDuty, IBM QRadar,
  canonical and generic field-mapped webhooks; pull connectors for Splunk,
  QRadar, Sentinel, Wazuh indexer and CrowdStrike Falcon with persisted
  cursors; secret redaction, size caps, fingerprints and deduplication;
  optional LLM normalisation fallback; outbound destination policy.
- **LLM layer**: provider factory (Anthropic by default, OpenAI and Gemini
  as extras, deterministic fake model), untrusted-data prompt boundary,
  structured output with refusal handling, prompt caching, per-model
  concurrency limits, usage and cost metering, per-tenant daily token
  budgets.
- **Agents** hardened against prompt injection: rule/LLM triage with
  injection detection, indicator-based correlation, analysis with tenant
  history and optional VirusTotal/AbuseIPDB enrichment; rule corroboration
  required for automatic benign closes and automatic containment; high and
  critical alerts are never closed as benign by automation; refusals
  escalate.
- **Human review**: escalation levels, SLAs and level-up sweeps, grouping of
  related alerts, claim and decision with optimistic locking, feedback,
  suppression suggestions.
- **Response automation** under per-tenant autonomy policy, protected
  assets, allowed actions, hourly caps and blast-radius limits; dry-run by
  default; HMAC-signed webhook connector for SOAR platforms; per-action
  approvals.
- **REST and WebSocket API** (`/api/v1`): local login with rotating refresh
  cookies, OIDC, scoped API keys, RBAC (viewer, analyst, admin, platform
  admin), ingestion, alerts, escalations, actions, sources, suppressions,
  users, API keys, tenant settings, dashboard, LLM usage, audit log and
  verification, tenant provisioning, live events; rate limits, body limits,
  security headers, OpenAPI.
- **Hash-chained, append-only audit log** per tenant.
- **Observability**: JSON logs with request/tenant/alert context and
  redaction, Prometheus metrics, OpenTelemetry tracing, health servers for
  workers and scheduler.
- **Deployment**: hardened multi-stage Dockerfile (non-root, read-only root
  filesystem), Docker Compose stack and production override with two
  database roles, Helm chart (HPA, KEDA, PDBs, NetworkPolicies,
  ServiceMonitors, migrate hook), secret generator, end-to-end stack smoke
  test, CI (lint, types, tests on PostgreSQL and Redis, dependency and
  secret scanning, image build, Helm validation).
- **Evaluation harness** (`lg-sotf eval`, `lg_sotf.eval`): labelled JSONL
  datasets in canonical or vendor formats, runs through the real ingestion
  and workflow without inventing analyst decisions, metrics (malicious
  false-negative rate, benign auto-close, escalation and inconclusive rates,
  precision/recall/F1, Cohen's kappa, cost, latency), JSON and Markdown
  reports, thresholds and baseline regression gate (baselines must match
  the dataset and selection); one fresh tenant per split so split metrics
  are independent; database, schema, Redis and report-path checks before
  any item runs; a 64-item synthetic dataset with an adversarial
  prompt-injection split; CI smoke evaluation; analyst-feedback export (one
  item per alert, final decision) for real data.
- **Documentation**: architecture contract, API, configuration reference
  generated from the code, deployment, operations runbook, security model,
  user guide, evaluation guide.

#### Changed

- The analyst web application in `src/lg_front` is rebuilt as a client of
  the new API (see its README).
- Configuration moved from `ConfigManager` YAML files to typed settings;
  `ConfigManager` remains as a thin read-only facade for agents.

#### Removed

- The proof-of-concept runtime (`app_initializer`, in-process queues and
  deduplication, schema creation at startup), empty placeholder modules and
  documentation, and dead files (`Backup/`, `test.html`,
  `test_claude_simple.py`, `test_claude_workflow.py`, `setup_api_key.sh`).

#### Security

- See [docs/security.md](docs/security.md) for the threat model and
  controls, and [SECURITY.md](SECURITY.md) for vulnerability reporting.
- Release hardening from the final review: login attempts are counted
  before the password check (lockout holds under concurrency); SSO is
  blocked by a disabled local account even without `email_verified`; open
  WebSockets re-check logout, deactivation and suspension and are capped per
  principal and tenant; LangGraph checkpoint tables are under tenant RLS;
  CLI-created accounts and reprocessing are audited; tenant-less login is
  resolved by password; response targets exclude parent processes and a
  built-in list of critical processes, and are scoped to the alert's hosts;
  containment on rule evidence applies only to corroborated targets;
  verdict-cache hits are severity-bound and invalidated by true positives;
  LLM-normalised alerts are never closed automatically; more command-line
  credential forms are redacted; URL guardrails canonicalise hosts;
  cookie endpoints check `Origin`; the compose stack trusts only its own
  proxy's `X-Forwarded-For`; the runtime image carries no pip or setuid
  binaries; Helm refuses enrichment keys in values.

#### Fixed

- Worker runs could wedge when a cancellation was swallowed inside redis-py
  on Python 3.11; cancelled polls, lost resume messages and stale resumes are
  recovered from PostgreSQL; ledger transitions and their audit entries are
  atomic; retention removes checkpoints with their alert and expires failed
  alerts; the token budget survives a Redis restart; dead consumers leave the
  group; settings PATCHes no longer lose concurrent updates.
- A worker killed after a graph step's writes were saved but before that
  step's checkpoint (seen right after `__start__`) no longer leaves its alert
  stuck in `processing` with the run marked `completed`: the retry continues
  the thread from the saved writes.
- Throughput: single-tenant workers use their full concurrency, LLM slots
  follow `worker.concurrency`, dispatch is batched with ingest admission
  control, and new indexes serve the dashboard and alert-list filters (see
  docs/performance.md).

## Before 0.2.0

Proof of concept: a single-process LangGraph workflow demonstrating
LLM-assisted alert triage. Not supported.
