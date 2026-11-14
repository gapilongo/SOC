/**
 * The investigation read model: what the investigation view (/alerts/:id)
 * renders. One shape for the verdict sentence, the claims and the
 * observations they rest on, what is not established, the steps, the track
 * record and the proposed response.
 *
 * `GET /alerts/{id}/investigation` (issue #411) will serve this shape. Until
 * its types are in the OpenAPI document, the shape is declared here from the
 * issue text and `adaptInvestigation` builds it from what the API gives
 * today (the alert detail, its escalation, its timeline and the response
 * preview). The adapter invents nothing: a field today's data cannot fill is
 * empty or null and named in `not_yet_available`, and the view says so.
 */

import { readFindings, text } from './fields';
import type { AlertDetailOut, AlertEventOut, EscalationOut, FindingOut, Open, PreviewActionOut, ResponsePreviewOut } from './types';
import { humanize } from '../../../lib/format';
import { asObjectOrNull } from '../../../lib/json';

// The shape --------------------------------------------------------------------

/** The four outcomes, each tied to what happens next. */
export const OUTCOME_CATEGORIES = ['ai_closed', 'ai_closed_audit', 'needs_decision_malicious', 'needs_decision_unsure'] as const;
export type OutcomeCategory = (typeof OUTCOME_CATEGORIES)[number];

export const CLOSED_BY_KINDS = ['ai', 'suppression_rule', 'cached_verdict', 'analyst'] as const;
export type ClosedByKind = (typeof CLOSED_BY_KINDS)[number];

export interface OutcomeReasonOut {
  /** The decide or close code behind the sentence (`grey_zone`, `analyst:true_positive` ...). */
  code: string | null;
  /** Why the alert is with a person, or why it was closed, in plain words. */
  text: string;
}

export interface ClosedByOut {
  kind: Open<ClosedByKind>;
  reason: string | null;
}

export interface InvestigationOutcomeOut {
  /** Null while the alert is in none of the four (being investigated, waiting for an approval, closed by a rule or a person). */
  category: Open<OutcomeCategory> | null;
  reason: OutcomeReasonOut | null;
  closed_by: ClosedByOut | null;
}

/** The summary of the analysis, marked with who wrote it. */
export interface InvestigationSummaryOut {
  text: string;
  source: 'model' | 'rules' | null;
}

export const CLAIM_CHECKS = ['supported', 'unsupported', 'rejected'] as const;
export type ClaimCheck = (typeof CLAIM_CHECKS)[number];

export interface ClaimOut {
  id: string;
  text: string;
  /** Which way the claim points; null when the data does not say. */
  direction: Open<'malicious' | 'benign'> | null;
  /** The observations the claim rests on. */
  observation_ids: string[];
  check: Open<ClaimCheck>;
  check_reason?: string | null;
}

/** One line of an observation's excerpt; `marks` are `[start, end)` character ranges to highlight. */
export interface ExcerptLineOut {
  text: string;
  marks?: Array<[number, number]>;
}

export const OBSERVATION_OUTCOMES = ['success', 'empty', 'failed'] as const;
export type ObservationOutcome = (typeof OBSERVATION_OUTCOMES)[number];

/** What one tool call returned. */
export interface ObservationOut {
  id: string;
  title: string;
  tool: string;
  at: string | null;
  outcome: Open<ObservationOutcome>;
  /** Rows returned, when the tool counts them. */
  rows?: number | null;
  excerpt: ExcerptLineOut[];
  /** The full, bounded result, shown on demand. */
  detail?: string | null;
  input_sha256?: string | null;
  output_sha256?: string | null;
  /** Served from the provider cache: fetched before this investigation ran. */
  cached?: boolean;
  /** Came from a test fixture, not a live lookup. */
  simulated?: boolean;
}

export interface NotEstablishedItemOut {
  what: string;
  why?: string | null;
  observation_id?: string | null;
}

/** Three kinds, never merged: none of them counts for or against the outcome. */
export interface NotEstablishedOut {
  checked_empty: NotEstablishedItemOut[];
  not_checked: NotEstablishedItemOut[];
  unavailable: NotEstablishedItemOut[];
}

export const STEP_ACTORS = ['code', 'model', 'check', 'policy', 'person'] as const;
export type StepActor = (typeof STEP_ACTORS)[number];

/** One investigation step in plain words (no engine node names). */
export interface StepOut {
  ts: string;
  actor: Open<StepActor>;
  text: string;
  produced?: string | null;
}

/** The counts behind this outcome category for the tenant; a rate is refused under `min_samples`. */
export interface TrackRecordOut {
  confirmed: number;
  total: number;
  window_days: number;
  min_samples: number;
}

export interface InvestigationResponseOut {
  actions: PreviewActionOut[];
  generated_at?: string | null;
  dry_run_forced?: boolean;
}

export interface InvestigationOut {
  version: number;
  alert_id: string;
  outcome: InvestigationOutcomeOut;
  summary: InvestigationSummaryOut | null;
  claims: ClaimOut[];
  observations: ObservationOut[];
  not_established: NotEstablishedOut;
  steps: StepOut[];
  track_record: TrackRecordOut | null;
  response: InvestigationResponseOut | null;
  /** The fields that stay empty until the harness (typed facts, the checker, hashes, the track record). */
  not_yet_available: string[];
}

/** The version of the shape this file declares. */
export const INVESTIGATION_VERSION = 1;

// The adapter ---------------------------------------------------------------------

/** What the adapter always leaves empty: only the harness and #411 can fill it. */
export const ADAPTER_GAPS = [
  'claims.check',
  'claims.direction',
  'observations.rows',
  'observations.input_sha256',
  'observations.output_sha256',
  'not_established.not_checked',
  'track_record',
] as const;

const MAX_CLAIMS = 12;
const MAX_CLAIM_CHARS = 400;
const MAX_EXCERPT_LINES = 6;
const MAX_LINE_CHARS = 200;
const MAX_NOT_CHECKED = 8;
const MAX_STEP_CHARS = 300;
const MAX_SIGNALS = 6;

type Rec = Record<string, unknown>;

function clip(value: string, max: number): string {
  const flat = value.trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1).trimEnd()}…`;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((v) => (typeof v === 'string' && v.trim() ? [v.trim()] : []));
}

function scalar(value: unknown): string | null {
  if (typeof value === 'string') return value.trim() ? value.trim() : null;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    const parts = value.flatMap((v) => (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? [String(v)] : []));
    return parts.length ? parts.join(', ') : null;
  }
  return null;
}

function count(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

/** "Assessment in the grey zone." from "assessment in the grey zone". */
function sentence(value: string): string {
  const flat = value.trim();
  const capital = flat.charAt(0).toUpperCase() + flat.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

const DECISION_WORDS: Record<string, string> = {
  true_positive: 'true positive',
  false_positive: 'false positive',
  benign_positive: 'benign, expected here',
  needs_more_info: 'needs more information',
};

const decisionWords = (value: unknown) => {
  const v = text(value);
  return v ? (DECISION_WORDS[v] ?? humanize(v).toLowerCase()) : null;
};

// Outcome

const ACTIVE_ESCALATION = new Set(['open', 'claimed', 'expired']);

function closedBy(summary: Rec, closeReason: string | null): ClosedByOut | null {
  const suppressed = asObjectOrNull(summary.suppressed_by);
  const type = text(suppressed?.type) ?? closeReason;
  if (type === 'suppression_rule') {
    const name = text(suppressed?.name);
    return { kind: 'suppression_rule', reason: name ? `Suppression rule "${clip(name, 120)}" matched this alert.` : 'A suppression rule matched this alert.' };
  }
  if (type === 'verdict_cache') {
    const earlier = decisionWords(suppressed?.decision);
    return {
      kind: 'cached_verdict',
      reason: earlier
        ? `An analyst decided the same alert before (${earlier}); that verdict was applied.`
        : 'An analyst decided the same alert before; that verdict was applied.',
    };
  }
  if (!closeReason) return null;
  if (closeReason.startsWith('analyst:')) {
    const decided = decisionWords(closeReason.slice('analyst:'.length));
    return { kind: 'analyst', reason: decided ? `An analyst decided: ${decided}.` : 'An analyst decided it.' };
  }
  const policy = text(asObjectOrNull(summary.decision)?.reason);
  if (closeReason === 'ai_closed:audit_required') {
    return { kind: 'ai', reason: policy ? sentence(policy) : 'The analysis judged it benign. It stays in the pool for the blind audit.' };
  }
  if (closeReason === 'policy:close') return { kind: 'ai', reason: policy ? sentence(policy) : 'The decision policy closed it.' };
  if (closeReason === 'policy:response') return { kind: 'ai', reason: 'The decision policy judged it malicious and the response plan finished.' };
  if (closeReason === 'triage:false_positive') return { kind: 'ai', reason: 'Triage judged it a false positive.' };
  return null;
}

function outcome(alert: AlertDetailOut, escalation: EscalationOut | null): InvestigationOutcomeOut {
  const summary: Rec = asObjectOrNull(alert.summary) ?? {};
  const analysis = asObjectOrNull(summary.analysis);
  const decision = asObjectOrNull(summary.decision);
  if (alert.status === 'closed') {
    const closeReason = text(summary.close_reason);
    const by = closedBy(summary, closeReason);
    const category = by?.kind !== 'ai' ? null : closeReason === 'ai_closed:audit_required' ? 'ai_closed_audit' : 'ai_closed';
    return { category, reason: by?.reason ? { code: closeReason, text: by.reason } : null, closed_by: by };
  }
  if (alert.status === 'waiting_human' || (escalation && ACTIVE_ESCALATION.has(escalation.status))) {
    const verdict = text(analysis?.verdict) ?? text(asObjectOrNull(escalation?.summary)?.verdict);
    const why = text(escalation?.reason) ?? text(decision?.reason);
    const code = text(asObjectOrNull(escalation?.routing)?.code) ?? text(decision?.code);
    return {
      category: verdict === 'malicious' ? 'needs_decision_malicious' : 'needs_decision_unsure',
      reason: why ? { code, text: `The AI did not close this alert: ${sentence(why).replace(/^./, (c) => c.toLowerCase())}` } : null,
      closed_by: null,
    };
  }
  return { category: null, reason: null, closed_by: null };
}

// Summary

function summaryOf(alert: AlertDetailOut, escalation: EscalationOut | null): InvestigationSummaryOut | null {
  const analysis = asObjectOrNull(asObjectOrNull(alert.summary)?.analysis);
  const esc = asObjectOrNull(escalation?.summary);
  const conclusion = text(analysis?.conclusion) ?? text(esc?.conclusion);
  if (!conclusion) return null;
  const llm = typeof analysis?.llm_used === 'boolean' ? analysis.llm_used : typeof esc?.llm_used === 'boolean' ? esc.llm_used : null;
  return { text: conclusion.trim(), source: llm === null ? null : llm ? 'model' : 'rules' };
}

// Observations

const KIND_WORDS: Record<string, string> = { ip: 'IP address', url: 'URL', hash: 'file hash', email: 'e-mail address' };
const kindWords = (kind: string) => KIND_WORDS[kind] ?? kind.replace(/_/g, ' ');

const FAILED_WORDS: Record<string, (source: string) => string> = {
  not_configured: (s) => `${s} is not configured for this tenant.`,
  unsupported: (s) => `${s} does not answer for this kind of indicator.`,
  rate_limited: (s) => `${s} refused the lookup: its rate limit was reached.`,
  skipped: (s) => `The lookup at ${s} was skipped.`,
  error: (s) => `${s} answered with an error.`,
};

function failedWords(f: FindingOut): string {
  return (FAILED_WORDS[f.status] ?? ((s: string) => `${s} did not answer (${humanize(f.status).toLowerCase()}).`))(f.source);
}

function observationOutcome(f: FindingOut): ObservationOutcome {
  if (f.status === 'ok') return 'success';
  return f.status === 'not_found' ? 'empty' : 'failed';
}

/** `key  value` lines of a lookup's data, the verdict first and highlighted when it points to a threat. */
function excerpt(f: FindingOut, outcomeOf: ObservationOutcome): { lines: ExcerptLineOut[]; detail: string | null } {
  if (outcomeOf === 'empty') return { lines: [{ text: `No record for this ${kindWords(f.kind)}.` }], detail: null };
  if (outcomeOf === 'failed') return { lines: [{ text: failedWords(f) }], detail: null };
  const data = asObjectOrNull(f.data) ?? {};
  const rows: Array<[string, string]> = [['verdict', f.verdict || 'unknown']];
  for (const [key, value] of Object.entries(data)) {
    if (key === 'simulated') continue;
    const shown = scalar(value);
    if (shown !== null) rows.push([key.replace(/_/g, ' '), shown]);
  }
  const width = Math.min(28, Math.max(...rows.map(([k]) => k.length)));
  const line = ([key, value]: [string, string]) => clip(`${key.padEnd(width)}  ${value}`, MAX_LINE_CHARS);
  const lines: ExcerptLineOut[] = rows.slice(0, MAX_EXCERPT_LINES).map((row, i) => {
    const out: ExcerptLineOut = { text: line(row) };
    // The highlight is set here, by code, on the provider's own verdict: never on anything a model wrote.
    if (i === 0 && (f.verdict === 'malicious' || f.verdict === 'suspicious')) out.marks = [[width + 2, width + 2 + f.verdict.length]];
    return out;
  });
  return { lines, detail: rows.length > MAX_EXCERPT_LINES ? rows.map(line).join('\n') : null };
}

interface Observed {
  finding: FindingOut;
  observation: ObservationOut;
}

function observe(alert: AlertDetailOut): Observed[] {
  return readFindings(alert).map((f, i) => {
    const result = observationOutcome(f);
    const { lines, detail } = excerpt(f, result);
    const target = clip(f.target, 160);
    const observation: ObservationOut = {
      id: `O-${String(i + 1).padStart(2, '0')}`,
      title: f.origin === 'history' ? `Earlier alerts of this tenant for ${kindWords(f.kind)} ${target}` : `Reputation of ${kindWords(f.kind)} ${target}`,
      tool: f.source,
      at: text(f.checked_at),
      outcome: result,
      rows: null,
      excerpt: lines,
      detail,
      input_sha256: null,
      output_sha256: null,
      cached: Boolean(f.cached),
      simulated: asObjectOrNull(f.data)?.simulated === true,
    };
    return { finding: f, observation };
  });
}

// Claims

interface Stated {
  text: string;
  direction: 'malicious' | 'benign' | null;
}

/**
 * What the model stated: the reasoning of the analysis (direction unknown),
 * then the indicators the triage model named for and against. The signals of
 * the rules (`rule_tp`, `rule_fp`, `threat_indicators`) are not claims: code
 * decided them, and the steps name them.
 */
function stated(summary: Rec): Stated[] {
  const analysis = asObjectOrNull(summary.analysis);
  const triage = asObjectOrNull(summary.triage);
  const all: Stated[] = [
    ...strings(analysis?.reasoning).map((t): Stated => ({ text: t, direction: null })),
    ...strings(triage?.llm_tp).map((t): Stated => ({ text: t, direction: 'malicious' })),
    ...strings(triage?.llm_fp).map((t): Stated => ({ text: t, direction: 'benign' })),
  ];
  const seen = new Set<string>();
  return all.filter((s) => {
    const key = s.text.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Today's check: a claim is supported when it names the target of a lookup
 * that returned data. A claim that names only lookups that found nothing, or
 * no lookup at all, is unsupported: nothing found is never proof.
 */
function claimsOf(summary: Rec, observed: Observed[]): ClaimOut[] {
  return stated(summary)
    .slice(0, MAX_CLAIMS)
    .map((s, i): ClaimOut => {
      const lower = s.text.toLowerCase();
      const named = observed.filter(({ finding }) => finding.target.trim().length >= 3 && lower.includes(finding.target.trim().toLowerCase()));
      const backing = named.filter(({ observation }) => observation.outcome === 'success');
      const supported = backing.length > 0;
      return {
        id: String(i + 1),
        text: clip(s.text, MAX_CLAIM_CHARS),
        direction: s.direction,
        observation_ids: (supported ? backing : named).map(({ observation }) => observation.id),
        check: supported ? 'supported' : 'unsupported',
        check_reason: supported ? null : named.length > 0 ? 'The lookup it names returned nothing, and nothing found is never counted as proof.' : 'It names no lookup.',
      };
    });
}

// Not established

const LOOKED_UP_KINDS: Array<[string, string]> = [
  ['ips', 'ip'],
  ['domains', 'domain'],
  ['urls', 'url'],
  ['hashes', 'hash'],
];

function notEstablished(alert: AlertDetailOut, observed: Observed[]): NotEstablishedOut {
  const out: NotEstablishedOut = { checked_empty: [], not_checked: [], unavailable: [] };
  const targets = new Set<string>();
  for (const { finding, observation } of observed) {
    targets.add(finding.target.trim().toLowerCase());
    if (observation.outcome === 'empty') out.checked_empty.push({ what: observation.title, why: `${finding.source} has no record.`, observation_id: observation.id });
    else if (observation.outcome === 'failed') {
      const item = { what: observation.title, why: failedWords(finding), observation_id: observation.id };
      (finding.status === 'skipped' ? out.not_checked : out.unavailable).push(item);
    }
  }
  // Indicators of the alert that no lookup was recorded for (only when an analysis ran at all).
  const entities = asObjectOrNull(asObjectOrNull(alert.normalized)?.entities);
  if (!entities || !asObjectOrNull(asObjectOrNull(alert.summary)?.analysis)) return out;
  const missing: NotEstablishedItemOut[] = [];
  for (const [key, kind] of LOOKED_UP_KINDS) {
    for (const value of strings(entities[key])) {
      if (!targets.has(value.toLowerCase())) missing.push({ what: `Reputation of ${kindWords(kind)} ${clip(value, 120)}`, why: 'No lookup was recorded for it.' });
    }
  }
  out.not_checked.push(...missing.slice(0, MAX_NOT_CHECKED));
  if (missing.length > MAX_NOT_CHECKED) {
    out.not_checked.push({ what: `${missing.length - MAX_NOT_CHECKED} more indicators of this alert`, why: 'No lookup was recorded for them.' });
  }
  return out;
}

// Steps

const CLOSE_WORDS: Record<string, string> = {
  'ai_closed:audit_required': 'on the analysis alone; it stays in the pool for the blind audit',
  'policy:close': 'by the decision policy',
  'policy:response': 'after the response plan finished',
  'triage:false_positive': 'as a false positive at triage',
  suppression_rule: 'by a suppression rule',
  verdict_cache: 'on an earlier analyst verdict',
};

function closeWords(reason: string | null): string {
  if (!reason) return '';
  if (reason.startsWith('analyst:')) return ` on the analyst's decision (${decisionWords(reason.slice('analyst:'.length))})`;
  return CLOSE_WORDS[reason] ? ` ${CLOSE_WORDS[reason]}` : '';
}

function statusCounts(value: unknown): string | null {
  const statuses = asObjectOrNull(value);
  if (!statuses) return null;
  const parts = Object.entries(statuses).flatMap(([k, n]) => (count(n) ? [`${n} ${humanize(k).toLowerCase()}`] : []));
  return parts.length ? parts.join(' · ') : null;
}

type StepWords = Pick<StepOut, 'actor' | 'text'> & { produced?: string | null };

/** The signals the rules raised, as the summary names them (codes such as `file_hash_present`). */
interface Signals {
  attack: string[];
  falsePositive: string[];
  threat: string[];
}

function signalsOf(summary: Rec): Signals {
  const triage = asObjectOrNull(summary.triage);
  return { attack: strings(triage?.rule_tp), falsePositive: strings(triage?.rule_fp), threat: strings(asObjectOrNull(summary.analysis)?.threat_indicators) };
}

/** "file hash present, process execution +2 more". */
function named(codes: string[]): string {
  const words = codes.slice(0, MAX_SIGNALS).map((c) => clip(c.replace(/_/g, ' '), 60));
  return codes.length > MAX_SIGNALS ? `${words.join(', ')} +${codes.length - MAX_SIGNALS} more` : words.join(', ');
}

/** A completed workflow stage in plain words; the stage's engine name never reaches the page. */
function stageStep(node: string, d: Rec, signals: Signals): StepWords | null {
  const model = d.llm_used === true;
  switch (node) {
    case 'gate':
      if (d.suppressed !== true) return { actor: 'check', text: 'Checked the suppression rules and earlier analyst verdicts: none applies.' };
      return d.verdict_cache === true
        ? { actor: 'check', text: 'An analyst decided the same alert before: that verdict applies, so no new investigation ran.' }
        : { actor: 'check', text: 'A suppression rule matched: no investigation ran.' };
    case 'triage': {
      // The rules' signals by name when the summary has them, else the counts of the event.
      const signs =
        signals.attack.length || signals.falsePositive.length
          ? [signals.attack.length ? `rule signs of an attack: ${named(signals.attack)}` : null, signals.falsePositive.length ? `of a false positive: ${named(signals.falsePositive)}` : null]
          : [count(d.rule_tp) !== null ? plural(d.rule_tp as number, 'sign of an attack', 'signs of an attack') : null, count(d.rule_fp) !== null ? `${d.rule_fp} of a false positive` : null];
      return {
        actor: model ? 'model' : 'code',
        text: model ? 'Triage: the rules and the model scored the alert.' : 'Triage: the rules scored the alert. No model was used.',
        produced: signs.filter(Boolean).join(' · ') || null,
      };
    }
    case 'correlation': {
      const related = count(d.related_count);
      return {
        actor: model ? 'model' : 'code',
        text: `Looked for related alerts of this tenant${related !== null ? `: ${related} found` : ''}${d.burst === true ? ', arriving in a burst' : ''}.`,
        produced: count(d.indicators) !== null ? plural(d.indicators as number, 'shared indicator', 'shared indicators') : null,
      };
    }
    case 'analysis': {
      const lookups = count(d.tool_steps);
      const verdict = text(d.verdict);
      return {
        actor: model ? 'model' : 'code',
        text: model
          ? `The model wrote the analysis${lookups !== null ? ` after ${plural(lookups, 'lookup', 'lookups')}` : ''}.`
          : 'The rules wrote the analysis. No model was used.',
        produced: [verdict ? `assessed as ${humanize(verdict).toLowerCase()}` : null, signals.threat.length ? `rule signals: ${named(signals.threat)}` : null].filter(Boolean).join(' · ') || null,
      };
    }
    case 'decide': {
      const reason = text(d.reason);
      const route = text(d.route);
      const what = route === 'close' ? 'close the alert' : route === 'plan_response' ? 'plan a response' : 'send it to an analyst';
      return { actor: 'policy', text: `Decision policy: ${what}${reason ? `. ${sentence(reason)}` : '.'}` };
    }
    case 'escalate': {
      const level = text(d.level);
      return d.attached === true && d.created !== true
        ? { actor: 'policy', text: 'Added to an escalation that is already open for the same activity.' }
        : { actor: 'policy', text: `Sent to an analyst${level ? `, level ${level}` : ''}.` };
    }
    case 'plan_response': {
      const parts = [
        count(d.auto) ? `${d.auto} to run` : null,
        count(d.awaiting) ? `${d.awaiting} waiting for approval` : null,
        count(d.blocked) ? `${d.blocked} blocked` : null,
        count(d.done) ? `${d.done} already done` : null,
      ].filter(Boolean);
      return { actor: 'policy', text: 'Planned the response.', produced: parts.join(' · ') || null };
    }
    case 'execute_actions':
      return { actor: 'code', text: 'Ran the response actions that were approved.', produced: statusCounts(d.statuses) };
    case 'close': {
      const disposition = text(d.disposition);
      return { actor: 'policy', text: `Closed${disposition ? ` as ${humanize(disposition).toLowerCase()}` : ''}${closeWords(text(d.close_reason))}.` };
    }
    // Waiting for a person: the person's own event says what happened.
    case 'await_analyst':
    case 'await_approval':
      return null;
    default:
      return { actor: 'code', text: 'An investigation step finished.' };
  }
}

function eventStep(e: AlertEventOut, signals: Signals): StepWords | null {
  const d: Rec = asObjectOrNull(e.data) ?? {};
  const actor: StepActor = e.actor_type === 'user' ? 'person' : e.actor_type === 'agent' ? 'model' : 'code';
  if (e.event_type === 'node.completed') return stageStep(e.node ?? '', d, signals);
  switch (e.event_type) {
    case 'analyst.decision': {
      const decided = decisionWords(d.decision);
      return { actor: 'person', text: `An analyst decided${decided ? `: ${decided}` : ''}${d.folded === true ? ' (with the alerts grouped under one escalation)' : ''}.` };
    }
    case 'actions.approval': {
      const parts = [count(d.approved) ? `${d.approved} approved` : null, count(d.rejected) ? `${d.rejected} rejected` : null].filter(Boolean);
      return { actor: 'person', text: 'A person decided on the response actions.', produced: parts.join(' · ') || null };
    }
    case 'note':
      return text(d.text) ? { actor: 'person', text: `Note: ${text(d.text)}` } : null;
    case 'escalation.detached':
      return { actor: 'policy', text: 'Given its own escalation, apart from the group it was decided with.' };
    case 'action.verified':
      return { actor: 'check', text: `Checked again that ${text(d.action_type) ? humanize(text(d.action_type)).toLowerCase() : 'the action'} is in effect: it is.` };
    case 'action.verification_failed':
      return { actor: 'check', text: `Could not confirm that ${text(d.action_type) ? humanize(text(d.action_type)).toLowerCase() : 'the action'} is in effect${text(d.reason) ? `: ${text(d.reason)}` : ''}.` };
    case 'alert.reopened':
      return { actor: 'policy', text: 'Reopened: a related alert was confirmed as a threat.' };
    default: {
      const note = text(d.note);
      return { actor, text: note ?? sentence(humanize(e.event_type)) };
    }
  }
}

function stepsOf(events: readonly AlertEventOut[], summary: Rec): StepOut[] {
  const signals = signalsOf(summary);
  return [...events]
    .sort((a, b) => a.ts.localeCompare(b.ts) || a.id - b.id)
    .flatMap((e): StepOut[] => {
      const words = eventStep(e, signals);
      return words ? [{ ts: e.ts, actor: words.actor, text: clip(words.text, MAX_STEP_CHARS), produced: words.produced ?? null }] : [];
    });
}

// The whole

export interface AdapterInput {
  alert: AlertDetailOut;
  /** The alert's escalation, when it has one. */
  escalation?: EscalationOut | null;
  /** The alert's timeline (any order). */
  events?: readonly AlertEventOut[];
  /** The response plan a true positive would start, for an escalation still waiting. */
  preview?: ResponsePreviewOut | null;
}

/** The investigation read model, built from today's API responses. */
export function adaptInvestigation({ alert, escalation = null, events = [], preview = null }: AdapterInput): InvestigationOut {
  const summary: Rec = asObjectOrNull(alert.summary) ?? {};
  const observed = observe(alert);
  return {
    version: INVESTIGATION_VERSION,
    alert_id: alert.id,
    outcome: outcome(alert, escalation),
    summary: summaryOf(alert, escalation),
    claims: claimsOf(summary, observed),
    observations: observed.map((o) => o.observation),
    not_established: notEstablished(alert, observed),
    steps: stepsOf(events, summary),
    track_record: null,
    response: preview && Array.isArray(preview.actions) ? { actions: preview.actions, generated_at: text(preview.generated_at), dry_run_forced: Boolean(preview.dry_run_forced) } : null,
    not_yet_available: [...ADAPTER_GAPS],
  };
}
