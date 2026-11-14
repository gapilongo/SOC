/**
 * The fallback of the investigation view for an API that predates
 * `GET /alerts/{id}/investigation` (it answers 404 there): the same read
 * model (`InvestigationOut`, api/types.ts), built from what that API does
 * give (the alert detail, its escalation, its timeline and the response
 * preview).
 *
 * The adapter invents nothing: a field those responses cannot fill is empty
 * or null and named in `pending_harness`, and the view says so. It follows
 * the read model's rules: only the fast model's indicators are model claims,
 * a claim is supported only by a lookup that returned data, and an empty or
 * failed lookup never backs one.
 */

import { readFindings, text } from './fields';
import type {
  AlertDetailOut,
  AlertEventOut,
  EscalationOut,
  FindingOut,
  InvestigationClaimOut,
  InvestigationClosedByOut,
  InvestigationObservationOut,
  InvestigationOut,
  InvestigationOutcomeOut,
  InvestigationSummaryOut,
  NotEstablishedOut,
  ObservationOutcome,
  OutcomeCategory,
  PendingHarnessFieldOut,
  PlainStepOut,
  PreviewActionOut,
  ProposedActionOut,
  ProposedResponseOut,
  ResponsePreviewOut,
  StepActor,
} from './types';
import { humanize } from '../../../lib/format';
import { asObjectOrNull } from '../../../lib/json';

/** The version of the read model the adapter builds. */
export const INVESTIGATION_VERSION = 1;

/** What an API without the read model cannot give at all (the issue that added the read model). */
export const ADAPTER_GAPS: readonly PendingHarnessFieldOut[] = [
  { field: 'track_record', why: 'This API version does not count how often analysts confirmed an outcome.', issue: 411 },
  { field: 'outcome.blockers', why: 'This API version does not say why the AI may not close the alert on its own.', issue: 411 },
  { field: 'observations[].input_sha256', why: 'This API version does not return the hashes of a tool call.', issue: 411 },
  { field: 'claims[].check', why: 'No checker compares claims with observations yet: a claim is supported only when a lookup backs it, and none is ever rejected.', issue: 207 },
  { field: 'observations[].excerpt[].marks', why: 'Highlight ranges are set by typed query templates, which do not exist yet.', issue: 200 },
  { field: 'not_established.not_checked', why: 'Without a playbook the list names only the indicators of the alert that no lookup was recorded for.', issue: 205 },
];

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

function closedBy(alert: AlertDetailOut, summary: Rec, closeReason: string | null): InvestigationClosedByOut | null {
  const suppressed = asObjectOrNull(summary.suppressed_by);
  const type = text(suppressed?.type) ?? closeReason;
  const by = (kind: InvestigationClosedByOut['kind'], code: string, words: string, extra: Partial<InvestigationClosedByOut> = {}): InvestigationClosedByOut => ({
    kind,
    reason: { code, sentence: words },
    at: text(alert.closed_at),
    decision: null,
    rule_id: null,
    rule_name: null,
    source_alert_id: null,
    ...extra,
  });
  if (type === 'suppression_rule') {
    const name = text(suppressed?.name);
    return by('suppression_rule', 'suppression_rule', 'A suppression rule matched this alert.', { rule_id: text(suppressed?.rule_id), rule_name: name ? clip(name, 120) : null });
  }
  if (type === 'verdict_cache') {
    return by('cached_verdict', 'verdict_cache', 'An analyst decided the same alert before; that verdict was applied.', {
      decision: text(suppressed?.decision),
      source_alert_id: text(suppressed?.source_alert_id),
    });
  }
  if (!closeReason) return null;
  if (closeReason.startsWith('analyst:')) {
    const decision = text(closeReason.slice('analyst:'.length));
    return by('analyst', closeReason, 'An analyst decided it.', { decision });
  }
  const policy = text(asObjectOrNull(summary.decision)?.reason);
  if (closeReason === 'ai_closed:audit_required') {
    return by('ai', closeReason, policy ? sentence(policy) : 'The analysis judged it benign. It stays in the pool for the blind audit.');
  }
  if (closeReason === 'policy:close') return by('ai', closeReason, policy ? sentence(policy) : 'The decision policy closed it.');
  if (closeReason === 'policy:response') return by('ai', closeReason, 'The decision policy judged it malicious and the response plan finished.');
  if (closeReason === 'triage:false_positive') return by('ai', closeReason, 'Triage judged it a false positive.');
  return null;
}

function outcome(alert: AlertDetailOut, escalation: EscalationOut | null): InvestigationOutcomeOut | null {
  const summary: Rec = asObjectOrNull(alert.summary) ?? {};
  const analysis = asObjectOrNull(summary.analysis);
  const decision = asObjectOrNull(summary.decision);
  const shell = { blockers: [], evidence: [] };
  if (alert.status === 'closed') {
    const closeReason = text(summary.close_reason);
    const by = closedBy(alert, summary, closeReason);
    const category: OutcomeCategory | null = by?.kind !== 'ai' ? null : closeReason === 'ai_closed:audit_required' ? 'ai_closed_audit' : 'ai_closed_evidence';
    return { ...shell, category, reason: by?.reason ?? null, closed_by: by };
  }
  if (alert.status === 'waiting_human' || (escalation && ACTIVE_ESCALATION.has(escalation.status))) {
    const verdict = text(analysis?.verdict) ?? text(asObjectOrNull(escalation?.summary)?.verdict);
    const why = text(escalation?.reason) ?? text(decision?.reason);
    const code = text(asObjectOrNull(escalation?.routing)?.code) ?? text(decision?.code);
    return {
      ...shell,
      category: verdict === 'malicious' ? 'needs_decision' : 'needs_review',
      reason: why ? { code: code ?? 'unknown', sentence: `The AI did not close this alert: ${sentence(why).replace(/^./, (c) => c.toLowerCase())}` } : null,
      closed_by: null,
    };
  }
  // Still processed, waiting for an approval, or failed: the alert's status says which.
  return null;
}

// Summary

function summaryOf(alert: AlertDetailOut, escalation: EscalationOut | null): InvestigationSummaryOut {
  const analysis = asObjectOrNull(asObjectOrNull(alert.summary)?.analysis);
  const esc = asObjectOrNull(escalation?.summary);
  const conclusion = text(analysis?.conclusion) ?? text(esc?.conclusion);
  if (!conclusion) return { text: null, written_by: null };
  const llm = typeof analysis?.llm_used === 'boolean' ? analysis.llm_used : typeof esc?.llm_used === 'boolean' ? esc.llm_used : null;
  return { text: conclusion.trim(), written_by: llm === null ? null : llm ? 'model' : 'rules' };
}

// Observations

const FAILED_WORDS: Record<string, string> = {
  not_configured: 'The source is not configured for this tenant.',
  unsupported: 'The source does not answer for this kind of indicator.',
  rate_limited: 'The source refused the lookup: its rate limit was reached.',
  skipped: 'The lookup was skipped.',
  error: 'The source did not answer.',
};

const failedWords = (f: FindingOut) => FAILED_WORDS[f.status] ?? 'The source did not answer.';

function observationOutcome(f: FindingOut): ObservationOutcome {
  if (f.status === 'ok') return 'success';
  return f.status === 'not_found' ? 'empty' : 'failed';
}

/** The provider's answer as lines: its status and verdict, then its data, one value a line. */
function excerpt(f: FindingOut, result: ObservationOutcome): { lines: string[]; truncated: boolean } {
  if (result !== 'success') return { lines: [`${f.source}  ${f.status}`], truncated: false };
  const lines = [`${f.source}  ${f.status}  ${f.verdict || 'unknown'}`];
  for (const [key, value] of Object.entries(asObjectOrNull(f.data) ?? {})) {
    if (key === 'simulated') continue;
    const shown = scalar(value);
    if (shown !== null) lines.push(`  ${clip(`${key}: ${shown}`, MAX_LINE_CHARS - 2)}`);
  }
  return { lines: lines.slice(0, MAX_EXCERPT_LINES), truncated: lines.length > MAX_EXCERPT_LINES };
}

interface Observed {
  finding: FindingOut;
  observation: InvestigationObservationOut;
}

function observe(alert: AlertDetailOut): Observed[] {
  return readFindings(alert).map((f, i) => {
    const result = observationOutcome(f);
    const { lines, truncated } = excerpt(f, result);
    const observation: InvestigationObservationOut = {
      id: `O-${String(i + 1).padStart(2, '0')}`,
      tool: f.origin === 'history' ? 'history' : 'reputation',
      title: f.origin === 'history' ? 'Earlier alerts of this customer for the same entity' : 'Threat-intelligence reputation',
      kind: text(f.kind),
      target: text(f.target) ? clip(f.target, 128) : null,
      sources: [f.source],
      at: text(f.checked_at),
      outcome: result,
      verdict: result === 'success' ? f.verdict || 'unknown' : null,
      cached: Boolean(f.cached),
      excerpt: lines.map((line) => ({ text: line, marks: [] })),
      excerpt_truncated: truncated,
      input_sha256: null,
      output_sha256: null,
    };
    return { finding: f, observation };
  });
}

// Claims

/**
 * The fast model's indicators, in its own words, cite nothing: unsupported.
 * The rules add one claim per lookup that reported a threat, and that lookup
 * backs it. The signals of the rules and the model's step-by-step reasoning
 * are not claims.
 */
function claimsOf(summary: Rec, observed: Observed[]): InvestigationClaimOut[] {
  const triage = asObjectOrNull(summary.triage);
  const seen = new Set<string>();
  const model = [
    ...strings(triage?.llm_tp).map((t) => ({ text: t, direction: 'malicious' as const })),
    ...strings(triage?.llm_fp).map((t) => ({ text: t, direction: 'benign' as const })),
  ].filter((s) => {
    const key = s.text.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const claims: Array<Omit<InvestigationClaimOut, 'id'>> = model.map((s) => ({
    text: clip(s.text, MAX_CLAIM_CHARS),
    written_by: 'model',
    direction: s.direction,
    observation_ids: [],
    check: 'unsupported',
    check_reason: 'The model named no observation for it.',
  }));
  for (const { finding, observation } of observed) {
    if (observation.outcome !== 'success' || (finding.verdict !== 'malicious' && finding.verdict !== 'suspicious')) continue;
    claims.push({
      text: finding.origin === 'history' ? `Earlier alerts of this customer for the same entity were confirmed ${finding.verdict}.` : `A threat-intelligence source reports a value of this alert as ${finding.verdict}.`,
      written_by: 'rules',
      direction: 'malicious',
      observation_ids: [observation.id],
      check: 'supported',
      check_reason: null,
    });
  }
  return claims.slice(0, MAX_CLAIMS).map((c, i) => ({ id: `C-${String(i + 1).padStart(2, '0')}`, ...c }));
}

// Not established

const KIND_WORDS: Record<string, string> = { ip: 'IP address', url: 'URL', hash: 'file hash' };
const LOOKED_UP_KINDS: Array<[string, string]> = [
  ['ips', 'ip'],
  ['domains', 'domain'],
  ['urls', 'url'],
  ['hashes', 'hash'],
];

function notEstablished(alert: AlertDetailOut, observed: Observed[]): NotEstablishedOut {
  const out: NotEstablishedOut = { empty: [], not_checked: [], unavailable: [] };
  const targets = new Set<string>();
  for (const { finding, observation } of observed) {
    targets.add(finding.target.trim().toLowerCase());
    if (observation.outcome === 'empty') out.empty.push(observation.id);
    else if (observation.outcome === 'failed') {
      out.unavailable.push({
        what: observation.title,
        why: failedWords(finding),
        kind: finding.status === 'not_configured' || finding.status === 'unsupported' ? 'no_source' : 'tool_failed',
        source: finding.source,
        observation_id: observation.id,
      });
    }
  }
  // Indicators of the alert that no lookup was recorded for (only when an analysis ran at all).
  const entities = asObjectOrNull(asObjectOrNull(alert.normalized)?.entities);
  if (!entities || !asObjectOrNull(asObjectOrNull(alert.summary)?.analysis)) return out;
  const missing: NotEstablishedOut['not_checked'] = [];
  for (const [key, kind] of LOOKED_UP_KINDS) {
    for (const value of strings(entities[key])) {
      if (!targets.has(value.toLowerCase())) missing.push({ what: `Reputation of ${KIND_WORDS[kind] ?? kind} ${clip(value, 120)}`, why: 'No lookup was recorded for it.' });
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

type StepWords = Pick<PlainStepOut, 'actor' | 'text'> & { produced?: string | null };

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

function stepsOf(events: readonly AlertEventOut[], summary: Rec): PlainStepOut[] {
  const signals = signalsOf(summary);
  return [...events]
    .sort((a, b) => a.ts.localeCompare(b.ts) || a.id - b.id)
    .flatMap((e): PlainStepOut[] => {
      const words = eventStep(e, signals);
      return words ? [{ ts: e.ts, actor: words.actor, text: clip(words.text, MAX_STEP_CHARS), produced: words.produced ?? null }] : [];
    });
}

// The proposed response

function previewed(a: PreviewActionOut): ProposedActionOut {
  return {
    action_id: null,
    action_type: a.action_type,
    target: a.target,
    description: text(a.description),
    risk: a.risk,
    reversible: a.reversible,
    inverse_action: a.inverse_action ?? null,
    irreversible_note: a.irreversible_note ?? null,
    guardrail: { verdict: a.guardrail.verdict, code: a.guardrail.code ?? null, reason: a.guardrail.reason ?? null },
    status: null,
    without_preapproval: a.without_preapproval,
    can_preapprove: a.can_preapprove,
    role_lock: a.role_lock ?? null,
    approval_entry: a.approval_entry,
  };
}

function responseOf(preview: ResponsePreviewOut | null): ProposedResponseOut {
  const actions = preview && Array.isArray(preview.actions) ? preview.actions.map(previewed) : [];
  return { source: actions.length ? 'preview' : 'none', actions };
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

/** The investigation read model, built from the responses of an API that does not serve it. */
export function adaptInvestigation({ alert, escalation = null, events = [], preview = null }: AdapterInput): InvestigationOut {
  const summary: Rec = asObjectOrNull(alert.summary) ?? {};
  const observed = observe(alert);
  return {
    schema_version: INVESTIGATION_VERSION,
    alert_id: alert.id,
    tenant_id: alert.tenant_id,
    generated_at: alert.updated_at,
    hidden_for_blind_audit: Boolean(alert.hidden_for_blind_audit),
    outcome: outcome(alert, escalation),
    summary: summaryOf(alert, escalation),
    claims: claimsOf(summary, observed),
    observations: observed.map((o) => o.observation),
    not_established: notEstablished(alert, observed),
    steps: stepsOf(events, summary),
    track_record: null,
    response: responseOf(preview),
    pending_harness: [...ADAPTER_GAPS],
  };
}
