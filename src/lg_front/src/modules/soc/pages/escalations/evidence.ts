/**
 * What the analysis stored about an alert, read defensively for the decision
 * page: the indicators for and against the AI verdict, the conclusion and
 * whether any evidence was simulated. Nothing is invented: a missing field
 * gives an empty list or null, and the page says so.
 */

import { text } from '../../api/fields';
import type { AlertDetailOut, EscalationOut } from '../../api/types';
import { asObjectOrNull } from '../../../../lib/json';

export function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((v) => (typeof v === 'string' && v.trim() ? [v.trim()] : typeof v === 'number' ? [String(v)] : []));
}

/** Who stated an indicator: the triage rules, the model, or the analysis agent. */
export type IndicatorBy = 'rule' | 'model' | 'analysis';

export interface Indicator {
  text: string;
  by: IndicatorBy;
}

export interface EvidenceDigest {
  /** Indicators pointing to malicious (true-positive indicators, threat indicators). */
  malicious: Indicator[];
  /** Indicators pointing to benign (false-positive indicators). */
  benign: Indicator[];
  conclusion: string | null;
  verdict: string | null;
  /** true: the model wrote the conclusion; false: the rules did; null: unknown. */
  llmUsed: boolean | null;
  threatScore: number | null;
  reasoning: string[];
  ruleEvidence: string[];
  recommended: string[];
  /** Some evidence was simulated rather than looked up (flagged by the analysis). */
  simulated: boolean;
  /** The model declined to assess the alert; rule results were used. */
  modelRefused: boolean;
  /** The tenant's LLM budget was exhausted; rules only. */
  budgetExceeded: boolean;
}

function dedupe(items: Indicator[]): Indicator[] {
  const seen = new Set<string>();
  return items.filter((i) => {
    const key = i.text.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const tagged = (values: string[], by: IndicatorBy): Indicator[] => values.map((t) => ({ text: t, by }));

/** The digest of the alert's analysis, falling back to the escalation's summary for the conclusion and verdict. */
export function readEvidence(alert: Pick<AlertDetailOut, 'summary'> | undefined, escalation: Pick<EscalationOut, 'summary'>): EvidenceDigest {
  const summary = asObjectOrNull(alert?.summary) ?? {};
  const esc = asObjectOrNull(escalation.summary) ?? {};
  const triage = asObjectOrNull(summary.triage);
  const analysis = asObjectOrNull(summary.analysis);
  const score = analysis?.threat_score ?? esc.threat_score;
  const llm = typeof analysis?.llm_used === 'boolean' ? analysis.llm_used : typeof esc.llm_used === 'boolean' ? esc.llm_used : null;
  return {
    malicious: dedupe([
      ...tagged(strings(triage?.rule_tp), 'rule'),
      ...tagged(strings(triage?.llm_tp), 'model'),
      ...tagged(strings(analysis?.threat_indicators), 'analysis'),
    ]),
    benign: dedupe([...tagged(strings(triage?.rule_fp), 'rule'), ...tagged(strings(triage?.llm_fp), 'model')]),
    conclusion: text(analysis?.conclusion) ?? text(esc.conclusion),
    verdict: text(analysis?.verdict) ?? text(esc.verdict),
    llmUsed: llm,
    threatScore: typeof score === 'number' && Number.isFinite(score) ? score : null,
    reasoning: strings(analysis?.reasoning),
    ruleEvidence: strings(analysis?.rule_evidence),
    recommended: strings(esc.recommended_actions).length ? strings(esc.recommended_actions) : strings(analysis?.recommended_actions),
    simulated: Boolean(esc.simulated_evidence) || Boolean(analysis?.simulated_evidence) || Boolean(summary.simulated_evidence),
    modelRefused: Boolean(analysis?.llm_refusal),
    budgetExceeded: Boolean(summary.llm_budget_exceeded),
  };
}

/** The alert's extracted entities by kind (`normalized.entities`), non-empty kinds only. */
export function readEntities(alert: Pick<AlertDetailOut, 'normalized'> | undefined): Array<[string, string[]]> {
  const entities = asObjectOrNull(asObjectOrNull(alert?.normalized)?.entities);
  if (!entities) return [];
  return Object.entries(entities).flatMap(([kind, values]): Array<[string, string[]]> => {
    const list = strings(values);
    return list.length ? [[kind, list]] : [];
  });
}
