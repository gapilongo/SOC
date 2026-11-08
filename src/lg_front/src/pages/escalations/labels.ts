/** Words for escalation fields, shared by the queue and the decision page. */

import { readRouting } from '../../api/fields';
import type { Decision, RoutingOut } from '../../api/types';
import { humanize } from '../../lib/format';

/** The verdicts an analyst records here ("needs more information" is not offered: a pending product decision). */
export const VERDICTS = ['true_positive', 'false_positive', 'benign_positive'] as const satisfies readonly Decision[];
export type Verdict = (typeof VERDICTS)[number];

export const DECISION_LABELS: Record<string, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign_positive: 'Benign positive',
  needs_more_info: 'Needs more information',
};

export function decisionLabel(value: string | null | undefined): string {
  return value ? (DECISION_LABELS[value] ?? humanize(value)) : '-';
}

/** Short names of the routing codes (`routing.code`); unknown codes are humanized. */
const ROUTING_LABELS: Record<string, string> = {
  grey_zone: 'Grey zone',
  false_positive_review: 'False-positive review',
  inconclusive: 'Inconclusive analysis',
  model_refused: 'Model declined',
  llm_normalized: 'Model-normalized alert',
  analyst_request: 'Analyst request',
  response_review: 'Response review',
  group_review: 'Group review',
  blind_audit: 'Blind audit',
};

export function routingLabel(code: string): string {
  return ROUTING_LABELS[code] ?? humanize(code);
}

/** "42%", or null without a confidence. */
export function percent(value: number | null | undefined): string | null {
  return typeof value === 'number' && Number.isFinite(value) ? `${Math.round(value)}%` : null;
}

/** "band 20–60", or null without a band. */
export function bandLabel(routing: RoutingOut | null): string | null {
  return routing?.band ? `band ${Math.round(routing.band.min)}–${Math.round(routing.band.max)}` : null;
}

/** Why an escalation needs a person, in a sentence, from its routing (null on escalations opened before it was recorded). */
export function routingSentence(value: unknown): string | null {
  const routing = readRouting(value);
  if (!routing) return null;
  const conf = percent(routing.confidence);
  switch (routing.code) {
    case 'grey_zone':
      if (conf && routing.band) {
        return `Escalated because triage confidence ${conf} is inside the review band (${Math.round(routing.band.min)}–${Math.round(routing.band.max)}%).`;
      }
      return conf ? `Escalated because triage confidence ${conf} is in the grey zone.` : 'Escalated because triage confidence is in the grey zone.';
    case 'false_positive_review':
      return 'Escalated to confirm a likely false positive before it is closed.';
    case 'inconclusive':
      return 'Escalated because the analysis was inconclusive.';
    case 'model_refused':
      return 'Escalated because the model declined to assess this alert.';
    case 'llm_normalized':
      return 'Escalated because the model had to normalize this alert; check the extracted fields.';
    case 'analyst_request':
      return 'Escalated at an analyst’s request.';
    case 'response_review':
      return 'Escalated so a person reviews the planned response.';
    case 'group_review':
      return 'Escalated for review together with similar alerts.';
    case 'blind_audit':
      return 'Escalated because an analyst labelled this auto-closed alert malicious in a blind audit.';
    default:
      return `Escalated: ${routingLabel(routing.code)}.`;
  }
}
