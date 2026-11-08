/** Words and keyboard shortcuts of the blind audit (labelling an auto-closed alert without the AI verdict). */

import type { AuditLabel, BlindAuditRevealOut } from '../../api/types';
import { humanize } from '../../lib/format';

export interface LabelChoice {
  label: AuditLabel;
  text: string;
  /** The key that records this label (lower case; Shift is ignored). */
  key: string;
  hint: string;
}

export const LABEL_CHOICES: readonly LabelChoice[] = [
  { label: 'malicious', text: 'Malicious', key: 'm', hint: 'A real threat: opens an escalation for it.' },
  { label: 'benign', text: 'Benign', key: 'b', hint: 'Closing it was right.' },
  { label: 'unsure', text: 'Unsure', key: 'u', hint: 'Cannot tell from the evidence.' },
];

/** The key that moves to the next sample once the AI verdict is shown. */
export const NEXT_KEY = 'n';

/** The label a key records, or null. */
export function labelForKey(key: string): AuditLabel | null {
  return LABEL_CHOICES.find((c) => c.key === key.toLowerCase())?.label ?? null;
}

/** Whether a key press belongs to a text field or carries a modifier (shortcuts then stay quiet). */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!target || typeof (target as HTMLElement).tagName !== 'string') return false;
  const el = target as HTMLElement;
  return ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) || Boolean(el.isContentEditable);
}

export function labelText(label: string | null | undefined): string {
  return LABEL_CHOICES.find((c) => c.label === label)?.text ?? humanize(label ?? '');
}

/** "You and the AI agree", "You disagree with the AI" or, for unsure labels, nothing to compare. */
export function agreementText(reveal: BlindAuditRevealOut): string {
  if (reveal.agreement === null) return 'An unsure label is not compared with the AI.';
  return reveal.agreement ? 'You and the AI agree.' : 'You disagree with the AI.';
}

/** The keys of a normalized event worth a line of their own (scalars only; entities are shown apart). */
export function normalizedFacts(normalized: Record<string, unknown> | null | undefined, limit = 12): Array<[string, string]> {
  if (!normalized) return [];
  const out: Array<[string, string]> = [];
  for (const [k, v] of Object.entries(normalized)) {
    if (k === 'entities' || v === null || v === undefined || typeof v === 'object') continue;
    out.push([humanize(k), String(v).slice(0, 300)]);
    if (out.length >= limit) break;
  }
  return out;
}
