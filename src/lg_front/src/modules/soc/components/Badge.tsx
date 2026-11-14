/**
 * Domain badges on the token primitives: severity is four bars plus the word
 * (SeverityTag), workflow states are a mark plus the state in words
 * (StatePill). Colour never carries the meaning alone: the word is always there.
 *
 * Labels are written here, not by CSS: an enum value from the API becomes its
 * words in sentence case (`humanize`, the one mapping), and a sentence passed
 * as a label keeps its own capitals ("Needs your input", never "Needs Your Input").
 */

import type { ReactNode } from 'react';

import type { ActionStatus, AlertStatus, Disposition, EscalationStatus } from '../api/types';
import { SeverityTag, StatePill, type StateTone } from '../../../components/ui';
import { humanize } from '../../../lib/format';

export type Tone = 'neutral' | 'info' | 'good' | 'warn' | 'bad' | 'critical';

const TONE_STATE: Record<Tone, StateTone> = {
  neutral: 'neutral',
  info: 'processing',
  good: 'ok',
  warn: 'waiting',
  bad: 'bad',
  critical: 'bad',
};

/** A label starts with a capital; the rest is left as written. */
function sentence(label: ReactNode): ReactNode {
  return typeof label === 'string' ? label.replace(/^\p{Ll}/u, (c) => c.toUpperCase()) : label;
}

/** A small label with a mark; the tone picks the mark. */
export function Badge({ tone = 'neutral', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <StatePill tone={TONE_STATE[tone]} title={title}>
      {sentence(children)}
    </StatePill>
  );
}

/** Source and connector health. */
type HealthStatus = 'healthy' | 'degraded' | 'failing' | 'unknown';

/**
 * Every known status has a tone (adding one to a vocabulary in api/types.ts fails the type check
 * until it gets one); a status from a newer API falls back to neutral.
 */
const STATUS_STATE: Record<AlertStatus | EscalationStatus | ActionStatus | HealthStatus, StateTone> = {
  new: 'processing',
  queued: 'processing',
  processing: 'processing',
  waiting_human: 'waiting',
  waiting_approval: 'approval',
  closed: 'ok',
  failed: 'bad',
  open: 'waiting',
  claimed: 'processing',
  decided: 'ok',
  expired: 'bad',
  cancelled: 'neutral',
  proposed: 'processing',
  awaiting_approval: 'approval',
  approved: 'processing',
  rejected: 'neutral',
  executing: 'processing',
  succeeded: 'ok',
  dry_run: 'neutral',
  blocked: 'bad',
  healthy: 'ok',
  degraded: 'waiting',
  failing: 'bad',
  unknown: 'neutral',
};
const DISPOSITION_STATE: Record<Disposition, StateTone> = { malicious: 'bad', benign: 'ok', inconclusive: 'waiting' };

function toneOf(map: Record<string, StateTone>, value: string): StateTone {
  return Object.hasOwn(map, value) ? map[value] : 'neutral';
}

export function statusTone(value: string): StateTone {
  return toneOf(STATUS_STATE, value);
}

export function SeverityBadge({ value }: { value: string | null | undefined }) {
  return <SeverityTag value={value} />;
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-muted">-</span>;
  return <StatePill tone={statusTone(value)}>{humanize(value)}</StatePill>;
}

export function DispositionBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-muted">Pending</span>;
  return <StatePill tone={toneOf(DISPOSITION_STATE, value)}>{humanize(value)}</StatePill>;
}

export function RiskBadge({ value }: { value: string | null | undefined }) {
  return <SeverityTag value={value} suffix="risk" />;
}
