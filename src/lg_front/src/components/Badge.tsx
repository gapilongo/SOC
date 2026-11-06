/**
 * Domain badges on the token primitives: severity is a square plus the word
 * (SeverityTag), workflow states are neutral pills with a coloured dot
 * (StatePill). Colour never carries the meaning alone: the word is always there.
 */

import type { ReactNode } from 'react';

import { SeverityTag, StatePill, type StateTone } from './ui';

export type Tone = 'neutral' | 'info' | 'good' | 'warn' | 'bad' | 'critical';

const TONE_STATE: Record<Tone, StateTone> = {
  neutral: 'neutral',
  info: 'processing',
  good: 'ok',
  warn: 'waiting',
  bad: 'bad',
  critical: 'bad',
};

/** A small labelled pill; the tone picks the dot colour. */
export function Badge({ tone = 'neutral', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <StatePill tone={TONE_STATE[tone]} title={title} className="capitalize">
      {children}
    </StatePill>
  );
}

const STATUS_STATE: Record<string, StateTone> = {
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
const DISPOSITION_STATE: Record<string, StateTone> = { malicious: 'bad', benign: 'ok', inconclusive: 'waiting' };

export function statusTone(value: string): StateTone {
  return STATUS_STATE[value] ?? 'neutral';
}

export function SeverityBadge({ value }: { value: string | null | undefined }) {
  return <SeverityTag value={value} />;
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-muted">-</span>;
  return (
    <StatePill tone={statusTone(value)} className="capitalize">
      {value.replace(/_/g, ' ')}
    </StatePill>
  );
}

export function DispositionBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-muted">pending</span>;
  return (
    <StatePill tone={DISPOSITION_STATE[value] ?? 'neutral'} className="capitalize">
      {value}
    </StatePill>
  );
}

export function RiskBadge({ value }: { value: string | null | undefined }) {
  return <SeverityTag value={value} suffix="risk" />;
}
