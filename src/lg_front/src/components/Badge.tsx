import { cx } from './ui';

const TONES = {
  neutral: 'border-slate-600 bg-slate-800 text-slate-200',
  info: 'border-sky-700 bg-sky-950 text-sky-200',
  good: 'border-emerald-700 bg-emerald-950 text-emerald-200',
  warn: 'border-amber-600 bg-amber-950 text-amber-200',
  bad: 'border-orange-600 bg-orange-950 text-orange-200',
  critical: 'border-red-600 bg-red-950 text-red-200',
} as const;

export type Tone = keyof typeof TONES;

export function Badge({ tone = 'neutral', children, title }: { tone?: Tone; children: React.ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={cx('inline-flex items-center whitespace-nowrap rounded border px-1.5 py-0.5 text-xs font-medium capitalize', TONES[tone])}
    >
      {children}
    </span>
  );
}

const SEVERITY_TONE: Record<string, Tone> = { info: 'neutral', low: 'info', medium: 'warn', high: 'bad', critical: 'critical' };
const STATUS_TONE: Record<string, Tone> = {
  new: 'info',
  queued: 'info',
  processing: 'info',
  waiting_human: 'warn',
  waiting_approval: 'warn',
  closed: 'good',
  failed: 'critical',
  open: 'warn',
  claimed: 'info',
  decided: 'good',
  expired: 'critical',
  cancelled: 'neutral',
  proposed: 'info',
  awaiting_approval: 'warn',
  approved: 'info',
  rejected: 'neutral',
  executing: 'info',
  succeeded: 'good',
  dry_run: 'neutral',
  blocked: 'bad',
  healthy: 'good',
  degraded: 'warn',
  failing: 'critical',
  unknown: 'neutral',
};
const DISPOSITION_TONE: Record<string, Tone> = { malicious: 'critical', benign: 'good', inconclusive: 'warn' };

export function SeverityBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-slate-400">-</span>;
  return <Badge tone={SEVERITY_TONE[value] ?? 'neutral'}>{value}</Badge>;
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-slate-400">-</span>;
  return <Badge tone={STATUS_TONE[value] ?? 'neutral'}>{value.replace(/_/g, ' ')}</Badge>;
}

export function DispositionBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-slate-400">pending</span>;
  return <Badge tone={DISPOSITION_TONE[value] ?? 'neutral'}>{value}</Badge>;
}

export function RiskBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-slate-400">-</span>;
  return <Badge tone={SEVERITY_TONE[value] ?? 'neutral'}>{value} risk</Badge>;
}
