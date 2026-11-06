/**
 * SLA state of an escalation, shared by the overview and the queues so they
 * agree on "at risk" and "breaching".
 *
 * * breaching: the deadline has passed;
 * * at risk: at most a quarter of the SLA window is left (the window runs
 *   from the escalation's creation to its deadline), or at most an hour when
 *   the creation time is unknown;
 * * ok: otherwise; none: no deadline.
 */

import { formatDuration } from './format';

export type SlaState = 'none' | 'ok' | 'at_risk' | 'breaching';

/** Share of the SLA window left at which an escalation is at risk. */
export const AT_RISK_FRACTION = 0.25;
/** Seconds left at which an escalation is at risk when its window is unknown. */
export const AT_RISK_FALLBACK_S = 3_600;

export interface SlaStatus {
  state: SlaState;
  /** Seconds to the deadline (negative once passed), null without one. */
  seconds: number | null;
  /** "4h 12m left", "2h 14m over" or "No SLA". */
  text: string;
}

function time(value: string | null | undefined): number | null {
  if (!value) return null;
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? null : t;
}

export function slaStatus(deadline: string | null | undefined, now: number, createdAt?: string | null): SlaStatus {
  const due = time(deadline);
  if (due === null) return { state: 'none', seconds: null, text: 'No SLA' };
  const seconds = Math.round((due - now) / 1000);
  if (seconds < 0) return { state: 'breaching', seconds, text: `${formatDuration(-seconds)} over` };
  const start = time(createdAt);
  const windowS = start !== null && start < due ? (due - start) / 1000 : null;
  const atRisk = windowS !== null ? seconds <= windowS * AT_RISK_FRACTION : seconds <= AT_RISK_FALLBACK_S;
  return { state: atRisk ? 'at_risk' : 'ok', seconds, text: `${formatDuration(seconds)} left` };
}

/** The status with its state in words: "2h 14m over · breaching", "4h 12m left · at risk". */
export function slaLabel(status: SlaStatus): string {
  if (status.state === 'breaching') return `${status.text} · breaching`;
  if (status.state === 'at_risk') return `${status.text} · at risk`;
  return status.text;
}
