/**
 * Defensive readers for the optional fields newer APIs add (console
 * redesign). Older APIs omit them, older rows carry null (`routing` and
 * `ai_reason_source` of escalations opened before they were recorded), and a
 * malformed value must not crash a page: every reader returns null (or an
 * empty value) for anything it cannot use, so pages omit the figure rather
 * than show a wrong one.
 */

import { shortId } from '../lib/format';
import { ApiError } from './client';
import {
  BULK_MAX_ITEMS,
  ENTITY_KINDS,
  type ActionOut,
  type AlertDetailOut,
  type BulkItemIn,
  type BulkOut,
  type DashboardOut,
  type EntitiesPreviewOut,
  type EntityKind,
  type EntityRefOut,
  type EscalationOut,
  type FindingOut,
  type GuardrailOut,
  type RoutingOut,
} from './types';
import { isJsonObject } from '../lib/json';

/** A non-blank string, else null. */
export function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

/** A finite number, else null. */
export function finite(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** A finite count (>= 0), else null. */
function count(value: unknown): number | null {
  const n = finite(value);
  return n !== null && n >= 0 ? n : null;
}

/** `{key: count}` keeping only finite, non-negative counts. */
export function readCounts(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  if (!isJsonObject(value)) return out;
  for (const [k, v] of Object.entries(value)) {
    const n = count(v);
    if (n !== null) out[k] = n;
  }
  return out;
}

/** Sum of a counts map. */
export function totalOf(counts: Record<string, number>): number {
  return Object.values(counts).reduce((sum, n) => sum + n, 0);
}

function isEntityKind(value: unknown): value is EntityKind {
  return (ENTITY_KINDS as readonly unknown[]).includes(value);
}

// Entities ---------------------------------------------------------------------

/** An `entities_preview`, or null when absent, empty or malformed. */
export function readEntitiesPreview(value: unknown): EntitiesPreviewOut | null {
  if (!isJsonObject(value)) return null;
  const items: EntityRefOut[] = Array.isArray(value.items)
    ? value.items.flatMap((item): EntityRefOut[] => {
        if (!isJsonObject(item) || !isEntityKind(item.kind)) return [];
        const v = text(item.value);
        return v ? [{ kind: item.kind, value: v }] : [];
      })
    : [];
  const counts: EntitiesPreviewOut['counts'] = {};
  for (const [k, n] of Object.entries(readCounts(value.counts))) if (isEntityKind(k)) counts[k] = n;
  if (!items.length && !Object.keys(counts).length) return null;
  return { items, counts };
}

/** Values the preview counts but does not show (each kind shows its first value only). */
export function hiddenEntityCount(preview: EntitiesPreviewOut | null): number {
  if (!preview) return 0;
  const counted = totalOf(preview.counts as Record<string, number>);
  return Math.max(0, counted - preview.items.length);
}

/** "j.moreau@acme.example · 185.220.101.4 · +3 more", or '' without entities. */
export function formatEntities(value: unknown, max = 3): string {
  const preview = readEntitiesPreview(value);
  if (!preview || !preview.items.length) return '';
  const shown = preview.items.slice(0, max).map((i) => i.value);
  const more = hiddenEntityCount(preview) + Math.max(0, preview.items.length - max);
  return more ? `${shown.join(' · ')} · +${more} more` : shown.join(' · ');
}

// Escalations ------------------------------------------------------------------

/** `routing`, or null on escalations opened before it was recorded (or when malformed). */
export function readRouting(value: unknown): RoutingOut | null {
  if (!isJsonObject(value)) return null;
  const code = text(value.code);
  if (!code) return null;
  const band = isJsonObject(value.band) && finite(value.band.min) !== null && finite(value.band.max) !== null
    ? { min: value.band.min as number, max: value.band.max as number }
    : null;
  return { code, confidence: finite(value.confidence), band };
}

/** The AI's one-sentence reason and who wrote it (`source` null on older escalations). */
export function readAiReason(e: Pick<EscalationOut, 'ai_reason' | 'ai_reason_source'>): { text: string; source: 'model' | 'rules' | null } | null {
  const reason = text(e.ai_reason);
  if (!reason) return null;
  const source = e.ai_reason_source === 'model' || e.ai_reason_source === 'rules' ? e.ai_reason_source : null;
  return { text: reason, source };
}

/** The alert title from the summary, else the rule, else a placeholder. */
export function escalationTitle(e: Pick<EscalationOut, 'summary' | 'rule'>): string {
  return text(e.summary?.title) ?? text(e.rule) ?? 'Untitled alert';
}

/** The alert's severity (newer APIs), else the one in the summary, else null. */
export function escalationSeverity(e: Pick<EscalationOut, 'alert_severity' | 'summary'>): string | null {
  return text(e.alert_severity) ?? text(e.summary?.severity);
}

/**
 * The info notice for a 409 on an escalation claim, or null for any other error.
 * A state error (already decided or closed) is told apart from a version race (changed meanwhile);
 * `refreshed` says what was reloaded, e.g. "the list has been refreshed".
 */
export function escalationConflictNotice(err: unknown, refreshed: string): string | null {
  if (!(err instanceof ApiError) || err.status !== 409) return null;
  if (err.isStateConflict) return `This escalation is already decided or closed; ${refreshed}.`;
  return `Someone else changed this escalation first; ${refreshed}.`;
}

export type OwnerKind = 'you' | 'other' | 'none';

/** Who holds an escalation, for display: "You", the owner's e-mail (else a short id), or "Unassigned". */
export function escalationOwner(
  e: Pick<EscalationOut, 'assigned_to' | 'assigned_to_email'>,
  userId: string | null | undefined,
): { kind: OwnerKind; label: string } {
  if (!e.assigned_to) return { kind: 'none', label: 'Unassigned' };
  if (userId && e.assigned_to === userId) return { kind: 'you', label: 'You' };
  return { kind: 'other', label: text(e.assigned_to_email) ?? shortId(e.assigned_to) };
}

/** Who decided an escalation: "You", their e-mail (else a short id), or null when undecided. */
export function decidedByLabel(e: Pick<EscalationOut, 'decided_by' | 'decided_by_email'>, userId: string | null | undefined): string | null {
  if (!e.decided_by) return null;
  if (userId && e.decided_by === userId) return 'You';
  return text(e.decided_by_email) ?? shortId(e.decided_by);
}

// Alerts and actions ------------------------------------------------------------

/** The findings of an alert detail, dropping malformed entries (empty on older APIs). */
export function readFindings(alert: Pick<AlertDetailOut, 'findings'>): FindingOut[] {
  if (!Array.isArray(alert.findings)) return [];
  return alert.findings.filter(
    (f): f is FindingOut =>
      isJsonObject(f) && (f.origin === 'threat_intel' || f.origin === 'history') && Boolean(text(f.kind)) && Boolean(text(f.source)),
  );
}

/** An action's guardrail verdict, or null when absent or malformed. */
export function readGuardrail(action: Pick<ActionOut, 'guardrail'>): GuardrailOut | null {
  const g: unknown = action.guardrail;
  if (!isJsonObject(g) || (g.verdict !== 'passed' && g.verdict !== 'blocked')) return null;
  return {
    verdict: g.verdict,
    evaluated: g.evaluated === 'recorded' ? 'recorded' : 'now',
    code: text(g.code),
    reason: text(g.reason),
    approval_reason: text(g.approval_reason),
  };
}

// Bulk triage -------------------------------------------------------------------

/**
 * Bulk request items for these escalations at the versions shown (each id
 * once, in order). Throws above BULK_MAX_ITEMS: the API would answer 422.
 */
export function toBulkItems(escalations: ReadonlyArray<Pick<EscalationOut, 'id' | 'version'>>): BulkItemIn[] {
  const seen = new Set<string>();
  const items: BulkItemIn[] = [];
  for (const e of escalations) {
    if (seen.has(e.id)) continue;
    seen.add(e.id);
    items.push({ escalation_id: e.id, version: e.version });
  }
  if (items.length > BULK_MAX_ITEMS) throw new RangeError(`A bulk request takes at most ${BULK_MAX_ITEMS} escalations.`);
  return items;
}

/** The items of a bulk result that failed, with the single endpoint's error (409 `conflict` = changed meanwhile). */
export function bulkFailures(out: BulkOut): Array<{ escalationId: string; status: number; code: string; message: string }> {
  return (out.results ?? [])
    .filter((r) => !r.ok)
    .map((r) => ({
      escalationId: r.escalation_id,
      status: finite(r.error?.status) ?? 0,
      code: text(r.error?.code) ?? 'unknown',
      message: text(r.error?.message) ?? 'This escalation could not be updated.',
    }));
}

// Dashboard ---------------------------------------------------------------------

/** The escalation and approval queue figures of the dashboard summary (right now, not the window). */
export interface QueueFigures {
  overdue: number;
  unassigned: number;
  unassignedBreaching: number;
  /** The earliest deadline still ahead, or null when none is. */
  nextSlaDeadline: string | null;
  /** Active escalations by their alert's severity. */
  openBySeverity: Record<string, number>;
  /** Actions awaiting approval in the tenant, and by risk. */
  pendingTotal: number;
  pendingByRisk: Record<string, number>;
  /** Of those, what the caller's role may approve under the autonomy policy. */
  pendingMine: number;
  /** Active escalations assigned to the caller. */
  myClaimed: number;
}

/**
 * The queue figures, or null on an API that predates them (the page then
 * omits the panels rather than show zeros it was never sent).
 */
export function readQueueFigures(d: DashboardOut | undefined): QueueFigures | null {
  if (!d) return null;
  const unassigned = count(d.unassigned_escalations);
  if (unassigned === null) return null;
  return {
    overdue: count(d.overdue_escalations) ?? 0,
    unassigned,
    unassignedBreaching: count(d.unassigned_breaching) ?? 0,
    nextSlaDeadline: text(d.next_sla_deadline),
    openBySeverity: readCounts(d.open_escalations_by_severity),
    pendingTotal: count(d.pending_approvals_total) ?? 0,
    pendingByRisk: readCounts(d.pending_approvals_by_risk),
    pendingMine: count(d.pending_approvals) ?? 0,
    myClaimed: count(d.my_claimed) ?? 0,
  };
}
