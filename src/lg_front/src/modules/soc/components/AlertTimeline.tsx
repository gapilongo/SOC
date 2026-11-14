/**
 * An alert's timeline, in the alert panel (`rail`) and on the decision page
 * (`rows`): one loader, one wording of an event, one shared `Timeline`.
 */

import { useApi } from '../../../auth/AuthContext';
import { Button, EmptyState, ErrorMessage, LoadingState, Timeline, type TimelineEntry, type TimelineVariant } from '../../../components/ui';
import { formatDateTime, humanize } from '../../../lib/format';
import { useKeysetList } from '../../../lib/pagination';
import { endpoints } from '../api/endpoints';
import { qk } from '../api/queryKeys';
import type { AlertEventOut } from '../api/types';

/** What an event says beyond its type: a note's text, a ticket's note, or the fields that changed. */
export function eventSummary(e: AlertEventOut): string {
  const d = e.data ?? {};
  if (e.event_type === 'note' && typeof d.text === 'string') return d.text;
  // Integration events (ticket opened, resolved outside LG-SOTF) carry a readable note.
  if (e.event_type.startsWith('ticket.') && typeof d.note === 'string') return d.note;
  const parts: string[] = [];
  for (const key of ['status', 'from', 'to', 'decision', 'reason', 'disposition', 'action_type', 'error']) {
    const v = d[key];
    if (typeof v === 'string' || typeof v === 'number') parts.push(`${humanize(key)}: ${v}`);
  }
  return parts.join(', ');
}

/** An alert event as a timeline entry. The narrow panel names the actor's id and the step; the page keeps the row short. */
export function alertEventEntry(e: AlertEventOut, variant: TimelineVariant): TimelineEntry {
  const rail = variant === 'rail';
  return {
    id: e.id,
    title: humanize(e.event_type),
    ts: e.ts,
    time: formatDateTime(e.ts),
    note: e.node ? (rail ? `node ${e.node}` : e.node) : undefined,
    byline: rail ? `by ${e.actor_type}${e.actor_id ? ` ${e.actor_id}` : ''}` : `by ${e.actor_type}`,
    detail: eventSummary(e) || undefined,
  };
}

export function AlertTimeline({ alertId, variant }: { alertId: string; variant: TimelineVariant }) {
  const api = useApi();
  const q = useKeysetList({
    queryKey: qk.alert.events(alertId),
    fetchPage: (cursor, signal) => endpoints.alertEvents(api, alertId, cursor, signal),
    itemKey: (e: AlertEventOut) => e.id,
  });
  return (
    <>
      {q.isPending && <LoadingState label="Loading timeline" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />}
      {q.isSuccess && q.items.length === 0 && <EmptyState title="No events yet" />}
      {q.items.length > 0 && <Timeline variant={variant} entries={q.items.map((e) => alertEventEntry(e, variant))} />}
      {q.hasNextPage && (
        <Button size="sm" className={variant === 'rail' ? 'mt-3' : 'self-start'} onClick={() => void q.fetchNextPage()} busy={q.isFetchingNextPage}>
          Load older events
        </Button>
      )}
    </>
  );
}
