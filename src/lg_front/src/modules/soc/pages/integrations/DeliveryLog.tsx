/** The delivery log of one integration: recent deliveries with their status and result. */

import { useQuery } from '@tanstack/react-query';

import { endpoints } from '../../../../api/endpoints';
import { qk } from '../../../../api/queryKeys';
import type { DeliveryOut, IntegrationOut } from '../../../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { Badge, type Tone } from '../../components/Badge';
import { Button, Card, EmptyState, ErrorMessage, LoadingState } from '../../../../components/ui';
import { formatDateTime, formatRelative, humanize } from '../../../../lib/format';
import { EVENT_LABELS } from './specs';

const DELIVERY_TONE: Record<string, Tone> = { pending: 'info', sent: 'good', failed: 'warn', dead: 'critical' };

export function describeResult(d: DeliveryOut): string {
  const r = d.result ?? {};
  if (typeof r.ticket === 'string') return `ticket ${r.ticket}${r.created === false ? ' (existing)' : ''}`;
  if (typeof r.skipped === 'string') return `skipped: ${humanize(r.skipped)}`;
  if (typeof r.http_status === 'number') return `HTTP ${r.http_status}`;
  if (typeof r.recipients === 'number') return `${r.recipients} recipient(s)`;
  return '';
}

export function DeliveryLog({ integration }: { integration: IntegrationOut }) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.integrations.deliveries(integration.id),
    queryFn: ({ signal }) => endpoints.deliveries(api, integration.id, signal),
    refetchInterval: 15_000,
  });
  return (
    <Card
      title={`Delivery log: ${integration.name}`}
      actions={
        <Button size="sm" onClick={() => void q.refetch()} busy={q.isFetching}>
          Refresh
        </Button>
      }
      className="mt-6"
    >
      {q.isPending && <LoadingState label="Loading deliveries" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />}
      {q.data && q.data.length === 0 && <EmptyState title="Nothing delivered yet">Events appear here once they are queued.</EmptyState>}
      {q.data && q.data.length > 0 && (
        <div className="relative overflow-x-auto">
          <table className="w-full min-w-[800px] text-left text-sm">
            <caption className="sr-only">Recent deliveries of {integration.name}</caption>
            <thead className="border-b border-subtle text-xs uppercase tracking-wide text-muted">
              <tr>
                <th scope="col" className="px-3 py-2">Queued</th>
                <th scope="col" className="px-3 py-2">Event</th>
                <th scope="col" className="px-3 py-2">Status</th>
                <th scope="col" className="px-3 py-2">Attempts</th>
                <th scope="col" className="px-3 py-2">Result</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((d) => (
                <tr key={d.id} className="border-b border-subtle align-top">
                  <td className="px-3 py-2 text-secondary">
                    <span title={formatDateTime(d.created_at)}>{formatRelative(d.created_at)}</span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-fg">{EVENT_LABELS[d.event_type] ?? d.event_type}</div>
                    {d.operation !== 'notify' && <div className="text-xs text-muted">{humanize(d.operation)}</div>}
                    {d.title && <div className="max-w-md truncate text-xs text-muted" title={d.title}>{d.title}</div>}
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone={DELIVERY_TONE[d.status] ?? 'neutral'}>{d.status}</Badge>
                    {(d.status === 'pending' || d.status === 'failed') && (
                      <div className="mt-1 text-xs text-muted">next {formatRelative(d.next_attempt_at)}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 tabular-nums text-body">{d.attempts}</td>
                  <td className="px-3 py-2 text-xs">
                    {d.last_error ? <span className="break-words text-danger-fg">{d.last_error}</span> : <span className="text-secondary">{describeResult(d)}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
