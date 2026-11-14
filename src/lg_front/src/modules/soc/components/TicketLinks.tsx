import { ExternalLink } from 'lucide-react';

import type { TicketOut } from '../api/types';
import { formatDateTime } from '../../../lib/format';
import { Badge } from './Badge';

const SYSTEM_LABELS: Record<string, string> = { jira: 'Jira', servicenow: 'ServiceNow' };

/** Only http(s) links are rendered as links; anything else is shown as text. */
export function safeHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : null;
  } catch {
    return null;
  }
}

export function TicketLink({ ticket }: { ticket: TicketOut }) {
  const href = safeHref(ticket.external_url);
  const label = `${SYSTEM_LABELS[ticket.system] ?? ticket.system} ${ticket.external_key}`;
  const title = [
    ticket.external_status ? `Status: ${ticket.external_status}` : null,
    ticket.resolved_by ? `Resolved by ${ticket.resolved_by}` : null,
    ticket.last_synced_at ? `Synced ${formatDateTime(ticket.last_synced_at)}` : null,
  ]
    .filter(Boolean)
    .join('. ');
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5 text-xs" title={title || undefined}>
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 font-medium text-link underline-offset-2 hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus"
        >
          {label}
          <ExternalLink className="h-3 w-3" aria-hidden="true" />
          <span className="sr-only">(opens in a new tab)</span>
        </a>
      ) : (
        <span className="font-medium text-body">{label}</span>
      )}
      {ticket.external_status && <Badge tone={ticket.resolved ? 'good' : 'info'}>{ticket.external_status}</Badge>}
    </span>
  );
}

export function TicketLinks({ tickets }: { tickets: TicketOut[] }) {
  if (tickets.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1" aria-label="External tickets">
      {tickets.map((t) => (
        <li key={t.id}>
          <TicketLink ticket={t} />
        </li>
      ))}
    </ul>
  );
}
