import { AlertTriangle, Inbox, Loader2, RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';

import { describeError } from '../../api/client';
import { Button } from './Button';
import { cx } from './cx';

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <span role="status" className="inline-flex items-center gap-2 text-sm text-secondary">
      <Loader2 className="h-4 w-4 animate-spin" strokeWidth={1.75} aria-hidden="true" />
      {label}
    </span>
  );
}

export function LoadingState({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center py-12">
      <Spinner label={label} />
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <Inbox className="h-8 w-8 text-muted" strokeWidth={1.75} aria-hidden="true" />
      <p className="text-sm font-semibold text-fg">{title}</p>
      {children && <div className="max-w-md text-sm text-secondary">{children}</div>}
    </div>
  );
}

/** API error display: the message, validation details and the request id for support. */
export function ErrorMessage({ error, onRetry, compact = false }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const { message, requestId, details } = describeError(error);
  return (
    <div role="alert" className={cx('rounded-control border border-danger bg-tint-danger text-sm text-fg', compact ? 'px-3 py-2' : 'p-4')}>
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-4 w-4 flex-none text-danger-fg" strokeWidth={1.75} aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p>{message}</p>
          {details.length > 0 && (
            <ul className="mt-1 list-disc pl-5 text-body">
              {details.map((d, i) => (
                <li key={i}>{d}</li>
              ))}
            </ul>
          )}
          {requestId && (
            <p className="mt-1 text-xs text-secondary">
              Request ID: <span className="select-all font-mono">{requestId}</span>
            </p>
          )}
        </div>
        {onRetry && (
          <Button size="sm" variant="quiet" onClick={onRetry} icon={<RefreshCw className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />}>
            Retry
          </Button>
        )}
      </div>
    </div>
  );
}
