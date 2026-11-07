import { useQuery } from '@tanstack/react-query';
import { X } from 'lucide-react';
import { useEffect, useId, useRef, type KeyboardEvent } from 'react';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { statusTone } from '../../components/Badge';
import { Button, ErrorMessage, LoadingState, SeverityTag, StatePill } from '../../components/ui';
import { formatDateTime, formatRelative } from '../../lib/format';
import { statusWords } from './alertSummary';
import { AlertSections, ReprocessButton } from './AlertSections';

/** Wide screens keep the panel beside the list; below this it covers the list. */
export const SIDE_BY_SIDE_QUERY = '(min-width: 1280px)';

function sideBySide(): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia(SIDE_BY_SIDE_QUERY).matches;
}

/**
 * The selected alert beside the list: a fixed column on wide screens (the
 * list keeps the keyboard), a drawer over the list on tablets and a
 * full-screen sheet on phones (focus moves into it). Escape closes it.
 */
export function AlertSidePanel({ alertId, onClose }: { alertId: string; onClose: () => void }) {
  const api = useApi();
  const { principal } = useAuth();
  const titleId = useId();
  const titleRef = useRef<HTMLHeadingElement>(null);
  const q = useQuery({
    queryKey: qk.alert.detail(alertId),
    queryFn: ({ signal }) => endpoints.alert(api, alertId, signal),
  });
  const a = q.data;

  // Over the list (narrow screens), the panel takes the focus so a keyboard user lands in it.
  useEffect(() => {
    if (!sideBySide()) titleRef.current?.focus();
  }, [alertId]);

  const onKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    // Dialogs opened from the panel render in a portal: their Escape is theirs.
    if (e.key === 'Escape' && !e.defaultPrevented && e.currentTarget.contains(e.target as Node)) {
      e.preventDefault();
      onClose();
    }
  };

  return (
    // Escape closes the panel from anywhere inside it; the close button is the pointer path.
    // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions
    <aside
      id="alert-panel"
      aria-labelledby={titleId}
      onKeyDown={onKeyDown}
      className={
        'fixed inset-0 z-30 overflow-y-auto bg-raised p-4 shadow-popover md:left-auto md:w-[420px] md:border-l md:border-subtle ' +
        'xl:sticky xl:top-4 xl:z-auto xl:max-h-[calc(100vh-2rem)] xl:w-[380px] xl:flex-none xl:rounded-card xl:border xl:shadow-none'
      }
    >
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-1.5">
          {a && (
            <div className="flex flex-wrap items-center gap-2">
              <SeverityTag value={a.severity} className="font-semibold" />
              <StatePill tone={statusTone(a.status)}>{statusWords(a.status)}</StatePill>
            </div>
          )}
          <h2 id={titleId} ref={titleRef} tabIndex={-1} className="break-words text-base font-semibold leading-snug text-fg focus:outline-none">
            {a ? a.title : 'Alert'}
          </h2>
          {a && (
            <p className="text-xs text-secondary">
              <span className="font-mono" title={a.id}>
                {a.id.slice(0, 8)}
              </span>
              {' · '}
              {a.source_name ?? a.source_id}
              {' · '}
              <time dateTime={a.ingested_at} title={formatDateTime(a.ingested_at)}>
                {formatRelative(a.ingested_at)}
              </time>
            </p>
          )}
        </div>
        <Button size="sm" aria-label="Close alert details" onClick={onClose} icon={<X className="h-4 w-4" strokeWidth={2} aria-hidden="true" />} />
      </div>
      {q.isPending && <LoadingState label="Loading alert" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {a && (
        <>
          <AlertSections alert={a} />
          {can.reprocess(principal) && (
            <div className="mt-4 border-t border-subtle pt-4">
              <ReprocessButton alertId={a.id} />
            </div>
          )}
        </>
      )}
    </aside>
  );
}
