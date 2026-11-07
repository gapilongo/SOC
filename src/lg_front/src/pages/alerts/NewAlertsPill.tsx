import { RefreshCw } from 'lucide-react';
import { useCallback, useRef, useState } from 'react';

import type { LiveEvent } from '../../api/types';
import { useLiveEvents } from '../../live/LiveProvider';

/**
 * When the list's rows were last read from the top: the time its data last
 * changed, except when the change was a further page (rows appended below,
 * none of the new alerts).
 */
export function useListLoadedAt(dataUpdatedAt: number, pages: number): number {
  const ref = useRef({ at: dataUpdatedAt, pages, loadedAt: dataUpdatedAt });
  if (ref.current.at !== dataUpdatedAt) {
    const appended = pages > ref.current.pages && ref.current.pages > 0;
    ref.current = { at: dataUpdatedAt, pages, loadedAt: appended ? ref.current.loadedAt : dataUpdatedAt };
  }
  return ref.current.loadedAt;
}

/**
 * Alerts created (live `alert.created` events matching `matches`) since the
 * list was loaded at `loadedAt`; back to zero whenever it reloads. Counted in
 * the browser: events are at-most-once, so this is a hint, not a total.
 */
export function useNewAlertCount(loadedAt: number, matches: (event: LiveEvent) => boolean = () => true): number {
  const loadedRef = useRef(loadedAt);
  loadedRef.current = loadedAt;
  const matchesRef = useRef(matches);
  matchesRef.current = matches;
  const [counter, setCounter] = useState({ since: loadedAt, n: 0 });
  useLiveEvents(
    useCallback((event: LiveEvent) => {
      if (event.type !== 'alert.created' || !matchesRef.current(event)) return;
      const since = loadedRef.current;
      setCounter((c) => (c.since === since ? { since, n: c.n + 1 } : { since, n: 1 }));
    }, []),
  );
  return counter.since === loadedAt ? counter.n : 0;
}

/** "3 new alerts": shown once alerts arrived since the list loaded; a click reloads the list. */
export function NewAlertsPill({ count, onRefresh, busy = false }: { count: number; onRefresh: () => void; busy?: boolean }) {
  const label = `${count} new ${count === 1 ? 'alert' : 'alerts'}`;
  return (
    <span role="status">
      {count > 0 && (
        <button
          type="button"
          onClick={onRefresh}
          aria-label={`${label}: reload the list`}
          disabled={busy}
          className="inline-flex h-[30px] items-center gap-1.5 rounded-full bg-accent px-3 text-ctl font-semibold text-on-accent hover:bg-accent-hover disabled:opacity-60 touch:min-h-11"
        >
          <RefreshCw className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
          {label}
        </button>
      )}
    </span>
  );
}
