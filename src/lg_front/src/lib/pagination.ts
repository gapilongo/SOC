/**
 * Keyset pagination over the API's `{items, next_cursor}` pages.
 *
 * Refetch amplification is bounded: React Query refetches every loaded page
 * of an infinite query, one after the other, whenever it is invalidated or
 * polled. So:
 *
 * * a list loads at most `MAX_PAGES` pages (the UI asks to narrow filters);
 * * once more than one page is loaded, polling and focus refetches pause and
 *   live invalidations only mark the list stale (see `invalidateBounded`);
 *   the page then offers "Reload from top", which keeps the first page and
 *   refetches just that one.
 */

import {
  hashKey,
  useInfiniteQuery,
  useQueryClient,
  type InfiniteData,
  type Query,
  type QueryClient,
  type QueryKey,
} from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type { Page } from '../modules/soc/api/types';

/** The cursor for the page after `last`, or undefined when the listing is complete. */
export function nextCursor<T>(last: Page<T> | undefined): string | undefined {
  return last?.next_cursor ? last.next_cursor : undefined;
}

/** Flatten pages, dropping items repeated across pages (a row that moved between fetches). */
export function flattenPages<T>(pages: ReadonlyArray<Page<T>> | undefined, key: (item: T) => string | number): T[] {
  const seen = new Set<string | number>();
  const out: T[] = [];
  for (const page of pages ?? []) {
    for (const item of page.items) {
      const k = key(item);
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(item);
    }
  }
  return out;
}

/** Upper bound on pages one list keeps loaded (and so refetches when invalidated). */
export const MAX_PAGES = 20;

function isInfinite(data: unknown): data is InfiniteData<unknown, unknown> {
  return Boolean(data && typeof data === 'object' && Array.isArray((data as { pages?: unknown }).pages));
}

/** Number of pages an infinite query holds (0 for other queries). */
export function pagesLoaded(data: unknown): number {
  return isInfinite(data) ? data.pages.length : 0;
}

/** The query is loading another page ("Load more" or scrolling to the end). */
function isFetchingMore(q: Query): boolean {
  return q.state.fetchStatus !== 'idle' && Boolean(q.state.fetchMeta?.fetchMore);
}

function invalidateOne(client: QueryClient, q: Query): Promise<void> {
  const pending = isFetchingMore(q) ? q.promise : undefined;
  if (pending) {
    // Refetching now would cancel the page being loaded (React Query cancels
    // a running fetch by default) and refetch only the pages already held:
    // the "Load more" would be silently lost. Let it land, then invalidate.
    // (Without a pending promise there is nothing to wait for: invalidate now
    // rather than re-check in a loop.)
    const settle = () => invalidateOne(client, q);
    return pending.then(settle, settle);
  }
  const deep = pagesLoaded(q.state.data) > 1;
  return client.invalidateQueries({ queryKey: q.queryKey, exact: true, refetchType: deep ? 'none' : 'active' });
}

/**
 * Invalidate queries under `queryKey` (every query when omitted) with a
 * bounded number of requests: a list holding several pages is marked stale
 * but not refetched; everything else refetches as usual. A list loading its
 * next page is invalidated once that page has arrived.
 */
export function invalidateBounded(client: QueryClient, queryKey?: QueryKey): Promise<void> {
  const queries = client.getQueryCache().findAll(queryKey ? { queryKey } : {});
  return Promise.all(queries.map((q) => invalidateOne(client, q))).then(() => undefined);
}

/** Keep only the first page of a list and refetch it (one request). */
export function reloadFromTop(client: QueryClient, queryKey: QueryKey): Promise<void> {
  client.setQueryData<InfiniteData<unknown, unknown>>(queryKey, (data) =>
    data && data.pages.length > 1 ? { pages: data.pages.slice(0, 1), pageParams: data.pageParams.slice(0, 1) } : data,
  );
  return client.invalidateQueries({ queryKey, exact: true });
}

export function useKeysetList<T>(opts: {
  queryKey: QueryKey;
  fetchPage: (cursor: string | undefined, signal: AbortSignal) => Promise<Page<T>>;
  itemKey: (item: T) => string | number;
  enabled?: boolean;
  refetchInterval?: number | false;
}) {
  const client = useQueryClient();
  const interval = opts.refetchInterval;
  const shallow = (q: { state: { data: unknown } }) => pagesLoaded(q.state.data) <= 1;
  const query = useInfiniteQuery({
    queryKey: opts.queryKey,
    queryFn: ({ pageParam, signal }) => opts.fetchPage(pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last, all) => (all.length >= MAX_PAGES ? undefined : nextCursor(last)),
    enabled: opts.enabled ?? true,
    refetchInterval: interval ? (q) => (shallow(q) ? interval : false) : interval,
    refetchOnWindowFocus: (q) => shallow(q),
  });
  // Callers pass an inline itemKey and a fresh queryKey array on every render. Keep the latest
  // itemKey in a ref so `items` changes only with the data, and reuse the queryKey while its hash
  // holds so `reloadFromTop` changes only with the query: memoized rows skip page re-renders.
  const itemKeyRef = useRef(opts.itemKey);
  itemKeyRef.current = opts.itemKey;
  const items = useMemo(() => flattenPages(query.data?.pages, itemKeyRef.current), [query.data]);
  const pages = query.data?.pages.length ?? 0;
  const lastPage = query.data?.pages[pages - 1];
  /** The list stopped at MAX_PAGES although the API has more rows. */
  const capped = pages >= MAX_PAGES && Boolean(nextCursor(lastPage));

  // Track invalidations that did not refetch (see invalidateBounded).
  const hash = hashKey(opts.queryKey);
  const [outdated, setOutdated] = useState(false);
  useEffect(() => {
    setOutdated(false);
    return client.getQueryCache().subscribe((event) => {
      if (event.query.queryHash !== hash || event.type !== 'updated') return;
      if (event.action.type === 'invalidate') setOutdated(true);
      else if (event.action.type === 'success') setOutdated(false);
    });
  }, [client, hash]);

  const keyRef = useRef({ hash, queryKey: opts.queryKey });
  if (keyRef.current.hash !== hash) keyRef.current = { hash, queryKey: opts.queryKey };
  const queryKey = keyRef.current.queryKey;
  const reload = useCallback(() => reloadFromTop(client, queryKey), [client, queryKey]);
  return { ...query, items, pages, capped, outdated: outdated && pages > 1, reloadFromTop: reload };
}
