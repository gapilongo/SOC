import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import { memo, useState, type ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';

import type { Page } from '../modules/soc/api/types';
import { flattenPages, invalidateBounded, MAX_PAGES, nextCursor, useKeysetList } from './pagination';

describe('keyset pagination', () => {
  it('stops when the API returns no next cursor', () => {
    expect(nextCursor({ items: [], next_cursor: 'c2' })).toBe('c2');
    expect(nextCursor({ items: [], next_cursor: null })).toBeUndefined();
    expect(nextCursor({ items: [] })).toBeUndefined();
    expect(nextCursor(undefined)).toBeUndefined();
  });

  it('flattens pages in order and drops rows repeated across pages', () => {
    const pages: Page<{ id: string }>[] = [
      { items: [{ id: 'a' }, { id: 'b' }], next_cursor: 'x' },
      { items: [{ id: 'b' }, { id: 'c' }], next_cursor: null },
    ];
    expect(flattenPages(pages, (r) => r.id).map((r) => r.id)).toEqual(['a', 'b', 'c']);
  });

  it('passes each page cursor to the next request', async () => {
    const fetchPage = vi.fn(async (cursor: string | undefined): Promise<Page<{ id: number }>> => {
      if (!cursor) return { items: [{ id: 1 }, { id: 2 }], next_cursor: 'cur-2' };
      if (cursor === 'cur-2') return { items: [{ id: 3 }], next_cursor: null };
      throw new Error('unexpected cursor');
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result } = renderHook(() => useKeysetList({ queryKey: ['t'], fetchPage, itemKey: (r) => r.id }), { wrapper });
    await waitFor(() => expect(result.current.items).toHaveLength(2));
    expect(result.current.hasNextPage).toBe(true);
    await act(async () => {
      await result.current.fetchNextPage();
    });
    await waitFor(() => expect(result.current.items.map((r) => r.id)).toEqual([1, 2, 3]));
    expect(result.current.hasNextPage).toBe(false);
    expect(fetchPage.mock.calls.map((c) => c[0])).toEqual([undefined, 'cur-2']);
  });

  it('bounds the requests one live invalidation makes on a deep list, and reloads from the top with one request', async () => {
    const fetchPage = vi.fn(async (cursor: string | undefined): Promise<Page<{ id: number }>> => {
      const n = cursor ? Number(cursor) : 0;
      return { items: [{ id: n }], next_cursor: String(n + 1) };
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result } = renderHook(() => useKeysetList({ queryKey: ['alerts', {}], fetchPage, itemKey: (r) => r.id }), { wrapper });
    await waitFor(() => expect(result.current.items).toHaveLength(1));
    for (let want = 2; want <= 5; want += 1) {
      await act(async () => {
        await result.current.fetchNextPage();
      });
      await waitFor(() => expect(result.current.pages).toBe(want));
    }
    fetchPage.mockClear();

    await act(async () => {
      await invalidateBounded(client, ['alerts']);
    });
    // Without the bound React Query would refetch all 5 pages in sequence.
    expect(fetchPage).not.toHaveBeenCalled();
    await waitFor(() => expect(result.current.outdated).toBe(true));
    expect(result.current.items).toHaveLength(5);

    await act(async () => {
      await result.current.reloadFromTop();
    });
    expect(fetchPage).toHaveBeenCalledTimes(1);
    expect(fetchPage.mock.calls[0][0]).toBeUndefined();
    await waitFor(() => expect(result.current.pages).toBe(1));
    expect(result.current.outdated).toBe(false);
  });

  it('keeps a page being loaded when a live invalidation arrives meanwhile', async () => {
    let releasePage2: () => void = () => {};
    const fetchPage = vi.fn(async (cursor: string | undefined): Promise<Page<{ id: number }>> => {
      if (!cursor) return { items: [{ id: 1 }], next_cursor: 'cur-2' };
      await new Promise<void>((resolve) => {
        releasePage2 = resolve;
      });
      return { items: [{ id: 2 }], next_cursor: null };
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result } = renderHook(() => useKeysetList({ queryKey: ['alerts', {}], fetchPage, itemKey: (r) => r.id }), { wrapper });
    await waitFor(() => expect(result.current.items).toHaveLength(1));

    // "Load more" is in flight when the (single-page) list is invalidated.
    let loading: Promise<unknown> = Promise.resolve();
    act(() => {
      loading = result.current.fetchNextPage();
    });
    await waitFor(() => expect(result.current.isFetchingNextPage).toBe(true));
    let invalidated: Promise<void> = Promise.resolve();
    act(() => {
      invalidated = invalidateBounded(client, ['alerts']);
    });
    await act(async () => {
      releasePage2();
      await loading;
      await invalidated;
    });

    // The next page was not cancelled and replaced by a refetch of page one.
    await waitFor(() => expect(result.current.items.map((r) => r.id)).toEqual([1, 2]));
    expect(fetchPage.mock.calls.map((c) => c[0])).toEqual([undefined, 'cur-2']);
    // The invalidation is not lost: the (now deep) list is marked outdated.
    await waitFor(() => expect(result.current.outdated).toBe(true));
  });

  it('refetches a single-page list on invalidation with one request', async () => {
    const fetchPage = vi.fn(async (): Promise<Page<{ id: number }>> => ({ items: [{ id: 1 }], next_cursor: null }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result } = renderHook(() => useKeysetList({ queryKey: ['actions', {}], fetchPage, itemKey: (r) => r.id }), { wrapper });
    await waitFor(() => expect(result.current.items).toHaveLength(1));
    fetchPage.mockClear();
    await act(async () => {
      await invalidateBounded(client);
    });
    await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(1));
  });

  it(`stops loading pages after ${MAX_PAGES} and says the list is capped`, async () => {
    const fetchPage = vi.fn(async (cursor: string | undefined): Promise<Page<{ id: number }>> => {
      const n = cursor ? Number(cursor) : 0;
      return { items: [{ id: n }], next_cursor: String(n + 1) };
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result } = renderHook(() => useKeysetList({ queryKey: ['audit', {}], fetchPage, itemKey: (r) => r.id }), { wrapper });
    await waitFor(() => expect(result.current.items).toHaveLength(1));
    while (result.current.hasNextPage) {
      await act(async () => {
        await result.current.fetchNextPage();
      });
    }
    expect(result.current.pages).toBe(MAX_PAGES);
    expect(result.current.capped).toBe(true);
    expect(fetchPage).toHaveBeenCalledTimes(MAX_PAGES);
  });
});

describe('useKeysetList render stability', () => {
  type Row = { id: string };
  const PAGE: Page<Row> = { items: [{ id: 'a' }, { id: 'b' }], next_cursor: null };

  it('keeps items and reloadFromTop stable across re-renders with inline itemKey and an equal queryKey', async () => {
    const fetchPage = vi.fn(async () => PAGE);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result, rerender } = renderHook(
      ({ status }: { status: string[] }) => useKeysetList({ queryKey: ['alerts', { status }], fetchPage, itemKey: (r: Row) => r.id }),
      { wrapper, initialProps: { status: ['queued'] } },
    );
    await waitFor(() => expect(result.current.items).toHaveLength(2));
    const { items, reloadFromTop } = result.current;

    rerender({ status: ['queued'] }); // a new array with the same content: the same query
    expect(result.current.items).toBe(items);
    expect(result.current.reloadFromTop).toBe(reloadFromTop);

    rerender({ status: ['closed'] }); // another query: a new reload target
    expect(result.current.reloadFromTop).not.toBe(reloadFromTop);
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  it('does not re-render a memoized row list when the page re-renders for unrelated state', async () => {
    const fetchPage = vi.fn(async () => PAGE);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    let rowRenders = 0;
    const Rows = memo(function Rows({ items, onReload }: { items: Row[]; onReload: () => void }) {
      rowRenders += 1;
      return (
        <ul aria-label="rows" data-reload={typeof onReload}>
          {items.map((r) => (
            <li key={r.id}>{r.id}</li>
          ))}
        </ul>
      );
    });
    function Page() {
      const [clicks, setClicks] = useState(0);
      const list = useKeysetList({ queryKey: ['alerts', { q: 'x' }], fetchPage, itemKey: (r: Row) => r.id });
      return (
        <>
          <button type="button" onClick={() => setClicks(clicks + 1)}>
            clicked {clicks}
          </button>
          <Rows items={list.items} onReload={list.reloadFromTop} />
        </>
      );
    }
    render(
      <QueryClientProvider client={client}>
        <Page />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getAllByRole('listitem')).toHaveLength(2));
    const settled = rowRenders;
    for (let i = 1; i <= 3; i += 1) {
      act(() => screen.getByRole('button').click());
      expect(screen.getByRole('button')).toHaveTextContent(`clicked ${i}`);
    }
    expect(rowRenders).toBe(settled);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });
});

