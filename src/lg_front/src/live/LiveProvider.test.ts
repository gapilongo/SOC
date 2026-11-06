import { QueryClient } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createInvalidator, keysForEvent } from './LiveProvider';

function invalidatedPrefixes(spy: { mock: { calls: unknown[][] } }): unknown[] {
  return spy.mock.calls.map((call) => (call[0] as { queryKey: unknown[] }).queryKey[0]);
}

describe('createInvalidator', () => {
  let client: QueryClient;

  beforeEach(() => {
    vi.useFakeTimers();
    // No garbage-collection timers: the fake clock only holds the invalidator's.
    client = new QueryClient({ defaultOptions: { queries: { gcTime: Infinity } } });
    // One cached query per prefix so each invalidation is observable.
    for (const key of ['alerts', 'alert', 'dashboard', 'escalations', 'actions']) client.setQueryData([key], 1);
  });

  afterEach(() => {
    vi.useRealTimers();
    client.clear();
  });

  it('invalidates each prefix once per window, however many events arrive inside it', () => {
    const spy = vi.spyOn(client, 'invalidateQueries');
    const inv = createInvalidator(client, 2_000);

    inv.add(keysForEvent('alert.created'));
    vi.advanceTimersByTime(500);
    inv.add(keysForEvent('alert.updated'));
    inv.add(keysForEvent('escalation.created'));
    vi.advanceTimersByTime(1_499);
    expect(spy).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(invalidatedPrefixes(spy).sort()).toEqual(['alert', 'alerts', 'dashboard', 'escalations']);

    // A later event opens a new window.
    spy.mockClear();
    inv.add(keysForEvent('action.updated'));
    vi.advanceTimersByTime(2_000);
    expect(invalidatedPrefixes(spy).sort()).toEqual(['actions', 'dashboard']);
  });

  it('ignores events that make nothing stale', () => {
    const spy = vi.spyOn(client, 'invalidateQueries');
    const inv = createInvalidator(client, 2_000);
    inv.add(keysForEvent('heartbeat' as never));
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(5_000);
    expect(spy).not.toHaveBeenCalled();
  });

  it('cancel() drops pending work', () => {
    const spy = vi.spyOn(client, 'invalidateQueries');
    const inv = createInvalidator(client, 2_000);
    inv.add(keysForEvent('alert.created'));
    inv.cancel();
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(5_000);
    expect(spy).not.toHaveBeenCalled();

    // Still usable after a cancel.
    inv.add(['actions']);
    vi.advanceTimersByTime(2_000);
    expect(invalidatedPrefixes(spy)).toEqual(['actions']);
  });
});
