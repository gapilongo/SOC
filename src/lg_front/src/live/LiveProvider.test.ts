import { QueryClient, type QueryKey } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createInvalidator } from './LiveProvider';

function invalidated(spy: { mock: { calls: unknown[][] } }): string[] {
  return spy.mock.calls.map((call) => JSON.stringify((call[0] as { queryKey: unknown[] }).queryKey)).sort();
}

/** A module's mapping, as the registry hands it to the provider (app/registry.ts). */
const KEYS: Record<string, QueryKey[]> = {
  'alert.created': [['m', 'alerts'], ['m', 'alert'], ['m', 'dashboard']],
  'alert.updated': [['m', 'alerts'], ['m', 'alert'], ['m', 'dashboard']],
  'escalation.created': [['m', 'escalations'], ['m', 'dashboard']],
  'action.updated': [['m', 'actions'], ['m', 'dashboard']],
};
const keysFor = (type: string) => KEYS[type] ?? [];

describe('createInvalidator', () => {
  let client: QueryClient;

  beforeEach(() => {
    vi.useFakeTimers();
    // No garbage-collection timers: the fake clock only holds the invalidator's.
    client = new QueryClient({ defaultOptions: { queries: { gcTime: Infinity } } });
    // One cached query per prefix so each invalidation is observable.
    for (const key of ['alerts', 'alert', 'dashboard', 'escalations', 'actions']) client.setQueryData(['m', key], 1);
  });

  afterEach(() => {
    vi.useRealTimers();
    client.clear();
  });

  it('invalidates each prefix once per window, however many events arrive inside it', () => {
    const spy = vi.spyOn(client, 'invalidateQueries');
    const inv = createInvalidator(client, 2_000);

    inv.add(keysFor('alert.created'));
    vi.advanceTimersByTime(500);
    inv.add(keysFor('alert.updated'));
    inv.add(keysFor('escalation.created'));
    vi.advanceTimersByTime(1_499);
    expect(spy).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(invalidated(spy)).toEqual(['["m","alert"]', '["m","alerts"]', '["m","dashboard"]', '["m","escalations"]']);

    // A later event opens a new window.
    spy.mockClear();
    inv.add(keysFor('action.updated'));
    vi.advanceTimersByTime(2_000);
    expect(invalidated(spy)).toEqual(['["m","actions"]', '["m","dashboard"]']);
  });

  it('ignores events that make nothing stale', () => {
    const spy = vi.spyOn(client, 'invalidateQueries');
    const inv = createInvalidator(client, 2_000);
    inv.add(keysFor('heartbeat'));
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(5_000);
    expect(spy).not.toHaveBeenCalled();
  });

  it('cancel() drops pending work', () => {
    const spy = vi.spyOn(client, 'invalidateQueries');
    const inv = createInvalidator(client, 2_000);
    inv.add(keysFor('alert.created'));
    inv.cancel();
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(5_000);
    expect(spy).not.toHaveBeenCalled();

    // Still usable after a cancel.
    inv.add([['m', 'actions']]);
    vi.advanceTimersByTime(2_000);
    expect(invalidated(spy)).toEqual(['["m","actions"]']);
  });
});
