import { act, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';

import type { LiveEvent } from '../modules/soc/api/types';
import { LiveContext, createLiveBus, useLive, useLiveEvents } from './LiveProvider';

const event = (type: LiveEvent['type'] = 'alert.created'): LiveEvent => ({ type, tenant_id: 'acme', alert_id: 'a-1', data: {}, ts: '2026-11-07T10:00:00Z' });

describe('createLiveBus', () => {
  it('hands every event to each listener until it unsubscribes, whatever another listener does', () => {
    const bus = createLiveBus();
    const failing = vi.fn(() => {
      throw new Error('boom');
    });
    const heard = vi.fn();
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    bus.subscribe(failing);
    const off = bus.subscribe(heard);
    bus.emit(event());
    expect(heard).toHaveBeenCalledWith(event());
    expect(error).toHaveBeenCalledTimes(1);
    off();
    bus.emit(event('alert.updated'));
    expect(heard).toHaveBeenCalledTimes(1);
    expect(failing).toHaveBeenCalledTimes(2);
    error.mockRestore();
  });
});

function Counter() {
  const [n, setN] = useState(0);
  const [, setTick] = useState(0);
  // A new handler every render: the hook keeps one subscription and calls the latest.
  useLiveEvents((e) => {
    if (e.type === 'alert.created') setN((x) => x + 1);
  });
  return (
    <button type="button" onClick={() => setTick((t) => t + 1)}>
      {n} heard
    </button>
  );
}

describe('useLiveEvents', () => {
  it('subscribes once through the live context and stops when unmounted', () => {
    const bus = createLiveBus();
    const subscribe = vi.fn(bus.subscribe);
    const { unmount } = render(
      <LiveContext.Provider value={{ status: 'open', subscribe }}>
        <Counter />
      </LiveContext.Provider>,
    );
    act(() => bus.emit(event()));
    act(() => screen.getByRole('button').click());
    act(() => bus.emit(event()));
    act(() => bus.emit(event('escalation.created')));
    expect(screen.getByRole('button')).toHaveTextContent('2 heard');
    expect(subscribe).toHaveBeenCalledTimes(1);
    unmount();
    expect(() => bus.emit(event())).not.toThrow();
  });

  it('is inert without a provider', () => {
    function Probe() {
      const { status, subscribe } = useLive();
      subscribe(() => undefined)();
      return <p>{status}</p>;
    }
    render(<Probe />);
    expect(screen.getByText('idle')).toBeInTheDocument();
  });
});
