import { act, renderHook } from '@testing-library/react';
import { renderToString } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useNow } from './useNow';
import { usePageVisible } from './visibility';

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
  document.dispatchEvent(new Event('visibilitychange'));
}

describe('useNow', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-07T12:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    setVisibility('visible');
  });

  it('ticks every interval while the tab is visible', () => {
    const start = Date.now();
    const { result } = renderHook(() => useNow(1_000));
    expect(result.current).toBe(start);
    act(() => {
      vi.advanceTimersByTime(3_000);
    });
    expect(result.current).toBe(start + 3_000);
  });

  it('stops while the tab is hidden and catches up when it shows again', () => {
    const start = Date.now();
    const { result } = renderHook(() => useNow(1_000));
    act(() => setVisibility('hidden'));
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    // No tick while hidden: the countdown shows the last time it knew.
    expect(result.current).toBe(start);
    expect(vi.getTimerCount()).toBe(0);
    act(() => setVisibility('visible'));
    expect(result.current).toBe(start + 10_000);
  });

  it('clears its timer on unmount', () => {
    const { unmount } = renderHook(() => useNow());
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('usePageVisible', () => {
  it('counts a page rendered without a document as visible', () => {
    function Probe() {
      return <p>{usePageVisible() ? 'visible' : 'hidden'}</p>;
    }
    expect(renderToString(<Probe />)).toContain('visible');
  });
});
