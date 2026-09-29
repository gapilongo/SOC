import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { shouldRetry } from '../queryClient';
import { ApiError } from '../api/client';
import { usePollInterval } from './visibility';

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
  document.dispatchEvent(new Event('visibilitychange'));
}

afterEach(() => setVisibility('visible'));

describe('polling', () => {
  it('pauses while the tab is hidden and resumes when visible', () => {
    const { result } = renderHook(() => usePollInterval(30_000));
    expect(result.current).toBe(30_000);
    act(() => setVisibility('hidden'));
    expect(result.current).toBe(false);
    act(() => setVisibility('visible'));
    expect(result.current).toBe(30_000);
  });

  it('retries only transient API failures', () => {
    const err = (status: number) => new ApiError({ status, code: 'x', message: 'x' });
    expect(shouldRetry(0, err(0))).toBe(true);
    expect(shouldRetry(0, err(503))).toBe(true);
    expect(shouldRetry(0, err(429))).toBe(true);
    expect(shouldRetry(0, err(404))).toBe(false);
    expect(shouldRetry(0, err(409))).toBe(false);
    expect(shouldRetry(2, err(503))).toBe(false);
  });
});
