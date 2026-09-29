import { QueryClient } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';
import { AuthStore } from './auth/store';
import { fakeApi, fakeTransport, token } from './test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('App', () => {
  it('drops cached data of the previous session when someone signs in', async () => {
    // No live socket in this test.
    vi.stubGlobal(
      'WebSocket',
      class {
        readyState = 0;
        onopen = null;
        onmessage = null;
        onclose = null;
        onerror = null;
        close() {}
      },
    );
    const auth = new AuthStore({
      transport: fakeTransport({ login: vi.fn(async () => token('b', { id: 'u-b', tenant_id: 'globex' })) }),
      lock: (_n, fn) => fn(),
      setTimer: () => 0,
      clearTimer: () => undefined,
    });
    const { api } = fakeApi(() => new Promise(() => undefined));
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<App session={{ auth, api }} queryClient={queryClient} />);
    // The refresh cookie is refused: the sign-in page is shown.
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();

    // Left over from an earlier session in this tab.
    queryClient.setQueryData(['alerts', {}], { pages: [{ items: [{ id: 'a-1' }] }], pageParams: [undefined] });
    await act(async () => auth.login('b@globex.test', 'pw', null));
    await waitFor(() => expect(auth.getState().status).toBe('authenticated'));
    expect(queryClient.getQueryData(['alerts', {}])).toBeUndefined();
  });
});
