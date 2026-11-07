import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { App, AppRoutes } from './App';
import { AuthStore } from './auth/store';
import type { UserOut } from './api/types';
import { APP_ROUTES } from './routes';
import { fakeApi, fakeTransport, renderWithSession, signedInSession, token } from './test/helpers';

/** No live socket in these tests. */
function stubWebSocket() {
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
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('App', () => {
  it('drops cached data of the previous session when someone signs in', async () => {
    stubWebSocket();
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

const DENIED = 'You do not have access to this page';

/** Every static page of the route table (parameterised routes and redirects are covered by their pages' tests). */
const PAGES = APP_ROUTES.filter((r) => !r.path.includes(':') && r.path !== '/actions');

/** [who, user, acting tenant, how many of the pages they may open] */
const PRINCIPALS: Array<[string, Partial<UserOut>, string | null, number]> = [
  ['viewer', { role: 'viewer' }, null, 7],
  ['analyst', { role: 'analyst' }, null, 7],
  ['admin', { role: 'admin' }, null, 14],
  ['platform admin', { role: 'admin', is_platform_admin: true }, null, 15],
  // No MSSP console and no account security while acting on another tenant.
  ['platform admin acting on a tenant', { role: 'admin', is_platform_admin: true }, 'globex', 13],
];

describe('route gates and navigation agree', () => {
  it.each(PRINCIPALS)('%s: a page is in the nav exactly when its route lets them in', async (_name, user, acting, allowed) => {
    stubWebSocket();
    // Pages stay loading: only the gate and the shell matter here.
    const { api } = fakeApi(() => new Promise(() => undefined));
    const session = await signedInSession(api, user);
    if (acting) act(() => session.auth.setActingTenant(acting));
    const visible: string[] = [];
    const gated: string[] = [];
    for (const route of PAGES) {
      renderWithSession(<AppRoutes />, session, { route: route.path });
      const nav = await screen.findByRole('navigation', { name: 'Main' });
      if (!screen.queryByRole('heading', { name: DENIED })) gated.push(route.path);
      if (route.nav) {
        if (within(nav).queryByRole('link', { name: route.nav.label })) visible.push(route.path);
      } else if (route.path === '/account') {
        await userEvent.click(screen.getByRole('button', { name: /^Account: / }));
        if (screen.queryByRole('menuitem', { name: 'Account security' })) visible.push(route.path);
      }
      cleanup();
    }
    expect(visible).toEqual(gated);
    expect(gated).toHaveLength(allowed);
  });
});
