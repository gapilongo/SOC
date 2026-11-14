/**
 * The scope: which tenant the console shows, chosen in the top bar and kept
 * in the address (`/s/<tenant>/...`).
 *
 * Acceptance of PRD-2.12: the tenant a platform admin works in survives a
 * reload and a pasted link, and is never silently replaced by the home
 * tenant. Someone with one tenant is not shown their own data under another
 * tenant's address.
 */
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { UserOut } from '../api/types';
import { SessionProvider } from '../auth/AuthContext';
import type { Session } from '../auth/session';
import { AuthStore } from '../auth/store';
import { scopeOf } from '../lib/scope';
import { fakeApi, fakeTransport, renderWithSession, signedInSession, token } from '../test/helpers';
import { tenant } from '../test/tenants';
import { App } from './App';
import { ScopedRouter } from './ScopedRouter';
import { ScopeControl } from './shell/ScopeControl';
import { filterTenants } from './shell/tenants';

const TENANTS = [
  tenant('initech', 'Initech', { status: 'suspended' }),
  tenant('globex', 'Globex Corp', { stats: { ...tenant('x', 'x').stats, open_escalations: 5 } }),
  tenant('acme', 'Acme (MSSP)'),
];
const PLATFORM_ADMIN: Partial<UserOut> = { role: 'admin', is_platform_admin: true };
const LAZY = { timeout: 15_000 };

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

/** A session as the app creates it: restored from the refresh cookie, its tenant read from the address. */
function sessionAt(user: Partial<UserOut>) {
  const { api, calls } = fakeApi((_method, path) => {
    if (path === '/platform/tenants') return TENANTS;
    if (path === '/auth/me') return { kind: 'user', tenant_id: 'acme', home_tenant_id: 'acme', auth_method: 'password' };
    return new Promise(() => undefined);
  });
  const auth = new AuthStore({
    transport: fakeTransport({ refresh: vi.fn(async () => token('restored', user)) }),
    lock: (_n, fn) => fn(),
    setTimer: () => 0,
    clearTimer: () => undefined,
    addressTenant: () => scopeOf(window.location.pathname).tenant,
  });
  return { session: { auth, api } as Session, calls };
}

function openApp(address: string, user: Partial<UserOut>) {
  stubWebSocket();
  window.history.pushState(null, '', address);
  const { session, calls } = sessionAt(user);
  const view = render(<App session={session} queryClient={new QueryClient({ defaultOptions: { queries: { retry: false } } })} />);
  return { session, calls, ...view };
}

/** A page inside the router: where it is (relative to the scope), and two links. */
function Probe() {
  const location = useLocation();
  return (
    <>
      <p data-testid="page">{location.pathname}</p>
      <Link to="/alerts/a-1">An alert</Link>
      <Link to="/s/globex/escalations">A link to another tenant</Link>
    </>
  );
}

function renderRouter(session: Session) {
  return render(
    <SessionProvider session={session}>
      <ScopedRouter>
        <Probe />
      </ScopedRouter>
    </SessionProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', '/');
  window.localStorage.clear();
});

describe('the tenant is part of the address', () => {
  it('survives a reload and opens from a pasted link', async () => {
    // A pasted link: a new session at an address that names a tenant.
    const first = openApp('/s/globex/alerts', PLATFORM_ADMIN);
    const nav = await screen.findByRole('navigation', { name: 'Main' }, LAZY);
    expect(first.session.auth.getActingTenant()).toBe('globex');
    expect(first.session.auth.getState().principal).toMatchObject({ tenantId: 'globex', homeTenantId: 'acme' });
    expect(screen.getByTestId('tenant-name')).toHaveTextContent('globex');
    expect(await screen.findByRole('heading', { name: 'Alerts', level: 1 }, LAZY)).toBeInTheDocument();
    expect(window.location.pathname).toBe('/s/globex/alerts');
    // Every link of the console carries the tenant, so a new tab opens the same one.
    expect(within(nav).getByRole('link', { name: 'Escalations' })).toHaveAttribute('href', '/s/globex/escalations');
    expect(within(nav).getByRole('link', { name: 'Alerts' })).toHaveAttribute('aria-current', 'page');

    // A reload: everything in memory is gone, the address is not.
    first.unmount();
    const second = openApp(window.location.pathname, PLATFORM_ADMIN);
    await screen.findByRole('navigation', { name: 'Main' }, LAZY);
    expect(second.session.auth.getActingTenant()).toBe('globex');
    expect(screen.getByTestId('tenant-name')).toHaveTextContent('globex');
    expect(window.location.pathname).toBe('/s/globex/alerts');
  });

  it('means the home tenant without a tenant in it, and accepts the home tenant by name', async () => {
    const plain = openApp('/alerts', PLATFORM_ADMIN);
    await screen.findByRole('navigation', { name: 'Main' }, LAZY);
    expect(plain.session.auth.getActingTenant()).toBeNull();
    expect(screen.getByTestId('tenant-name')).toHaveTextContent('acme');
    expect(window.location.pathname).toBe('/alerts');
    plain.unmount();

    const named = openApp('/s/acme/alerts', PLATFORM_ADMIN);
    const nav = await screen.findByRole('navigation', { name: 'Main' }, LAZY);
    expect(named.session.auth.getActingTenant()).toBeNull();
    expect(window.location.pathname).toBe('/s/acme/alerts');
    expect(within(nav).getByRole('link', { name: 'Escalations' })).toHaveAttribute('href', '/s/acme/escalations');
  });

  it('follows the scope control: choosing a tenant puts it in the address, and Back returns to the one before', async () => {
    const user = userEvent.setup();
    const { session } = openApp('/alerts', PLATFORM_ADMIN);
    await screen.findByRole('navigation', { name: 'Main' }, LAZY);
    await user.click(await screen.findByRole('button', { name: /^Tenant acme/ }, LAZY));
    await user.click(await screen.findByRole('option', { name: /Globex Corp/ }));
    await waitFor(() => expect(window.location.pathname).toBe('/s/globex/alerts'));
    expect(session.auth.getActingTenant()).toBe('globex');
    expect(await screen.findByTestId('tenant-name')).toHaveTextContent('globex');

    // Back and Forward across a change of tenant: the tenant follows the address.
    act(() => window.history.back());
    await waitFor(() => expect(session.auth.getActingTenant()).toBeNull());
    expect(window.location.pathname).toBe('/alerts');
    act(() => window.history.forward());
    await waitFor(() => expect(session.auth.getActingTenant()).toBe('globex'));
    expect(window.location.pathname).toBe('/s/globex/alerts');
  });

  it('refuses another tenant\'s address to someone with one tenant, and shows nothing under it', async () => {
    const { session, calls } = openApp('/s/globex/alerts', { role: 'admin' });
    expect(await screen.findByRole('heading', { name: 'This address is for another tenant' }, LAZY)).toBeInTheDocument();
    expect(session.auth.getActingTenant()).toBeNull();
    expect(screen.getByRole('main')).toHaveTextContent('It names the tenant globex. You are signed in to acme and cannot open another tenant');
    expect(screen.getByRole('link', { name: 'Open acme' })).toHaveAttribute('href', '/');
    // No page ran, so nothing of the person's own tenant was fetched under the other tenant's address.
    expect(screen.queryByRole('navigation', { name: 'Main' })).not.toBeInTheDocument();
    expect(calls).toEqual([]);
    expect(window.location.pathname).toBe('/s/globex/alerts');
  });

  it('opens a link that names the person\'s own tenant', async () => {
    const { session } = openApp('/s/acme/alerts', { role: 'analyst' });
    const nav = await screen.findByRole('navigation', { name: 'Main' }, LAZY);
    expect(session.auth.getState().principal?.tenantId).toBe('acme');
    expect(within(nav).getByRole('link', { name: 'Alerts' })).toHaveAttribute('href', '/s/acme/alerts');
    expect(screen.queryByRole('heading', { name: 'This address is for another tenant' })).not.toBeInTheDocument();
  });
});

describe('ScopedRouter', () => {
  it('moves the address when the tenant changes in the app: a record gives way to its list', async () => {
    window.history.pushState(null, '', '/alerts/a-1');
    const session = await signedInSession(fakeApi(() => []).api, PLATFORM_ADMIN);
    renderRouter(session);
    expect(screen.getByTestId('page')).toHaveTextContent('/alerts/a-1');

    act(() => session.auth.setActingTenant('globex'));
    expect(window.location.pathname).toBe('/s/globex/alerts');
    expect(screen.getByTestId('page')).toHaveTextContent('/alerts');
    expect(screen.getByRole('link', { name: 'An alert' })).toHaveAttribute('href', '/s/globex/alerts/a-1');

    // Another tenant, then home: the prefix changes, then goes.
    act(() => session.auth.setActingTenant('initech'));
    expect(window.location.pathname).toBe('/s/initech/alerts');
    act(() => session.auth.setActingTenant(null));
    expect(window.location.pathname).toBe('/alerts');
    expect(screen.getByRole('link', { name: 'An alert' })).toHaveAttribute('href', '/alerts/a-1');
  });

  it('follows a navigation to an address that names a tenant (the return from single sign-on)', async () => {
    const user = userEvent.setup();
    const session = await signedInSession(fakeApi(() => []).api, PLATFORM_ADMIN);
    renderRouter(session);
    await user.click(screen.getByRole('link', { name: 'A link to another tenant' }));
    await waitFor(() => expect(session.auth.getActingTenant()).toBe('globex'));
    expect(window.location.pathname).toBe('/s/globex/escalations');
    expect(screen.getByTestId('page')).toHaveTextContent('/escalations');
  });

  it('leaves the address alone while nobody is signed in, and for someone with one tenant', async () => {
    window.history.pushState(null, '', '/s/globex/login');
    const anonymous = new AuthStore({ transport: fakeTransport(), lock: (_n, fn) => fn(), setTimer: () => 0, clearTimer: () => undefined });
    const view = renderRouter({ auth: anonymous, api: fakeApi(() => []).api });
    expect(screen.getByTestId('page')).toHaveTextContent('/login');
    expect(window.location.pathname).toBe('/s/globex/login');
    view.unmount();

    window.history.pushState(null, '', '/alerts');
    const session = await signedInSession(fakeApi(() => []).api, { role: 'admin' });
    renderRouter(session);
    // Back to an address of another tenant: refused, and the person's tenant does not change.
    act(() => window.history.pushState(null, '', '/s/globex/alerts'));
    act(() => window.dispatchEvent(new PopStateEvent('popstate')));
    expect(await screen.findByRole('heading', { name: 'This address is for another tenant' })).toBeInTheDocument();
    expect(session.auth.getState().principal?.tenantId).toBe('acme');
  });
});

describe('ScopeControl', () => {
  const renderControl = async (user: Partial<UserOut>, handler: () => unknown = () => TENANTS) => {
    const { api, calls } = fakeApi(handler);
    const session = await signedInSession(api, user);
    renderWithSession(<ScopeControl label="Acme (MSSP)" />, session);
    return { session, calls };
  };

  it('filters by id or name, home tenant first', () => {
    expect(filterTenants(TENANTS, 'corp', 'acme').map((t) => t.id)).toEqual(['globex']);
    expect(filterTenants(TENANTS, 'INI', 'acme').map((t) => t.id)).toEqual(['initech']);
    expect(filterTenants(TENANTS, '', 'globex').map((t) => t.id)).toEqual(['globex', 'acme', 'initech']);
  });

  it('says where someone with one tenant is, and offers no choice', async () => {
    const { calls } = await renderControl({ role: 'admin' });
    expect(screen.getByTestId('tenant-name')).toHaveTextContent('Acme (MSSP)');
    expect(screen.getByText('Tenant')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(calls).toEqual([]);
  });

  it('lets a platform admin choose a tenant from a searchable list, with the keyboard', async () => {
    const user = userEvent.setup();
    const { session, calls } = await renderControl(PLATFORM_ADMIN);
    const button = await screen.findByRole('button', { name: 'Tenant Acme (MSSP)' }, LAZY);
    expect(button).toHaveAttribute('aria-haspopup', 'dialog');
    // The list is asked for when the control opens, not before.
    expect(calls).toEqual([]);
    await user.click(button);
    const dialog = screen.getByRole('dialog', { name: 'Choose the tenant' });
    expect(dialog).toHaveTextContent('part of the address');
    const search = within(dialog).getByRole('combobox', { name: 'Search tenants' });
    expect(search).toHaveFocus();
    await within(dialog).findByRole('option', { name: /Globex Corp/ });
    expect(calls.map((c) => c.path)).toEqual(['/platform/tenants']);
    // The home tenant first and marked current; what waits in a tenant; a suspended one says so.
    expect(within(dialog).getAllByRole('option').map((o) => o.textContent)).toEqual(['Acme (MSSP)home', 'Globex Corp5 need a person', 'Initechsuspended']);
    expect(within(within(dialog).getByRole('option', { name: /Acme/ })).getByLabelText('current')).toBeInTheDocument();
    // "All tenants" and tenant groups are not offered: the API has neither yet.
    expect(dialog).not.toHaveTextContent(/All tenants|group/i);

    await user.keyboard('{ArrowDown}{ArrowDown}{ArrowDown}');
    expect(search).toHaveAttribute('aria-activedescendant', within(dialog).getByRole('option', { name: /Initech/ }).id);
    await user.keyboard('{ArrowUp}');
    expect(within(dialog).getByRole('option', { name: /Globex Corp/ })).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{Enter}');
    expect(session.auth.getState().actingTenant).toBe('globex');
    expect(screen.getByText("Working in Globex Corp. Every request is recorded in that tenant's audit log.")).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(button).toHaveFocus();

    // Back home through the same list, by typing and with the pointer.
    await user.click(button);
    await user.type(screen.getByRole('combobox', { name: 'Search tenants' }), 'acm');
    const home = await screen.findByRole('option', { name: /Acme/ });
    expect(screen.getAllByRole('option')).toHaveLength(1);
    fireEvent.pointerDown(home);
    await user.hover(home);
    await user.click(home);
    expect(session.auth.getState().actingTenant).toBeNull();
    expect(screen.getByText('Back to your home tenant.')).toBeInTheDocument();
  });

  it('says so when no tenant matches, and closes on Escape with nothing chosen', async () => {
    const user = userEvent.setup();
    const { session } = await renderControl(PLATFORM_ADMIN);
    const button = await screen.findByRole('button', { name: /^Tenant/ }, LAZY);
    await user.click(button);
    await screen.findByRole('option', { name: /Globex Corp/ });
    await user.type(screen.getByRole('combobox', { name: 'Search tenants' }), 'No Such Tenant');
    expect(screen.getByText('No tenant matches.')).toBeInTheDocument();
    await user.keyboard('{Enter}');
    expect(session.auth.getState().actingTenant).toBeNull();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(button).toHaveFocus();
    // The search starts empty the next time.
    await user.click(button);
    expect(screen.getByRole('combobox', { name: 'Search tenants' })).toHaveValue('');
    await user.click(button);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('still accepts a typed tenant id when the list cannot be loaded', async () => {
    const user = userEvent.setup();
    const { session } = await renderControl(PLATFORM_ADMIN, () => {
      throw new Error('down');
    });
    await user.click(await screen.findByRole('button', { name: /^Tenant/ }, LAZY));
    expect(await screen.findByText(/could not be loaded/)).toBeInTheDocument();
    await user.type(screen.getByRole('combobox', { name: 'Search tenants' }), 'umbrella');
    expect(screen.getByRole('option', { name: 'Use tenant id "umbrella"' })).toBeInTheDocument();
    await user.keyboard('{Enter}');
    expect(session.auth.getState().actingTenant).toBe('umbrella');
    expect(screen.getByText("Working in umbrella. Every request is recorded in that tenant's audit log.")).toBeInTheDocument();
  });
});
