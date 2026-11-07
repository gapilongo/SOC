import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Principal } from '../../auth/store';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { LiveContext } from '../../live/LiveProvider';
import type { LiveStatus } from '../../live/socket';
import { tenant } from '../../test/tenants';
import { Layout } from '../Layout';
import { NAV_GROUPS } from '../routes';
import { Header, LiveIndicator } from './Header';
import { navCounts, navFor, roleNote } from './nav';
import { Sidebar } from './Sidebar';
import { initials, roleLabel, UserMenu } from './UserMenu';

function principal(overrides: Partial<Principal> = {}): Principal {
  return { userId: 'u-1', email: 'x@acme.test', role: 'analyst', tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: false, method: 'password', ...overrides };
}

const titles = (p: Principal) => navFor(NAV_GROUPS, p).map((g) => `${g.title}: ${g.items.map((i) => i.label).join(', ')}`);

const DASHBOARD = {
  window_hours: 24,
  since: '2026-11-05T12:00:00Z',
  generated_at: '2026-11-06T12:00:00Z',
  alerts_total: 0,
  by_status: {},
  by_severity: {},
  by_disposition: {},
  acknowledged: 0,
  resolved: 0,
  open_escalations: 0,
  runs_by_status: {},
  queue_depth: 0,
  llm_cost_usd: 0,
  llm_tokens: 0,
};

/** An API that answers the shell's two reads (dashboard summary, /auth/me). */
function shellApi({ summary = DASHBOARD as object, me = {} as object, tenants = [] as unknown[] } = {}) {
  return fakeApi((_method, path) => {
    if (path === '/dashboard/summary') return summary;
    if (path === '/auth/me') return { kind: 'user', tenant_id: 'acme', home_tenant_id: 'acme', auth_method: 'password', ...me };
    if (path === '/platform/tenants') return tenants;
    return [];
  });
}

afterEach(() => {
  window.localStorage.clear();
});

describe('navigation model', () => {
  it('groups the pages by role', () => {
    expect(titles(principal({ role: 'viewer' }))).toEqual(['Operate: Overview, Escalations, Approvals, Alerts, Suppressions', 'Report: Reports']);
    expect(titles(principal())).toEqual(['Operate: Overview, Escalations, Approvals, Alerts, Suppressions', 'Report: Reports']);
    expect(titles(principal({ role: 'admin' }))).toEqual([
      'Operate: Overview, Escalations, Approvals, Alerts, Suppressions',
      'Report: Reports, LLM usage, Audit log',
      'Configure: Getting started, Sources, Integrations, Users and API keys, Tenant settings',
    ]);
    expect(titles(principal({ role: 'admin', isPlatformAdmin: true })).at(-1)).toBe('Platform: MSSP console');
    // The console works across tenants: hidden while acting on one.
    expect(titles(principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' }))).not.toContain('Platform: MSSP console');
    expect(navFor(NAV_GROUPS, null)).toEqual([]);
  });

  it('maps every item to an existing route', () => {
    const items = navFor(NAV_GROUPS, principal({ role: 'admin', isPlatformAdmin: true })).flatMap((g) => g.items);
    expect(Object.fromEntries(items.map((i) => [i.label, i.to]))).toMatchObject({ Overview: '/', Approvals: '/approvals', 'MSSP console': '/platform' });
  });

  it('reads nav counts defensively from the dashboard summary', () => {
    expect(navCounts(undefined)).toEqual({});
    expect(navCounts('nope')).toEqual({});
    expect(navCounts(DASHBOARD)).toEqual({});
    expect(navCounts({ ...DASHBOARD, unassigned_breaching: 3, pending_approvals: 1 })).toEqual({ unassigned_breaching: 3, pending_approvals: 1 });
    expect(navCounts({ unassigned_breaching: 0, pending_approvals: -1 })).toEqual({});
    expect(navCounts({ unassigned_breaching: '3', pending_approvals: 1.5 })).toEqual({});
    expect(navCounts({ unassigned_breaching: null })).toEqual({});
  });

  it('explains the role under the nav', () => {
    expect(roleNote(null)).toBe('');
    expect(roleNote(principal({ role: 'viewer' }))).toMatch(/viewer\. Admin pages are hidden/);
    expect(roleNote(principal())).toBe('Signed in as an analyst. Admin pages are hidden.');
    expect(roleNote(principal({ role: 'admin' }))).toBe('Signed in as a tenant admin.');
    expect(roleNote(principal({ role: 'admin', isPlatformAdmin: true }))).toBe('Signed in as a platform admin.');
    expect(roleNote(principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' }))).toMatch(/acting on a tenant/);
  });

  it('derives initials and role labels for the account menu', () => {
    expect(initials('m.roux@acme.example')).toBe('MR');
    expect(initials('analyst@acme.test')).toBe('AN');
    expect(initials(null)).toBe('?');
    expect(roleLabel('analyst', false)).toBe('Analyst');
    expect(roleLabel('admin', true)).toBe('Admin, platform admin');
    expect(roleLabel(null, false)).toBe('No role');
  });
});

describe('Sidebar', () => {
  it('hides counts the API does not send yet', async () => {
    const { api, calls } = shellApi();
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<Sidebar groups={NAV_GROUPS} />, session, { route: '/escalations' });
    await waitFor(() => expect(calls.some((c) => c.path === '/dashboard/summary')).toBe(true));
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'Escalations' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: 'Approvals' })).toHaveAttribute('href', '/approvals');
    expect(within(nav).getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
    expect(within(nav).queryByText(/breaching SLA/)).not.toBeInTheDocument();
    expect(within(nav).queryByText(/you can approve/)).not.toBeInTheDocument();
    expect(within(nav).getByRole('list', { name: 'Operate' })).toBeInTheDocument();
    expect(within(nav).queryByRole('list', { name: 'Configure' })).not.toBeInTheDocument();
    expect(screen.getByText('Signed in as an analyst. Admin pages are hidden.')).toBeInTheDocument();
  });

  it('shows counts with their meaning once the API sends them', async () => {
    const { api } = shellApi({ summary: { ...DASHBOARD, unassigned_breaching: 3, pending_approvals: 1 } });
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<Sidebar groups={NAV_GROUPS} />, session, { route: '/' });
    const escalations = await screen.findByRole('link', { name: 'Escalations 3 unassigned escalations breaching SLA' });
    expect(escalations).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Approvals 1 action you can approve' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('list', { name: 'Configure' })).toBeInTheDocument();
  });
});

describe('Header', () => {
  const renderHeader = async (opts: Parameters<typeof shellApi>[0] = {}, overrides = {}) => {
    const { api, calls } = shellApi(opts);
    const session = await signedInSession(api, overrides);
    const onOpenMenu = vi.fn();
    const onSignOut = vi.fn();
    const utils = renderWithSession(<Header page="Alerts" menuOpen={false} onOpenMenu={onOpenMenu} onSignOut={onSignOut} />, session, { route: '/alerts' });
    return { ...utils, calls, session, onOpenMenu, onSignOut };
  };

  it('falls back to the tenant id when /auth/me has no tenant_name', async () => {
    const { calls } = await renderHeader();
    await waitFor(() => expect(calls.some((c) => c.path === '/auth/me')).toBe(true));
    expect(screen.getByTestId('tenant-name')).toHaveTextContent('acme');
    expect(screen.getByRole('navigation', { name: 'Breadcrumb' })).toHaveTextContent('Alerts');
    expect(screen.getByRole('banner')).toHaveTextContent(/Offline|Connecting/);
    expect(screen.getByRole('group', { name: 'Theme' })).toBeInTheDocument();
  });

  it('shows tenant_name from /auth/me when the API sends it', async () => {
    await renderHeader({ me: { tenant_name: 'Acme Corp' } });
    await waitFor(() => expect(screen.getByTestId('tenant-name')).toHaveTextContent('Acme Corp'));
  });

  it('gives platform admins the tenant switcher with the tenant name', async () => {
    const { session } = await renderHeader({ me: { tenant_name: 'Acme Corp' }, tenants: [tenant('acme', 'Acme Corp'), tenant('globex', 'Globex')] }, { role: 'admin', is_platform_admin: true });
    const button = await screen.findByRole('button', { name: /Switch tenant, current: Acme Corp/ });
    await userEvent.click(button);
    expect(await screen.findByRole('combobox', { name: 'Search tenants' })).toBeInTheDocument();
    expect(session.auth.getState().actingTenant).toBeNull();
  });

  it('opens the phone menu', async () => {
    const { onOpenMenu } = await renderHeader();
    await userEvent.click(screen.getByRole('button', { name: 'Open menu' }));
    expect(onOpenMenu).toHaveBeenCalled();
  });
});

describe('account menu', () => {
  const renderMenu = async (overrides = {}) => {
    const { api } = shellApi();
    const session = await signedInSession(api, overrides);
    const onSignOut = vi.fn();
    renderWithSession(
      <Routes>
        <Route path="/" element={<UserMenu tenantLabel="Acme Corp" onSignOut={onSignOut} />} />
        <Route path="/account" element={<h1>Account page</h1>} />
      </Routes>,
      session,
    );
    return { onSignOut, session };
  };

  it('opens with the keyboard, moves with arrows and returns focus on Escape', async () => {
    const user = userEvent.setup();
    await renderMenu();
    const button = screen.getByRole('button', { name: 'Account: analyst@acme.test, Analyst' });
    expect(button).toHaveAttribute('aria-haspopup', 'menu');
    button.focus();
    await user.keyboard('{ArrowDown}');
    const menu = screen.getByRole('menu', { name: 'Account' });
    expect(button).toHaveAttribute('aria-expanded', 'true');
    expect(within(menu).getByText('Analyst · Acme Corp')).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: 'Account security' })).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(within(menu).getByRole('menuitemradio', { name: 'Dark theme' })).toHaveFocus();
    await user.keyboard('{End}');
    expect(within(menu).getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(within(menu).getByRole('menuitem', { name: 'Account security' })).toHaveFocus();
    await user.keyboard('{ArrowUp}');
    expect(within(menu).getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
    await user.keyboard('{Home}');
    expect(within(menu).getByRole('menuitem', { name: 'Account security' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(button).toHaveFocus();

    await user.keyboard('{ArrowUp}');
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
    await user.keyboard('{Tab}');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('switches theme and row density from the menu', async () => {
    const user = userEvent.setup();
    await renderMenu();
    const button = screen.getByRole('button', { name: /^Account: / });
    await user.click(button);
    expect(screen.getByRole('menuitemradio', { name: 'Dark theme' })).toHaveAttribute('aria-checked', 'true');
    await user.click(screen.getByRole('menuitemradio', { name: 'Light theme' }));
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(screen.getByRole('menuitemradio', { name: 'Light theme' })).toHaveAttribute('aria-checked', 'true');
    const rows = screen.getByRole('menuitemcheckbox', { name: 'Comfortable rows' });
    expect(rows).toHaveAttribute('aria-checked', 'false');
    await user.click(rows);
    expect(rows).toHaveAttribute('aria-checked', 'true');
    expect(document.documentElement.dataset.density).toBe('comfortable');
    await user.click(screen.getByRole('menuitemradio', { name: 'Dark theme' }));
    // Clicking outside closes.
    fireEvent.pointerDown(document.body);
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('opens account security', async () => {
    const user = userEvent.setup();
    await renderMenu();
    await user.click(screen.getByRole('button', { name: /^Account: / }));
    await user.click(screen.getByRole('menuitem', { name: 'Account security' }));
    expect(screen.getByRole('heading', { name: 'Account page' })).toBeInTheDocument();
  });

  it('signs out from the menu', async () => {
    const user = userEvent.setup();
    const { onSignOut } = await renderMenu();
    const button = screen.getByRole('button', { name: /^Account: / });
    await user.click(button);
    await user.click(button);
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    await user.click(button);
    await user.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    expect(onSignOut).toHaveBeenCalled();
  });

  it('hides account security while a platform admin acts on another tenant', async () => {
    const user = userEvent.setup();
    const { session } = await renderMenu({ role: 'admin', is_platform_admin: true });
    act(() => session.auth.setActingTenant('globex'));
    await user.click(screen.getByRole('button', { name: 'Account: analyst@acme.test, Admin, platform admin' }));
    expect(screen.queryByRole('menuitem', { name: 'Account security' })).not.toBeInTheDocument();
    expect(screen.getByRole('menuitemradio', { name: 'Dark theme' })).toHaveFocus();
  });
});

describe('Layout', () => {
  it('renders one header, the sidebar and the page, with a phone menu that returns focus', async () => {
    const user = userEvent.setup();
    const { api } = shellApi({ me: { tenant_name: 'Acme Corp' } });
    const session = await signedInSession(api);
    renderWithSession(
      <Routes>
        <Route element={<Layout />}>
          <Route path="/alerts" element={<h1>Alerts</h1>} />
          <Route path="/" element={<h1>Dashboard</h1>} />
        </Route>
      </Routes>,
      session,
      { route: '/alerts' },
    );
    expect(screen.getAllByRole('banner')).toHaveLength(1);
    expect(screen.getByRole('heading', { name: 'Alerts', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Skip to main content' })).toHaveAttribute('href', '#main');
    await waitFor(() => expect(screen.getByTestId('tenant-name')).toHaveTextContent('Acme Corp'));

    const open = screen.getByRole('button', { name: 'Open menu' });
    await user.click(open);
    const drawer = screen.getByRole('dialog', { name: 'Main menu' });
    expect(within(drawer).getByRole('button', { name: 'Close menu' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(open).toHaveFocus();

    await user.click(open);
    await user.click(within(screen.getByRole('dialog', { name: 'Main menu' })).getByRole('link', { name: 'Overview' }));
    expect(await screen.findByRole('heading', { name: 'Dashboard', level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.getElementById('main')).toHaveFocus();
  });

  it('signs out through the store from the account menu', async () => {
    const user = userEvent.setup();
    const { api } = shellApi();
    const session = await signedInSession(api);
    renderWithSession(
      <Routes>
        <Route path="/" element={<Layout />} />
      </Routes>,
      session,
    );
    await user.click(screen.getByRole('button', { name: /^Account: / }));
    await user.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    await waitFor(() => expect(session.auth.getState().status).toBe('anonymous'));
  });
});

describe('LiveIndicator', () => {
  const renderStatus = async (status: LiveStatus, acting: string | null = null) => {
    const { api } = shellApi();
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    if (acting) act(() => session.auth.setActingTenant(acting));
    renderWithSession(
      <LiveContext.Provider value={{ status, subscribe: () => () => undefined }}>
        <div data-testid="live">
          <LiveIndicator />
        </div>
      </LiveContext.Provider>,
      session,
    );
    return within(screen.getByTestId('live')).getByRole('status');
  };

  it.each<[LiveStatus, string]>([
    ['open', 'Live'],
    ['reconnecting', 'Reconnecting'],
    ['connecting', 'Connecting'],
    ['idle', 'Offline'],
    ['closed', 'Offline'],
  ])('shows %s as %s', async (status, label) => {
    const indicator = await renderStatus(status);
    expect(indicator).toHaveTextContent(label);
    expect(indicator).not.toHaveAttribute('title');
  });

  it('explains an unavailable stream', async () => {
    const indicator = await renderStatus('unavailable');
    expect(indicator).toHaveTextContent('Live updates unavailable');
    expect(indicator).toHaveAttribute('title', expect.stringMatching(/api\.cors_origins/));
  });

  it('says live updates are off while acting on another tenant', async () => {
    const indicator = await renderStatus('unavailable', 'globex');
    expect(indicator).toHaveTextContent('Live updates off (acting on another tenant)');
    expect(indicator).not.toHaveAttribute('title');
  });
});
