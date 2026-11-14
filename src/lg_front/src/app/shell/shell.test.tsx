import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Boxes } from 'lucide-react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Principal } from '../../auth/store';
import * as config from '../../config';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { LiveContext } from '../../live/LiveProvider';
import type { LiveStatus } from '../../live/socket';
import { Layout } from '../Layout';
import { NAV_GROUPS, REGISTRY } from '../routes';
import { AccountMenu, initials, roleLabel } from './AccountMenu';
import { BrandMark, brandInitials } from './BrandMark';
import { navFor, searchPrompt, type NavGroup } from './nav';
import { Rail } from './Rail';
import { LiveIndicator, ThemeControl, TopBar } from './TopBar';

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

/** An API that answers the shell's reads (dashboard summary, /auth/me, the sources of an admin). */
function shellApi({ summary = DASHBOARD as object, me = {} as object, sources = [] as unknown[] } = {}) {
  return fakeApi((_method, path) => {
    if (path === '/dashboard/summary') return summary;
    if (path === '/auth/me') return { kind: 'user', tenant_id: 'acme', home_tenant_id: 'acme', auth_method: 'password', ...me };
    if (path === '/sources') return sources;
    return [];
  });
}

/** A service group as a second module would declare it, with the module switched on or off. */
function serviceGroup(licensed: boolean): NavGroup {
  return {
    id: 'voc',
    title: 'Vulnerabilities',
    service: true,
    items: [
      { to: '/voc/findings', label: 'Findings', icon: Boxes, allowed: () => true, enabled: () => licensed },
      { to: '/voc/remediation', label: 'Remediation', icon: Boxes, allowed: () => true, enabled: () => licensed },
    ],
  };
}

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
});

describe('navigation model', () => {
  it('puts the pages in the capability groups of console v2, by role', () => {
    expect(titles(principal({ role: 'viewer' }))).toEqual(['Work: Overview, Queue, Approvals', 'Detect and respond: Alerts, Suppressions', 'Assure: Reports']);
    expect(titles(principal())).toEqual(['Work: Overview, Queue, Approvals', 'Detect and respond: Alerts, Suppressions, Blind audit', 'Assure: Reports']);
    expect(titles(principal({ role: 'admin' }))).toEqual([
      'Work: Overview, Queue, Approvals',
      'Detect and respond: Alerts, Suppressions, Blind audit',
      'Assure: Reports, Audit log, AI usage and cost, Proof of value',
      'Configure: Getting started, Sources, Integrations, People and keys, Tenant settings',
    ]);
    expect(titles(principal({ role: 'admin', isPlatformAdmin: true })).at(-1)).toBe('Platform: Tenants');
    // The console works across tenants: hidden while acting on one.
    expect(titles(principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' }))).not.toContain('Platform: Tenants');
    expect(navFor(NAV_GROUPS, null)).toEqual([]);
    // The older escalation list has no entry in the rail; the work queue is where work waits.
    expect(NAV_GROUPS.flatMap((g) => g.items).map((i) => i.to)).not.toContain('/escalations');
  });

  it('maps every item to an existing route', () => {
    const items = navFor(NAV_GROUPS, principal({ role: 'admin', isPlatformAdmin: true })).flatMap((g) => g.items);
    expect(Object.fromEntries(items.map((i) => [i.label, i.to]))).toMatchObject({ Overview: '/', Queue: '/queue', Approvals: '/approvals', Tenants: '/platform' });
  });

  it('lists a service that is not licensed locked for a platform admin and not at all for a customer', () => {
    const groups = [serviceGroup(false)];
    expect(navFor(groups, principal({ role: 'admin' }))).toEqual([]);
    expect(navFor(groups, principal({ role: 'viewer' }))).toEqual([]);
    const forOperator = navFor(groups, principal({ role: 'admin', isPlatformAdmin: true }));
    expect(forOperator.map((g) => [g.title, g.locked, g.items.map((i) => i.label)])).toEqual([['Vulnerabilities', true, ['Findings', 'Remediation']]]);
    // Also while the operator works in a customer's tenant.
    expect(navFor(groups, principal({ role: 'admin', isPlatformAdmin: true, tenantId: 'globex' }))[0].locked).toBe(true);
    // Licensed: an ordinary group for everyone.
    expect(navFor([serviceGroup(true)], principal()).map((g) => [g.title, g.locked])).toEqual([['Vulnerabilities', false]]);
    // A capability group never lists a page that does not open, whoever asks.
    expect(navFor([{ ...serviceGroup(false), service: undefined }], principal({ role: 'admin', isPlatformAdmin: true }))).toEqual([]);
  });

  it('derives initials and role labels for the person at the bottom of the rail', () => {
    expect(initials('m.roux@acme.example')).toBe('MR');
    expect(initials('analyst@acme.test')).toBe('AN');
    expect(initials(null)).toBe('?');
    expect(roleLabel('analyst', false)).toBe('Analyst');
    expect(roleLabel('admin', true)).toBe('Admin, platform admin');
    expect(roleLabel(null, false)).toBe('No role');
  });

  it('says in the search field what it finds', () => {
    expect(searchPrompt(REGISTRY, principal())).toBe('Search pages and alerts');
    expect(searchPrompt(REGISTRY, null)).toBe('Search pages');
    const things = { ...REGISTRY.searches[0], label: 'Things' };
    expect(searchPrompt({ searches: [...REGISTRY.searches, things] }, principal())).toBe('Search pages, alerts and things');
  });
});

describe('brand', () => {
  it('shows the product\'s own mark for the product, a logo when the brand has one, else two letters', () => {
    expect(brandInitials('Brightwater SOC')).toBe('BS');
    expect(brandInitials('Nordvakt')).toBe('NO');
    const { container, rerender } = render(<BrandMark brand={config.PRODUCT_BRAND} />);
    expect(container.querySelector('svg')).not.toBeNull();
    expect(container).toHaveTextContent('');
    rerender(<BrandMark brand={{ ...config.PRODUCT_BRAND, name: 'Brightwater SOC' }} />);
    expect(container).toHaveTextContent('BS');
    rerender(<BrandMark brand={{ ...config.PRODUCT_BRAND, name: 'Brightwater SOC', logoUrl: '/brand/logo.svg' }} />);
    expect(container.querySelector('img')).toHaveAttribute('src', '/brand/logo.svg');
    // Decorative: the name stands next to it.
    expect(container.querySelector('img')).toHaveAttribute('alt', '');
  });

  it('takes the name in the rail and on the browser tab from the one brand object', async () => {
    vi.spyOn(config, 'getBrand').mockReturnValue({ name: 'Brightwater SOC', tagline: 'on LG-SOTF', logoUrl: null, accent: null });
    const session = await signedInSession(shellApi().api);
    renderWithSession(
      <Routes>
        <Route element={<Layout />}>
          <Route path="/alerts" element={<h1>Alerts</h1>} />
        </Route>
      </Routes>,
      session,
      { route: '/alerts' },
    );
    const home = within(screen.getByRole('navigation', { name: 'Main' })).getByRole('link', { name: 'Brightwater SOC on LG-SOTF' });
    expect(home).toHaveAttribute('href', '/');
    expect(home).toHaveTextContent('BS');
    expect(document.title).toBe('Alerts · Brightwater SOC');
  });
});

describe('Rail', () => {
  const renderRail = async (opts: Parameters<typeof shellApi>[0], overrides: object, groups: readonly NavGroup[] = NAV_GROUPS, route = '/') => {
    const { api, calls } = shellApi(opts);
    const session = await signedInSession(api, overrides);
    const onSignOut = vi.fn();
    renderWithSession(<Rail groups={groups} tenantLabel="Acme Corp" onSignOut={onSignOut} />, session, { route });
    return { calls, session, onSignOut, nav: screen.getByRole('navigation', { name: 'Main' }) };
  };

  it('shows the brand, the groups of the role, the current page and the person, and no count the API does not send', async () => {
    const { calls, nav } = await renderRail({}, { role: 'analyst' }, NAV_GROUPS, '/queue');
    await waitFor(() => expect(calls.some((c) => c.path === '/dashboard/summary')).toBe(true));
    expect(within(nav).getByRole('link', { name: 'LG-SOTF Security operations' })).toHaveAttribute('href', '/');
    expect(within(nav).getByRole('link', { name: 'Queue' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).queryByRole('link', { name: 'Escalations' })).not.toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Approvals' })).toHaveAttribute('href', '/approvals');
    expect(within(nav).getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
    expect(within(nav).queryByText(/breaching SLA/)).not.toBeInTheDocument();
    expect(within(nav).queryByText(/you can approve/)).not.toBeInTheDocument();
    expect(within(nav).getAllByRole('list').map((l) => l.getAttribute('aria-labelledby') && document.getElementById(l.getAttribute('aria-labelledby') as string)?.textContent)).toEqual([
      'Work',
      'Detect and respond',
      'Assure',
    ]);
    expect(within(nav).queryByRole('list', { name: 'Configure' })).not.toBeInTheDocument();
    expect(within(nav).getByRole('button', { name: 'Account: AN analyst@acme.test Analyst' })).toBeInTheDocument();
  });

  it('shows counts with their meaning once the API sends them', async () => {
    await renderRail({ summary: { ...DASHBOARD, unassigned_breaching: 3, pending_approvals: 1 } }, { role: 'admin' });
    const queue = await screen.findByRole('link', { name: 'Queue 3 unassigned escalations breaching SLA' });
    expect(within(queue).getByTitle('3 unassigned escalations breaching SLA')).toHaveTextContent('3');
    expect(screen.getByRole('link', { name: 'Approvals 1 action you can approve' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('list', { name: 'Configure' })).toBeInTheDocument();
  });

  it('lists a service that is not licensed locked, in words, for a platform admin', async () => {
    const { nav } = await renderRail({}, { role: 'admin', is_platform_admin: true }, [...NAV_GROUPS, serviceGroup(false)]);
    const group = within(nav).getByRole('list', { name: 'Vulnerabilities Not licensed' });
    expect(within(group).getByRole('link', { name: /^Findings ?, not licensed$/ })).toHaveAttribute('href', '/voc/findings');
    expect(within(group).getAllByRole('link')).toHaveLength(2);
    // The SOC's own groups are not locked.
    expect(within(nav).getByRole('list', { name: 'Work' })).toBeInTheDocument();
  });

  it('does not show a customer a service that is not licensed', async () => {
    const { nav } = await renderRail({}, { role: 'admin' }, [...NAV_GROUPS, serviceGroup(false)]);
    expect(within(nav).queryByText('Vulnerabilities')).not.toBeInTheDocument();
    expect(within(nav).queryByText('Not licensed')).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: /Findings/ })).not.toBeInTheDocument();
  });
});

describe('TopBar', () => {
  const renderBar = async (opts: Parameters<typeof shellApi>[0] = {}, overrides = {}, tenantLabel = 'acme') => {
    const { api, calls } = shellApi(opts);
    const session = await signedInSession(api, overrides);
    const onOpenMenu = vi.fn();
    const onSearch = vi.fn();
    const utils = renderWithSession(
      <Routes>
        <Route path="*" element={<TopBar registry={REGISTRY} tenantLabel={tenantLabel} menuOpen={false} onOpenMenu={onOpenMenu} onSearch={onSearch} />} />
      </Routes>,
      session,
      { route: '/alerts' },
    );
    return { ...utils, calls, session, onOpenMenu, onSearch };
  };

  it('shows the scope, the search field, the live status, notifications and the theme', async () => {
    const { onSearch, onOpenMenu } = await renderBar();
    const bar = screen.getByRole('banner');
    expect(within(bar).getByTestId('tenant-name')).toHaveTextContent('acme');
    expect(within(bar).getByRole('status')).toHaveTextContent(/Offline|Connecting/);
    expect(within(bar).getByRole('button', { name: 'Notifications: nothing needs you' })).toBeInTheDocument();
    expect(within(bar).getByRole('button', { name: /^Theme: System/ })).toBeInTheDocument();

    // The field's words are its accessible name, with the keys that open it.
    await userEvent.click(within(bar).getByRole('button', { name: 'Search pages and alerts Ctrl K' }));
    expect(onSearch).toHaveBeenCalledTimes(1);
    await userEvent.click(within(bar).getByRole('button', { name: 'Open the menu' }));
    expect(onOpenMenu).toHaveBeenCalledTimes(1);
  });

  it('steps the theme through System, Light and Dark, saying which is on', async () => {
    renderWithSession(<ThemeControl />, await signedInSession(shellApi().api));
    const button = () => screen.getByRole('button', { name: /^Theme: / });
    expect(button()).toHaveAccessibleName('Theme: System (follows the system). Change to Light');
    expect(button()).toHaveTextContent('System');
    await userEvent.click(button());
    expect(button()).toHaveAccessibleName('Theme: Light (light). Change to Dark');
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(window.localStorage.getItem('lg-sotf.theme')).toBe('light');
    await userEvent.click(button());
    expect(button()).toHaveTextContent('Dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
    await userEvent.click(button());
    expect(button()).toHaveTextContent('System');
    expect(window.localStorage.getItem('lg-sotf.theme')).toBe('system');
  });
});

describe('Notifications', () => {
  const soon = () => new Date(Date.now() + 4 * 60_000 - 5_000).toISOString();
  const renderBar = async (opts: Parameters<typeof shellApi>[0], overrides = {}) => {
    const { api, calls } = shellApi(opts);
    const session = await signedInSession(api, overrides);
    renderWithSession(
      <Routes>
        <Route path="/" element={<TopBar registry={REGISTRY} tenantLabel="Acme Corp" menuOpen={false} onOpenMenu={vi.fn()} onSearch={vi.fn()} />} />
        <Route path="*" element={<h1>Another page</h1>} />
      </Routes>,
      session,
    );
    return { calls, session };
  };

  it('says so when nothing needs an act', async () => {
    const user = userEvent.setup();
    const { calls } = await renderBar({});
    const bell = screen.getByRole('button', { name: 'Notifications: nothing needs you' });
    expect(bell).toHaveAttribute('aria-expanded', 'false');
    await user.click(bell);
    const dialog = screen.getByRole('dialog', { name: 'Notifications' });
    expect(dialog).toHaveTextContent('Nothing needs you right now in Acme Corp.');
    expect(within(dialog).queryByRole('link')).not.toBeInTheDocument();
    // An analyst may not read sources: the shell does not ask.
    expect(calls.some((c) => c.path === '/sources')).toBe(false);
    await user.click(bell);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('lists what needs an act, each line with its tenant, and opens the page where the act happens', async () => {
    const user = userEvent.setup();
    await renderBar(
      {
        summary: { ...DASHBOARD, overdue_escalations: 1, unassigned_breaching: 2, next_sla_deadline: soon(), pending_approvals: 4 },
        sources: [
          { id: 's-1', name: 'Wazuh manager', enabled: true, health: 'failing' },
          { id: 's-2', name: 'Sentinel', enabled: true, health: 'healthy' },
          { id: 's-3', name: 'Old Splunk', enabled: false, health: 'failing' },
        ],
      },
      { role: 'admin' },
    );
    const bell = await screen.findByRole('button', { name: 'Notifications: 4 need an act' });
    expect(bell).toHaveTextContent('4');
    await user.click(bell);
    const dialog = screen.getByRole('dialog', { name: 'Notifications' });
    expect(within(dialog).getAllByRole('link').map((a) => [a.textContent, a.getAttribute('href')])).toEqual([
      ['1 escalation is past its deadlineAcme Corp · the queue lists them first', '/queue'],
      ['A deadline passes in 4 minAcme Corp · 2 escalations near their deadline have no owner', '/queue?view=soon'],
      ['4 actions wait for your approvalAcme Corp', '/approvals'],
      ['Source failing: Wazuh managerAcme Corp · alerts may be missing', '/sources'],
    ]);
    await user.click(within(dialog).getByRole('link', { name: /4 actions wait for your approval/ }));
    expect(await screen.findByRole('heading', { name: 'Another page' })).toBeInTheDocument();
  });

  it('closes on Escape, returning focus to the bell, and on a press outside', async () => {
    const user = userEvent.setup();
    await renderBar({ summary: { ...DASHBOARD, pending_approvals: 1 } });
    const bell = await screen.findByRole('button', { name: 'Notifications: 1 needs an act' });
    await user.click(bell);
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(bell).toHaveFocus();
    await user.click(bell);
    fireEvent.pointerDown(screen.getByRole('dialog', { name: 'Notifications' }));
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeInTheDocument();
    fireEvent.pointerDown(document.body);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});

describe('account menu', () => {
  const renderMenu = async (overrides = {}) => {
    const { api } = shellApi();
    const session = await signedInSession(api, overrides);
    const onSignOut = vi.fn();
    renderWithSession(
      <Routes>
        <Route path="/" element={<AccountMenu tenantLabel="Acme Corp" onSignOut={onSignOut} />} />
        <Route path="/account" element={<h1>Account page</h1>} />
      </Routes>,
      session,
    );
    return { onSignOut, session };
  };

  it('opens with the keyboard, moves with arrows and returns focus on Escape', async () => {
    const user = userEvent.setup();
    await renderMenu();
    const button = screen.getByRole('button', { name: 'Account: AN analyst@acme.test Analyst' });
    expect(button).toHaveAttribute('aria-haspopup', 'menu');
    button.focus();
    await user.keyboard('{ArrowDown}');
    const menu = screen.getByRole('menu', { name: 'Account' });
    expect(button).toHaveAttribute('aria-expanded', 'true');
    expect(within(menu).getByText('Analyst · Acme Corp')).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: 'Account security' })).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(within(menu).getByRole('menuitemcheckbox', { name: 'Comfortable rows' })).toHaveFocus();
    await user.keyboard('{End}');
    expect(within(menu).getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(within(menu).getByRole('menuitem', { name: 'Account security' })).toHaveFocus();
    await user.keyboard('{ArrowUp}');
    expect(within(menu).getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
    await user.keyboard('{Home}');
    expect(within(menu).getByRole('menuitem', { name: 'Account security' })).toHaveFocus();
    await user.keyboard('x');
    expect(within(menu).getByRole('menuitem', { name: 'Account security' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(button).toHaveFocus();

    await user.keyboard('{ArrowUp}');
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toHaveFocus();
    await user.keyboard('{Tab}');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('switches row density from the menu and closes on a press outside', async () => {
    const user = userEvent.setup();
    await renderMenu();
    await user.click(screen.getByRole('button', { name: /^Account: / }));
    const rows = screen.getByRole('menuitemcheckbox', { name: 'Comfortable rows' });
    expect(rows).toHaveAttribute('aria-checked', 'false');
    await user.click(rows);
    expect(rows).toHaveAttribute('aria-checked', 'true');
    expect(document.documentElement.dataset.density).toBe('comfortable');
    await user.click(rows);
    expect(document.documentElement.dataset.density).toBe('compact');
    // The theme has its own control in the top bar.
    expect(screen.queryByRole('menuitemradio')).not.toBeInTheDocument();
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
    await user.click(screen.getByRole('button', { name: 'Account: AN analyst@acme.test Admin, platform admin' }));
    expect(screen.queryByRole('menuitem', { name: 'Account security' })).not.toBeInTheDocument();
    expect(screen.getByRole('menuitemcheckbox', { name: 'Comfortable rows' })).toHaveFocus();
  });

  it('says so when the session has no e-mail, and marks single sign-on', async () => {
    const user = userEvent.setup();
    const session = await signedInSession(shellApi().api);
    const state = session.auth.getState();
    vi.spyOn(session.auth, 'getState').mockReturnValue({ ...state, principal: { ...(state.principal as Principal), email: null, method: 'oidc' } });
    renderWithSession(<AccountMenu tenantLabel="Acme Corp" onSignOut={vi.fn()} />, session);
    await user.click(screen.getByRole('button', { name: 'Account: ? Signed in Analyst' }));
    expect(screen.getByRole('menu', { name: 'Account' })).toHaveTextContent('Analyst · Acme Corp · SSO');
  });
});

describe('Layout', () => {
  const renderLayout = async (route = '/alerts', overrides = {}) => {
    const { api, calls } = shellApi({ me: { tenant_name: 'Acme Corp' } });
    const session = await signedInSession(api, overrides);
    renderWithSession(
      <Routes>
        <Route element={<Layout />}>
          <Route path="/alerts" element={<h1>Alerts</h1>} />
          <Route
            path="/"
            element={
              <>
                <h1>Dashboard</h1>
                <input aria-label="A page field" />
              </>
            }
          />
          <Route path="/nowhere" element={<h1>Unnamed</h1>} />
        </Route>
      </Routes>,
      session,
      { route },
    );
    return { session, calls };
  };

  it('renders one top bar, the rail and the page, names the page on the browser tab, and has a menu that returns focus', async () => {
    const user = userEvent.setup();
    await renderLayout();
    expect(screen.getAllByRole('banner')).toHaveLength(1);
    expect(screen.getByRole('heading', { name: 'Alerts', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Skip to main content' })).toHaveAttribute('href', '#main');
    await waitFor(() => expect(screen.getByTestId('tenant-name')).toHaveTextContent('Acme Corp'));
    expect(document.title).toBe('Alerts · LG-SOTF');

    const open = screen.getByRole('button', { name: 'Open the menu' });
    await user.click(open);
    const drawer = screen.getByRole('dialog', { name: 'Main menu' });
    expect(within(drawer).getByRole('button', { name: 'Close the menu' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(open).toHaveFocus();

    await user.click(open);
    await user.click(within(screen.getByRole('dialog', { name: 'Main menu' })).getByRole('button', { name: 'Close the menu' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    await user.click(open);
    await user.click(within(screen.getByRole('dialog', { name: 'Main menu' })).getByRole('link', { name: 'Overview' }));
    expect(await screen.findByRole('heading', { name: 'Dashboard', level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.getElementById('main')).toHaveFocus();
    expect(document.title).toBe('Overview · LG-SOTF');
  });

  it('names the console alone on the browser tab of a page without a name', async () => {
    await renderLayout('/nowhere');
    expect(document.title).toBe('LG-SOTF');
  });

  it('keeps Tab and Shift+Tab inside the open menu', async () => {
    const user = userEvent.setup();
    await renderLayout('/', { role: 'viewer' });
    await user.click(screen.getByRole('button', { name: 'Open the menu' }));
    const drawer = screen.getByRole('dialog', { name: 'Main menu' });
    const close = within(drawer).getByRole('button', { name: 'Close the menu' });
    expect(close).toHaveFocus();
    const first = within(drawer).getByRole('link', { name: 'LG-SOTF Security operations' });

    // Forwards from the last control wraps to the first, backwards from the first wraps to the last.
    await user.tab();
    expect(first).toHaveFocus();
    await user.tab({ shift: true });
    expect(close).toHaveFocus();
    // A full round trip never leaves the menu.
    for (let i = 0; i < within(drawer).getAllByRole('link').length + 3; i += 1) {
      await user.tab();
      expect(drawer).toContainElement(document.activeElement as HTMLElement);
    }
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open the menu' })).toHaveFocus();
  });

  it('signs out through the store from the person at the bottom of the rail', async () => {
    const user = userEvent.setup();
    const { session } = await renderLayout('/');
    await user.click(screen.getByRole('button', { name: /^Account: / }));
    await user.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    await waitFor(() => expect(session.auth.getState().status).toBe('anonymous'));
  });

  it('opens the search field from its button, with Ctrl+K and with the slash key', async () => {
    const user = userEvent.setup();
    await renderLayout('/');
    const field = screen.getByRole('button', { name: /^Search pages and alerts/ });
    await user.click(field);
    expect(await screen.findByRole('dialog', { name: 'Search and commands' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Search' })).toHaveFocus();
    // Ctrl+K closes it again, and focus is back on the field's button.
    await user.keyboard('{Control>}k{/Control}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(field).toHaveFocus();

    await user.keyboard('{Meta>}K{/Meta}');
    expect(await screen.findByRole('dialog', { name: 'Search and commands' })).toBeInTheDocument();
    // The slash is a character while the field is open.
    await user.keyboard('/');
    expect(screen.getByRole('combobox', { name: 'Search' })).toHaveValue('/');
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    // A slash typed into a field of the page stays there.
    await user.click(screen.getByRole('textbox', { name: 'A page field' }));
    await user.keyboard('/');
    expect(screen.getByRole('textbox', { name: 'A page field' })).toHaveValue('/');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    // Outside a field it opens the search field; with a modifier it is the browser's.
    act(() => document.getElementById('main')?.focus());
    await user.keyboard('{Alt>}/{/Alt}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.keyboard('/');
    expect(await screen.findByRole('dialog', { name: 'Search and commands' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Search' })).toHaveValue('');
  });

  it('lets single-key shortcuts be switched off: the slash then does nothing, Ctrl+K still works', async () => {
    const user = userEvent.setup();
    window.localStorage.setItem('lg-sotf.single-keys.u-1', 'off');
    await renderLayout('/');
    act(() => document.getElementById('main')?.focus());
    await user.keyboard('/');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.keyboard('{Control>}k{/Control}');
    expect(await screen.findByRole('dialog', { name: 'Search and commands' }, { timeout: 10_000 })).toBeInTheDocument();
    // The command that turns them back on says so, and the choice is kept.
    await user.keyboard('>single');
    expect(screen.getByRole('option', { name: /Single-key shortcuts: turn on/ })).toBeInTheDocument();
    await user.keyboard('{Enter}');
    expect(window.localStorage.getItem('lg-sotf.single-keys.u-1')).toBe('on');
    expect(await screen.findByText('Single-key shortcuts are on. Ctrl K, Tab and Enter always work.')).toBeInTheDocument();
    await user.keyboard('/');
    expect(await screen.findByRole('dialog', { name: 'Search and commands' })).toBeInTheDocument();
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

  it('says live updates are off, and why, while working in another tenant', async () => {
    const indicator = await renderStatus('unavailable', 'globex');
    expect(indicator).toHaveTextContent('Live updates off. Live updates are off while you work in another tenant');
    expect(indicator).toHaveAttribute('title', expect.stringMatching(/another tenant/));
  });
});
