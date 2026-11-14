/**
 * A service this installation's licence does not include (ADR 0015, PRD-2.12).
 *
 * `moduleEnabled` is the one place that says whether a tenant has a module. Today it says yes for every
 * module; here it is stubbed to switch the example module off (there is no second service yet, and no
 * fake one is shipped to users). The route guard, the rail, the search field, the notifications and the
 * extension points all ask it:
 *
 * - a customer tenant's users do not see the service at all, and are never shown something to buy;
 * - a platform admin sees its group in the rail, locked and labelled "Not licensed", and each item
 *   opens the page that says the service is not part of this installation's licence.
 *
 * The server-supplied entitlement field is ARCH-E10.2 (#377).
 */
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type * as ModuleContract from '../core/module';
import { AlertEntities } from '../modules/soc/components/AlertEntities';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import { AppRoutes } from './App';
import type * as ModulesFile from './modules';
import { mayOpen } from './registry';
import { APP_ROUTES, NAV_GROUPS, REGISTRY } from './routes';
import { commandItems, pageItems } from './shell/CommandPalette';
import { navFor, searchPrompt } from './shell/nav';

vi.mock('./modules', async (importOriginal) => {
  const real = await importOriginal<typeof ModulesFile>();
  const { scaffold } = await import('../test/scaffold-module');
  return { ...real, MODULES: [...real.MODULES, scaffold] };
});

// The installation has the SOC but not the scaffold service.
vi.mock('../core/module', async (importOriginal) => {
  const real = await importOriginal<typeof ModuleContract>();
  return { ...real, moduleEnabled: (manifest: { id: string }) => manifest.id !== 'scaffold' };
});

const LAZY = { timeout: 10_000 };
const analyst = { userId: 'u-1', email: 'x@acme.test', role: 'analyst', tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: false, method: 'password' as const };
const operator = { ...analyst, role: 'admin', isPlatformAdmin: true };

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

async function open(route: string, user: object) {
  stubWebSocket();
  const calls = fakeApi(() => new Promise(() => undefined));
  const session = await signedInSession(calls.api, user);
  renderWithSession(<AppRoutes />, session, { route });
  const nav = await screen.findByRole('navigation', { name: 'Main' }, LAZY);
  return { nav, calls: calls.calls };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('a service the licence does not include', () => {
  const route = APP_ROUTES.find((r) => r.path === '/scaffold');

  it('is still registered, and its role rule alone would let an analyst in', () => {
    expect(route?.module).toBe('scaffold');
    expect(route?.allowed(analyst)).toBe(true);
    expect(route && mayOpen(route, analyst)).toBe(false);
    // The SOC is untouched.
    const alerts = APP_ROUTES.find((r) => r.path === '/alerts');
    expect(alerts && mayOpen(alerts, analyst)).toBe(true);
  });

  it('is absent from a customer\'s rail and listed locked in a platform admin\'s', () => {
    expect(navFor(NAV_GROUPS, analyst).map((g) => g.title)).toEqual(['Work', 'Detect and respond', 'Assure']);
    expect(navFor(NAV_GROUPS, { ...analyst, role: 'admin' }).map((g) => g.title)).not.toContain('Scaffold');
    const groups = navFor(NAV_GROUPS, operator);
    expect(groups.map((g) => [g.title, g.locked])).toEqual([
      ['Work', false],
      ['Scaffold', true],
      ['Detect and respond', false],
      ['Assure', false],
      ['Configure', false],
      ['Platform', false],
    ]);
    expect(groups[1].items.map((i) => i.label)).toEqual(['Scaffold things']);
  });

  it('adds nothing to the search field or its commands, for anyone', () => {
    for (const p of [analyst, operator]) {
      expect(pageItems(REGISTRY, p).map((i) => i.title)).not.toContain('Scaffold things');
      expect(commandItems(REGISTRY, p).map((i) => i.title)).not.toContain('Sort the scaffold things');
      expect(searchPrompt(REGISTRY, p)).toBe('Search pages and alerts');
    }
  });

  it('tells a customer who types its address that the page is not part of their console, with nothing to buy', async () => {
    const { nav, calls } = await open('/scaffold', { role: 'analyst' });
    expect(await screen.findByRole('heading', { name: 'This page is not part of your console' }, LAZY)).toBeInTheDocument();
    expect(screen.getByRole('main')).toHaveTextContent('Scaffold is not enabled for your organisation. The rest of the console works as before.');
    expect(screen.queryByText('Not licensed')).not.toBeInTheDocument();
    expect(screen.queryByText('What it would add')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Scaffold things' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: /Scaffold things/ })).not.toBeInTheDocument();
    expect(within(nav).queryByText('Scaffold')).not.toBeInTheDocument();
    // Its count and notice hooks never ran: nothing asked the module's API.
    expect(calls.some((c) => c.path.startsWith('/scaffold'))).toBe(false);
  });

  it('shows a platform admin the locked group, and the page that says the service is not licensed', async () => {
    const { nav, calls } = await open('/', { role: 'admin', is_platform_admin: true });
    const group = within(nav).getByRole('list', { name: 'Scaffold Not licensed' });
    const link = within(group).getByRole('link', { name: /^Scaffold things ?, not licensed$/ });
    expect(link).toHaveAttribute('href', '/scaffold');
    await userEvent.click(link);
    expect(await screen.findByRole('heading', { name: "Scaffold is not part of this installation's licence.", level: 1 }, LAZY)).toBeInTheDocument();
    const main = screen.getByRole('main');
    expect(main).toHaveTextContent('Not licensed');
    expect(main).toHaveTextContent('Nothing is collected and nothing is hidden from you');
    // What the service would add, from its manifest.
    expect(within(main).getByRole('heading', { name: 'What it would add' })).toBeInTheDocument();
    expect(within(main).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'Scaffold things: the things that wait, in one list',
      'On every alert: a note next to each host',
    ]);
    expect(link).toHaveAttribute('aria-current', 'page');
    // The service's own page did not load and its API was not asked.
    expect(screen.queryByRole('heading', { name: 'Scaffold things' })).not.toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith('/scaffold'))).toBe(false);
  });

  it('contributes nothing to another module, whatever its own rule says', async () => {
    const contribution = REGISTRY.extensions.find((c) => c.slot.id === 'alert.entity');
    expect(contribution?.when?.(analyst)).toBe(false);
    const session = await signedInSession(fakeApi(() => ({})).api, { role: 'analyst' });
    renderWithSession(<AlertEntities layout="stacked" entities={[['hosts', ['LT-1']]]} />, session);
    expect(screen.getByText('LT-1').nextElementSibling).toBeNull();
    expect(screen.queryByText(/Scaffold note/)).not.toBeInTheDocument();
  });
});
