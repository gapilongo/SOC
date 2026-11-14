/**
 * The entitlement hook of ADR 0015: `moduleEnabled` is the one place that says whether a tenant has a
 * module. Today it says yes for every module; here it is stubbed to switch the example module off, to
 * pin down that the route guard, the sidebar and the extension points all ask it. The server-supplied
 * field and the "not enabled for this tenant" page are ARCH-E10.2.
 */
import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type * as ModuleContract from '../core/module';
import { AlertEntities } from '../modules/soc/components/AlertEntities';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import { AppRoutes } from './App';
import type * as ModulesFile from './modules';
import { mayOpen } from './registry';
import { APP_ROUTES, NAV_GROUPS, REGISTRY } from './routes';
import { navFor } from './shell/nav';

vi.mock('./modules', async (importOriginal) => {
  const real = await importOriginal<typeof ModulesFile>();
  const { scaffold } = await import('../test/scaffold-module');
  return { ...real, MODULES: [...real.MODULES, scaffold] };
});

// The tenant has the SOC but not the scaffold module.
vi.mock('../core/module', async (importOriginal) => {
  const real = await importOriginal<typeof ModuleContract>();
  return { ...real, moduleEnabled: (manifest: { id: string }) => manifest.id !== 'scaffold' };
});

const LAZY = { timeout: 10_000 };
const analyst = { userId: 'u-1', email: 'x@acme.test', role: 'analyst', tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: false, method: 'password' as const };

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

describe('a module the tenant does not have', () => {
  const route = APP_ROUTES.find((r) => r.path === '/scaffold');

  it('is still registered, and its role rule alone would let an analyst in', () => {
    expect(route?.module).toBe('scaffold');
    expect(route?.allowed(analyst)).toBe(true);
    expect(route && mayOpen(route, analyst)).toBe(false);
    // The SOC is untouched.
    const alerts = APP_ROUTES.find((r) => r.path === '/alerts');
    expect(alerts && mayOpen(alerts, analyst)).toBe(true);
  });

  it('is not in the sidebar', () => {
    expect(navFor(NAV_GROUPS, analyst).map((g) => g.title)).toEqual(['Operate', 'Report']);
  });

  it('is refused by the route guard, even when the URL is typed', async () => {
    stubWebSocket();
    const calls = fakeApi(() => new Promise(() => undefined));
    const session = await signedInSession(calls.api, { role: 'analyst' });
    renderWithSession(<AppRoutes />, session, { route: '/scaffold' });
    const nav = await screen.findByRole('navigation', { name: 'Main' }, LAZY);
    expect(await screen.findByRole('heading', { name: 'You do not have access to this page' }, LAZY)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Scaffold things' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: /Scaffold things/ })).not.toBeInTheDocument();
    // Its count hook never ran: nothing asked the module's API.
    expect(calls.calls.some((c) => c.path.startsWith('/scaffold'))).toBe(false);
  });

  it('contributes nothing to another module, whatever its own rule says', async () => {
    const contribution = REGISTRY.extensions.find((c) => c.slot.id === 'alert.entity');
    expect(contribution?.when?.(analyst)).toBe(false);
    const session = await signedInSession(fakeApi(() => ({})).api, { role: 'analyst' });
    renderWithSession(<AlertEntities layout="stacked" entities={[['hosts', ['LT-1']]]} />, session);
    expect(screen.getByText('LT-1').nextElementSibling).toBeNull();
    expect(screen.queryByText(/Scaffold note/)).not.toBeInTheDocument();
  });

  it.todo('shows "not enabled for this tenant" instead of "no access" (ARCH-E10.2)');
});
