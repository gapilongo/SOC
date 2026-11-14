/**
 * The acceptance test of the module model (ADR 0015, ARCH-E10.1): a new
 * service is its folder and one registry line.
 *
 * The folder is src/test/scaffold-module (one page, a nav group with a
 * counted item, a query-key namespace, a live event, a contribution to the
 * SOC's `alert.entity` slot). The one line is the mock below, which adds its
 * manifest to MODULES in src/app/modules.ts. Nothing else is touched: the
 * real App, sidebar, guards, registry and SOC components run unchanged and
 * must pick the module up.
 */
import { screen, within } from '@testing-library/react';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { soc } from '../modules/soc';
import { AlertEntities } from '../modules/soc/components/AlertEntities';
import { qk } from '../modules/soc/api/queryKeys';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import { scaffold } from '../test/scaffold-module';
import { AppRoutes } from './App';
import { MODULES } from './modules';
import type * as ModulesFile from './modules';
import { buildRegistry } from './registry';
import { APP_ROUTES, NAV_GROUPS, REGISTRY, pageLabel } from './routes';
import { navFor } from './shell/nav';

vi.mock('./modules', async (importOriginal) => {
  const real = await importOriginal<typeof ModulesFile>();
  const { scaffold: added } = await import('../test/scaffold-module');
  // The one registry line a new service adds.
  return { ...real, MODULES: [...real.MODULES, added] };
});

const DENIED = 'You do not have access to this page';

/** Lazy chunks (the page, the contribution) are imported and transformed on first use: allow for a busy runner. */
const LAZY = { timeout: 10_000 };

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

/** The scaffold's own endpoint answers; every other request stays pending (only the shell matters here). */
function api(count = 2) {
  return fakeApi((_method, p) => (p === '/scaffold/things/count' ? { count } : new Promise(() => undefined)));
}

async function open(route: string, role: string) {
  stubWebSocket();
  const session = await signedInSession(api().api, { role });
  renderWithSession(<AppRoutes />, session, { route });
  return screen.findByRole('navigation', { name: 'Main' }, LAZY);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('a module is its folder and one registry line', () => {
  const socOnly = buildRegistry([soc]);

  it('is registered by the one line, after the SOC', () => {
    expect(MODULES.map((m) => m.id)).toEqual(['soc', 'scaffold']);
    expect(REGISTRY.modules).toBe(MODULES);
  });

  it('adds its route to the route table and leaves the SOC routes as they were', () => {
    expect(APP_ROUTES.map((r) => r.path)).toEqual([...socOnly.routes.map((r) => r.path), '/scaffold']);
    const route = APP_ROUTES.find((r) => r.path === '/scaffold');
    expect(route?.module).toBe('scaffold');
    expect(route?.allowed).toBe(scaffold.routes[0].allowed);
    expect(pageLabel('/scaffold')).toBe('Scaffold things');
    expect(pageLabel('/scaffold/42')).toBe('Scaffold things');
  });

  it('adds its nav group in order, gated like its route', () => {
    expect(NAV_GROUPS.map((g) => g.title)).toEqual(['Operate', 'Scaffold', 'Report', 'Configure', 'Platform']);
    const principal = (role: string) => ({ userId: 'u-1', email: 'x@acme.test', role, tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: false, method: 'password' as const });
    const groups = (role: string) => navFor(NAV_GROUPS, principal(role)).map((g) => g.title);
    expect(groups('analyst')).toEqual(['Operate', 'Scaffold', 'Report']);
    expect(groups('viewer')).toEqual(['Operate', 'Report']);
  });

  it('renders its page inside the shell, with its nav item, count and breadcrumb', async () => {
    const nav = await open('/scaffold', 'analyst');
    expect(await screen.findByRole('heading', { name: 'Scaffold things', level: 1 }, LAZY)).toBeInTheDocument();
    expect(await screen.findByText('2 waiting.', undefined, LAZY)).toBeInTheDocument();
    // The sidebar: its own group, the item current, the module's count with its meaning.
    const group = within(nav).getByRole('list', { name: 'Scaffold' });
    const link = await within(group).findByRole('link', { name: 'Scaffold things 2 things waiting' }, LAZY);
    expect(link).toHaveAttribute('href', '/scaffold');
    expect(link).toHaveAttribute('aria-current', 'page');
    // The SOC's nav is still there, untouched.
    expect(within(nav).getByRole('link', { name: 'Escalations' })).toHaveAttribute('href', '/escalations');
    expect(screen.getByRole('navigation', { name: 'Breadcrumb' })).toHaveTextContent('Scaffold things');
    expect(screen.queryByRole('heading', { name: DENIED })).not.toBeInTheDocument();
  });

  it('is guarded by its own access rule: a viewer gets neither the page nor the nav item', async () => {
    const nav = await open('/scaffold', 'viewer');
    expect(await screen.findByRole('heading', { name: DENIED }, LAZY)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Scaffold things' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: /Scaffold things/ })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('list', { name: 'Scaffold' })).not.toBeInTheDocument();
  });

  it('maps its live event to its own query keys, beside the SOC events', () => {
    expect(REGISTRY.liveKeys('scaffold.updated')).toEqual([['scaffold', 'things']]);
    expect(REGISTRY.liveKeys('alert.created')).toEqual([qk.alerts.all, qk.alert.all, qk.dashboard.all]);
    expect(REGISTRY.liveKeys('unknown.kind')).toEqual([]);
  });

  it('shows its contribution in the SOC entity list, without a change to the SOC', async () => {
    const session = await signedInSession(api().api, { role: 'analyst' });
    renderWithSession(<AlertEntities layout="stacked" entities={[['hosts', ['LT-1']], ['users', ['j.doe']]]} />, session);
    const note = await screen.findByText('Scaffold note for LT-1', undefined, LAZY);
    expect(note.previousElementSibling).toHaveTextContent('LT-1');
    expect(screen.getByText('j.doe').nextElementSibling).toBeNull();
    // Without the module the same list shows the entities alone (the SOC's own tests cover it).
    expect(socOnly.extensions.some((c) => c.slot.id === 'alert.entity')).toBe(false);
  });
});

describe('the registry refuses a manifest that cannot work', () => {
  const route = scaffold.routes[0];

  it.each([
    ['a module registered twice', [soc, soc], /registered twice/],
    ['a path two modules declare', [soc, { ...scaffold, routes: [{ ...route, path: '/alerts', nav: undefined }] }], /"\/alerts" is declared by both "soc" and "scaffold"/],
    ['a nav group nobody declares', [{ ...scaffold, navGroups: [] }], /nav group "scaffold", which no module declares/],
    ['a path that is not absolute', [{ ...scaffold, routes: [{ ...route, path: 'scaffold' }] }], /must start with "\/"/],
    ['a nav entry outside the shell', [{ ...scaffold, routes: [{ ...route, shell: false }] }], /outside the shell/],
    ['an id that is not a folder name', [{ ...scaffold, id: 'Scaffold Module' }], /is not a module id/],
    ['the kernel namespace as an id', [{ ...scaffold, id: 'core' }], /kernel's query-key namespace/],
    ['a live event on another module\'s keys', [soc, { ...scaffold, liveEvents: { 'scaffold.updated': [qk.alerts.all] } }], /not the module's own/],
  ])('%s', (_name, modules, message) => {
    expect(() => buildRegistry(modules)).toThrow(message);
  });

  it('lets a module add items to a group another module declared', () => {
    const registry = buildRegistry([soc, { ...scaffold, navGroups: [], routes: [{ ...route, nav: { ...route.nav!, group: 'operate' } }] }]);
    const operate = registry.navGroups.find((g) => g.id === 'operate');
    expect(operate?.items.at(-1)?.label).toBe('Scaffold things');
    expect(registry.navGroups.map((g) => g.title)).toEqual(['Operate', 'Report', 'Configure', 'Platform']);
  });
});

describe('the scaffold folder obeys the module boundary', () => {
  it('lints clean when it sits in src/modules', async () => {
    // Same depth as src/modules/<id>, so its relative imports resolve identically there.
    const { ESLint } = await import('eslint');
    const root = path.resolve(__dirname, '../..');
    const folder = path.join(root, 'src/test/scaffold-module');
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name);
        if (statSync(full).isDirectory()) walk(full);
        else files.push(full);
      }
    };
    walk(folder);
    expect(files.length).toBeGreaterThanOrEqual(5);
    const eslint = new ESLint({ cwd: root });
    for (const file of files) {
      const as = path.join(root, 'src/modules/scaffold', path.relative(folder, file));
      const [result] = await eslint.lintText(readFileSync(file, 'utf8'), { filePath: as });
      expect(result.messages.map((m) => `${m.ruleId}: ${m.message}`), path.relative(root, as)).toEqual([]);
    }
  }, 60_000);
});
