import { describe, expect, it } from 'vitest';

import { can } from './auth/roles';
import { APP_ROUTES, NAV_GROUPS, pageLabel } from './routes';

describe('route table', () => {
  it('declares each path once', () => {
    const paths = APP_ROUTES.map((r) => r.path);
    expect(new Set(paths).size).toBe(paths.length);
    for (const path of paths) expect(path).toMatch(/^\//);
  });

  it('builds the sidebar from the routes with a nav entry, gated like the route', () => {
    const items = NAV_GROUPS.flatMap((g) => g.items);
    const withNav = APP_ROUTES.filter((r) => r.nav);
    expect(items.map((i) => i.to)).toEqual(expect.arrayContaining(withNav.map((r) => r.path)));
    expect(items).toHaveLength(withNav.length);
    for (const item of items) expect(item.allowed).toBe(APP_ROUTES.find((r) => r.path === item.to)?.allowed);
    expect(NAV_GROUPS.map((g) => g.title)).toEqual(['Operate', 'Report', 'Configure', 'Platform']);
  });

  it('gates account security with can.account', () => {
    expect(APP_ROUTES.find((r) => r.path === '/account')?.allowed).toBe(can.account);
  });

  it('names pages for the breadcrumb', () => {
    expect(pageLabel('/')).toBe('Overview');
    expect(pageLabel('/approvals')).toBe('Approvals');
    expect(pageLabel('/escalations/esc-1')).toBe('Escalations');
    expect(pageLabel('/reports/x')).toBe('Reports');
    expect(pageLabel('/account')).toBe('Account security');
    expect(pageLabel('/actions')).toBeNull();
    expect(pageLabel('/nowhere')).toBeNull();
  });
});
