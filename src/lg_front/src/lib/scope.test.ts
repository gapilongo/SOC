import { describe, expect, it } from 'vitest';

import { listPath, scopedPath, scopeOf, TENANT_ID } from './scope';

describe('the scope in the address', () => {
  it('reads the tenant in front of the page path', () => {
    expect(scopeOf('/s/globex/alerts/a-1')).toEqual({ tenant: 'globex', basename: '/s/globex', path: '/alerts/a-1' });
    expect(scopeOf('/s/globex')).toEqual({ tenant: 'globex', basename: '/s/globex', path: '/' });
    expect(scopeOf('/s/globex/')).toEqual({ tenant: 'globex', basename: '/s/globex', path: '/' });
    expect(scopeOf('/s/northwind-logistics/escalations')).toMatchObject({ tenant: 'northwind-logistics', path: '/escalations' });
  });

  it("means the person's own tenant without the prefix", () => {
    expect(scopeOf('/alerts')).toEqual({ tenant: null, basename: '', path: '/alerts' });
    expect(scopeOf('/')).toEqual({ tenant: null, basename: '', path: '/' });
    expect(scopeOf('')).toEqual({ tenant: null, basename: '', path: '/' });
    // A page whose path merely starts like the prefix.
    expect(scopeOf('/sources')).toMatchObject({ tenant: null, path: '/sources' });
    expect(scopeOf('/setup')).toMatchObject({ tenant: null });
  });

  it('takes only a tenant id for a tenant, and keeps "all" and "g" for the scopes to come', () => {
    expect(TENANT_ID.test('globex')).toBe(true);
    expect(TENANT_ID.test('Globex')).toBe(false);
    expect(scopeOf('/s/Not%20A%20Tenant/alerts')).toMatchObject({ tenant: null, basename: '' });
    expect(scopeOf('/s/x/alerts')).toMatchObject({ tenant: null });
    expect(scopeOf('/s/all/queue')).toMatchObject({ tenant: null, basename: '', path: '/s/all/queue' });
    expect(scopeOf('/s/g/contract-247/queue')).toMatchObject({ tenant: null });
  });

  it('writes the address of a page in a tenant', () => {
    expect(scopedPath('globex', '/alerts')).toBe('/s/globex/alerts');
    expect(scopedPath('globex', '/')).toBe('/s/globex');
    expect(scopedPath(null, '/alerts')).toBe('/alerts');
    expect(scopedPath(null, '/')).toBe('/');
    expect(scopeOf(scopedPath('globex', '/alerts')).path).toBe('/alerts');
  });

  it('leads from a record to its list when the tenant changes', () => {
    expect(listPath('/alerts/a-1')).toBe('/alerts');
    expect(listPath('/escalations/e-1')).toBe('/escalations');
    expect(listPath('/reports/monthly/2026-10')).toBe('/reports');
    expect(listPath('/alerts')).toBe('/alerts');
    expect(listPath('/')).toBe('/');
  });
});
