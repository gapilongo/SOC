/**
 * The scope in the address.
 *
 * A platform admin who works in another tenant has that tenant in the
 * address: `/s/<tenant>/alerts`. A reload, a new tab and a shared link then
 * open the same tenant instead of falling back to the home tenant. Without
 * the prefix the address means the signed-in person's own tenant.
 *
 * Only "one tenant" exists today. "All tenants" and tenant groups
 * (`/s/all`, `/s/g/<group>`) need the API to answer for more than one tenant
 * (#377); `all` and `g` are not tenant ids, so those addresses stay free.
 */

/** A tenant id as the API issues it. */
export const TENANT_ID = /^[a-z0-9][a-z0-9_-]{1,62}$/;

const RESERVED = new Set(['all', 'g']);
const PREFIX = /^\/s\/([^/]+)(?=\/|$)/;

export interface AddressScope {
  /** The tenant the address names, or null for the signed-in person's own. */
  tenant: string | null;
  /** The part of the path that carries the scope: `/s/<tenant>`, or '' without one. The router's basename. */
  basename: string;
  /** The page's path inside the scope, starting with `/`. */
  path: string;
}

/** Split a pathname into its scope and the page's path. */
export function scopeOf(pathname: string): AddressScope {
  const m = PREFIX.exec(pathname);
  if (!m || !TENANT_ID.test(m[1]) || RESERVED.has(m[1])) return { tenant: null, basename: '', path: pathname || '/' };
  return { tenant: m[1], basename: m[0], path: pathname.slice(m[0].length) || '/' };
}

/** The address of `path` in `tenant` (null: the person's own tenant, no prefix). */
export function scopedPath(tenant: string | null, path: string): string {
  return tenant ? `/s/${tenant}${path === '/' ? '' : path}` : path;
}

/**
 * Where a page leads when the tenant changes: a record belongs to one tenant, so its page gives
 * way to the list it came from (`/alerts/a-1` becomes `/alerts`); a list stays.
 */
export function listPath(path: string): string {
  const first = path.split('/')[1];
  return first ? `/${first}` : '/';
}
