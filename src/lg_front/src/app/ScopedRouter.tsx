/**
 * The router, with the scope as part of the address (lib/scope.ts).
 *
 * `/s/<tenant>` in front of a page's path is the router's basename, so every
 * link and navigation of every page carries it without knowing: a platform
 * admin who works in `globex` is at `/s/globex/alerts`, and a reload, a new
 * tab or a pasted link opens the same tenant.
 *
 * - A session that starts takes its tenant from the address (auth/store.ts).
 * - When the tenant changes in the app (the scope control, the MSSP console,
 *   "Return to ..."), the address follows: a record's page gives way to its
 *   list, because a record belongs to one tenant.
 * - When the address changes (Back and Forward across a change of tenant, a
 *   link to a scoped address), the tenant follows.
 * - Someone who is not a platform admin has one tenant. An address that
 *   names another one is refused in words; their own tenant is never shown
 *   under another tenant's address.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { BrowserRouter, useLocation } from 'react-router-dom';

import { useAuth, useAuthStore } from '../auth/AuthContext';
import { listPath, scopedPath, scopeOf } from '../lib/scope';

/** Inside the router: tells the scope when a navigation leads to a scoped address the basename does not carry yet. */
function AddressWatch({ onScoped }: { onScoped: () => void }) {
  const { pathname } = useLocation();
  useEffect(() => {
    if (scopeOf(pathname).tenant) onScoped();
  }, [pathname, onScoped]);
  return null;
}

function OtherTenant({ wanted, own }: { wanted: string; own: string }) {
  return (
    <main className="mx-auto max-w-xl px-4 py-24 text-center">
      <h1 className="text-lg font-semibold text-fg">This address is for another tenant</h1>
      <p className="mt-2 text-sm text-secondary">
        It names the tenant <span className="font-mono">{wanted}</span>. You are signed in to <span className="font-mono">{own}</span> and cannot open another
        tenant, so nothing is shown under this address.
      </p>
      <p className="mt-4 text-sm">
        <a href="/" className="font-medium text-link underline underline-offset-2 hover:text-link-hover">
          Open {own}
        </a>
      </p>
    </main>
  );
}

export function ScopedRouter({ children }: { children: ReactNode }) {
  const store = useAuthStore();
  const { status, principal, actingTenant } = useAuth();
  const [scope, setScope] = useState(() => scopeOf(window.location.pathname));

  // The address changed: the tenant follows it (for a platform admin), and the router takes the new basename.
  const adopt = useCallback(() => {
    const next = scopeOf(window.location.pathname);
    const p = store.getState().principal;
    if (p?.isPlatformAdmin && (next.tenant ?? p.homeTenantId) !== p.tenantId) store.setActingTenant(next.tenant);
    setScope((current) => (current.basename === next.basename ? current : next));
  }, [store]);

  useEffect(() => {
    window.addEventListener('popstate', adopt);
    return () => window.removeEventListener('popstate', adopt);
  }, [adopt]);

  // The tenant changed in the app: the address follows it.
  useEffect(() => {
    if (status !== 'authenticated' || !principal?.isPlatformAdmin) return;
    const here = scopeOf(window.location.pathname);
    if ((here.tenant ?? principal.homeTenantId) === principal.tenantId) return;
    window.history.pushState(null, '', scopedPath(actingTenant, listPath(here.path)));
    setScope(scopeOf(window.location.pathname));
  }, [status, principal, actingTenant]);

  const refused = status === 'authenticated' && principal && !principal.isPlatformAdmin && scope.tenant && scope.tenant !== principal.tenantId;

  return (
    <BrowserRouter key={scope.basename} basename={scope.basename}>
      <AddressWatch onScoped={adopt} />
      {refused ? <OtherTenant wanted={scope.tenant as string} own={principal.tenantId} /> : children}
    </BrowserRouter>
  );
}
