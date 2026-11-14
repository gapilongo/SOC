/**
 * The scope control at the left of the top bar: the tenant the pages show.
 *
 * Today a scope is one tenant. Everyone sees which; a platform admin can
 * choose another, and the choice becomes part of the address
 * (`/s/<tenant>/...`, app/ScopedRouter.tsx), so a reload, a new tab and a
 * shared link keep it. "All tenants" and tenant groups are listed here once
 * the API offers them (#377), never as options that do nothing.
 *
 * Choosing a tenant sets the store's acting tenant: requests then carry
 * `X-Tenant-ID` (each one is recorded in that tenant's audit log), live
 * updates stay off, and cached data of the previous tenant is dropped
 * (bindQueryCacheToSession). The list comes from `GET /platform/tenants`
 * and is asked for when the control opens (TenantPicker.tsx).
 */

import { Building2 } from 'lucide-react';
import { lazy, Suspense } from 'react';

import { useAuth } from '../../auth/AuthContext';

// The picker is for platform admins only: everyone else never downloads it.
const TenantPicker = lazy(() => import('./TenantPicker'));

export const BOX =
  'inline-flex h-ctl min-w-0 max-w-[150px] items-center gap-1.5 rounded-control border border-control bg-raised px-2 text-ctl font-medium text-fg min-[861px]:max-w-[260px] touch:min-h-11';

export function Current({ label }: { label: string }) {
  return (
    <>
      <Building2 className="h-4 w-4 flex-none" strokeWidth={1.5} aria-hidden="true" />
      <span className="sr-only font-mono text-2xs uppercase leading-none tracking-label text-muted min-[861px]:not-sr-only">Tenant</span>
      <span className="truncate" data-testid="tenant-name">
        {label}
      </span>
    </>
  );
}

/** `label`: the current tenant's display name. */
export function ScopeControl({ label }: { label: string }) {
  const { principal } = useAuth();
  const plain = (
    <span className={BOX}>
      <Current label={label} />
    </span>
  );
  // Someone with one tenant has nothing to choose: the control says where they are.
  if (!principal?.isPlatformAdmin) return plain;
  // The plain name also stands in for the moment the picker takes to load.
  return (
    <Suspense fallback={plain}>
      <TenantPicker principal={principal} label={label} />
    </Suspense>
  );
}
