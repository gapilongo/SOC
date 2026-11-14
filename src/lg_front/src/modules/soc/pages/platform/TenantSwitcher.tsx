/**
 * Tenant context for platform admins: the tenant list of the MSSP console,
 * switching to a tenant from it, and the "acting as tenant" banner. The
 * tenant picker itself is the shell's scope control (app/shell/ScopeControl).
 *
 * Switching sets the store's acting tenant: requests then carry
 * `X-Tenant-ID` (each one is recorded in that tenant's audit log), live
 * updates stay off, cached data of the previous tenant is dropped
 * (bindQueryCacheToSession) and the address gains `/s/<tenant>`
 * (app/ScopedRouter). The tenant list comes from `/platform/tenants` (never
 * sent with the override).
 */

import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, LogOut } from 'lucide-react';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import type { TenantSummaryOut } from '../../api/types';
import { useApi, useAuth, useAuthStore } from '../../../../auth/AuthContext';
import { isTenantOverride } from '../../../../auth/roles';
import { useToast } from '../../../../components/Toast';
import { Button } from '../../../../components/ui';

/** Options a caller of {@link usePlatformTenants} may set; anything left out keeps the client default. */
export interface PlatformTenantsOptions {
  refetchInterval?: number | false;
  staleTime?: number;
  enabled?: boolean;
}

/**
 * Every tenant (platform admins). One query shared by the tenant switcher and
 * the platform page; each caller states its own freshness options.
 */
export function usePlatformTenants(options: PlatformTenantsOptions = {}) {
  const api = useApi();
  // Only the options a caller set: an explicit undefined would override the client defaults.
  const set = Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined)) as PlatformTenantsOptions;
  return useQuery({
    queryKey: qk.platformTenants.all,
    queryFn: ({ signal }) => endpoints.platformTenants(api, signal),
    ...set,
  });
}

/** Tenants whose id or name contains every word of `query` (case-insensitive), home tenant first. */
export function filterTenants(tenants: readonly TenantSummaryOut[], query: string, home: string): TenantSummaryOut[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return tenants
    .filter((t) => words.every((w) => t.id.includes(w) || t.name.toLowerCase().includes(w)))
    .sort((a, b) => Number(b.id === home) - Number(a.id === home) || a.name.localeCompare(b.name));
}

/** Switch the acting tenant and say what that means; returns false when the store refused. */
export function useSwitchTenant(): (tenant: string | null, name?: string) => boolean {
  const store = useAuthStore();
  const toast = useToast();
  return (tenant, name) => {
    try {
      // Cached data of the previous tenant is dropped by bindQueryCacheToSession (App).
      store.setActingTenant(tenant);
      const home = store.getState().principal?.homeTenantId;
      toast.info(
        tenant && tenant !== home
          ? `Acting as tenant ${name ?? tenant}. Every request is recorded in that tenant's audit log.`
          : 'Back to your home tenant.',
      );
      return true;
    } catch (err) {
      toast.error(err);
      return false;
    }
  };
}

/** Shown on every page while a platform admin acts on another tenant. */
export function ActingTenantBanner() {
  const { principal } = useAuth();
  const switchTo = useSwitchTenant();
  if (!principal || !isTenantOverride(principal)) return null;
  return (
    <div role="status" className="flex flex-wrap items-center gap-3 border-b border-warn/60 bg-tint-warn px-4 py-1.5 text-ctl font-medium text-fg md:px-6">
      <AlertTriangle className="h-4 w-4 flex-none text-warn-fg" strokeWidth={1.75} aria-hidden="true" />
      <span className="min-w-0 flex-1">
        Acting as tenant <strong className="font-semibold">{principal.tenantId}</strong>. Every request is recorded in that tenant&apos;s
        audit log; live updates are off.
      </span>
      <Button size="sm" onClick={() => switchTo(null)} icon={<LogOut className="h-3.5 w-3.5" aria-hidden="true" />}>
        Return to {principal.homeTenantId}
      </Button>
    </div>
  );
}
