/**
 * Choosing the tenant to work in: shared by the scope control's picker and
 * the search field, both loaded on demand.
 */

import type { TenantRef } from '../../api/types';
import { useAuthStore } from '../../auth/AuthContext';
import { useToast } from '../../components/Toast';

/** Tenants whose id or name contains every word of `query` (case-insensitive), the home tenant first. */
export function filterTenants<T extends Pick<TenantRef, 'id' | 'name'>>(tenants: readonly T[], query: string, home: string): T[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return tenants
    .filter((t) => words.every((w) => t.id.includes(w) || t.name.toLowerCase().includes(w)))
    .sort((a, b) => Number(b.id === home) - Number(a.id === home) || a.name.localeCompare(b.name));
}

/** Work in `tenant` (null: back to the home tenant) and say what that means. The address follows the store. */
export function useChooseTenant(): (tenant: string | null, name?: string) => void {
  const store = useAuthStore();
  const toast = useToast();
  return (tenant, name) => {
    store.setActingTenant(tenant);
    toast.info(
      store.getState().actingTenant
        ? `Working in ${name ?? tenant}. Every request is recorded in that tenant's audit log.`
        : 'Back to your home tenant.',
    );
  };
}
