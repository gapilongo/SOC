/**
 * The kernel's React Query hooks: who the caller is, and the polling rhythm
 * every module's read hooks share. A module's own hooks live in its API
 * slice (`src/modules/<id>/api/hooks.ts`).
 *
 * Polling is a fallback to the live stream: pass `refetchInterval` from
 * `useLivePollInterval`, which slows down while live events flow and stops
 * while the tab is hidden.
 */

import { useQuery } from '@tanstack/react-query';

import { useApi, useAuth } from '../auth/AuthContext';
import { usePollInterval } from '../lib/visibility';
import { useLive } from '../live/LiveProvider';
import { coreKeys } from './queryKeys';
import type { MeOut } from './types';

/** Poll every `liveMs` while the live stream is open, every `fallbackMs` otherwise; paused while the tab is hidden. */
export function useLivePollInterval(liveMs = 60_000, fallbackMs = 20_000): number | false {
  const { status } = useLive();
  return usePollInterval(status === 'open' ? liveMs : fallbackMs);
}

/** GET /auth/me for the tenant the caller acts on (cached five minutes; tenant_name on newer APIs). */
export function useMe() {
  const api = useApi();
  const { principal } = useAuth();
  const tenantId = principal?.tenantId ?? '';
  return useQuery({
    queryKey: coreKeys.me.forTenant(tenantId),
    queryFn: ({ signal }) => api.get<MeOut>('/auth/me', { signal }),
    enabled: Boolean(tenantId),
    staleTime: 5 * 60_000,
  });
}

/**
 * The current tenant's display name: `tenant_name` from GET /auth/me when the
 * API sends it, otherwise the tenant id.
 */
export function useTenantLabel(): string {
  const { principal } = useAuth();
  const tenantId = principal?.tenantId ?? '';
  const me = useMe();
  const name = me.data?.tenant_name;
  return typeof name === 'string' && name.trim() && me.data?.tenant_id === tenantId ? name.trim() : tenantId || '-';
}
