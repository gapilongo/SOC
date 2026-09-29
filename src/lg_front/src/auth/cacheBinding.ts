/**
 * Ties the React Query cache to the signed-in identity.
 *
 * Cached API data belongs to one principal acting on one tenant. Whenever
 * the session ends (expired, signed out, refused) or a refresh or sign-in
 * yields a different identity (another user, another home tenant, another
 * acting tenant), every cached query is dropped so the next person in this
 * tab never sees the previous one's alerts, escalations or admin data.
 *
 * The store notifies listeners synchronously, before React re-renders, so
 * the cache is empty by the time any page renders for the new identity.
 */

import type { QueryClient } from '@tanstack/react-query';

import type { AuthState, AuthStore } from './store';

/** Identity the cached data belongs to, or null when nobody is signed in. */
export function identityKey(state: AuthState): string | null {
  if (state.status !== 'authenticated' || !state.principal) return null;
  const p = state.principal;
  return JSON.stringify([p.userId, p.homeTenantId, p.tenantId, p.role, p.isPlatformAdmin]);
}

/** Clear `client` whenever the identity changes. Returns the unsubscribe function. */
export function bindQueryCacheToSession(store: Pick<AuthStore, 'getState' | 'subscribe'>, client: QueryClient): () => void {
  let current = identityKey(store.getState());
  return store.subscribe(() => {
    const next = identityKey(store.getState());
    if (next === current) return;
    current = next;
    forgetCachedData(client, next !== null);
  });
}

/**
 * Drop every cached result. `QueryClient.clear()` alone is not enough: a
 * mounted observer keeps rendering the data of a query removed from the
 * cache. Resetting first notifies observers (their data becomes undefined);
 * with a new identity the mounted queries then refetch for it.
 */
export function forgetCachedData(client: QueryClient, refetchMounted: boolean): void {
  const cache = client.getQueryCache();
  // Requests of the old identity must not land in the cache afterwards.
  for (const query of cache.getAll()) void query.cancel({ silent: true });
  if (refetchMounted) {
    void client.resetQueries();
    client.removeQueries({ type: 'inactive' });
  } else {
    for (const query of cache.getAll()) query.reset();
    client.removeQueries({ type: 'inactive' });
  }
  client.getMutationCache().clear();
}
