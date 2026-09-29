/**
 * Application singletons: the auth store and the API client wired to it.
 */

import { createApiClient, type ApiClient } from '../api/client';
import { apiRoot, getConfig } from '../config';
import { refreshOidc } from './oidc';
import { AuthStore } from './store';
import { createAuthTransport } from './transport';

export interface Session {
  auth: AuthStore;
  api: ApiClient;
}

export function createSession(fetchImpl?: typeof fetch): Session {
  const config = getConfig();
  // The store and the client reference each other: the client asks the store
  // for tokens and refreshes; the store's transport uses an anonymous client.
  let store: AuthStore | null = null;
  const api = createApiClient({
    baseUrl: apiRoot(config),
    fetchImpl,
    auth: {
      getToken: () => store?.getToken() ?? null,
      refresh: () => store?.refresh() ?? Promise.resolve(null),
      actingTenant: () => store?.getActingTenant() ?? null,
    },
  });
  const oidc = config.oidc;
  store = new AuthStore({
    transport: createAuthTransport(api),
    oidc: oidc ? { refresh: (rt) => refreshOidc(oidc, rt, fetchImpl) } : null,
  });
  return { auth: store, api };
}
