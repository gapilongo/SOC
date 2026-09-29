import type { ApiClient } from '../api/client';
import type { MeOut, TokenOut } from '../api/types';
import type { AuthTransport } from './store';

/** Auth endpoints. They bypass the client's refresh-on-401 (anonymous) to avoid recursion. */
export function createAuthTransport(api: ApiClient): AuthTransport {
  return {
    login: (email, password, tenant) =>
      api.post<TokenOut>(
        '/auth/login',
        { email, password, ...(tenant ? { tenant } : {}) },
        { anonymous: true, credentials: 'include' },
      ),
    refresh: () => api.post<TokenOut>('/auth/refresh', undefined, { anonymous: true, credentials: 'include' }),
    logout: async (token) => {
      await api.post<void>('/auth/logout', undefined, {
        anonymous: true,
        credentials: 'include',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
    },
    me: (token) => api.get<MeOut>('/auth/me', { anonymous: true, headers: { Authorization: `Bearer ${token}` } }),
  };
}
