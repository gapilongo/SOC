import type { ApiClient } from '../api/client';
import type { LoginOut, MeOut, MfaConfirmOut, MfaEnrollOut, TokenOut } from '../modules/soc/api/types';
import type { AuthTransport } from './store';

/** Auth endpoints. They bypass the client's refresh-on-401 (anonymous) to avoid recursion. */
export function createAuthTransport(api: ApiClient): AuthTransport {
  return {
    login: (email, password, tenant) =>
      api.post<LoginOut>(
        '/auth/login',
        { email, password, ...(tenant ? { tenant } : {}) },
        { anonymous: true, credentials: 'include' },
      ),
    verifyMfa: (mfaToken, code) =>
      api.post<TokenOut>('/auth/mfa/verify', { mfa_token: mfaToken, code }, { anonymous: true, credentials: 'include' }),
    enrollMfa: (mfaToken) => api.post<MfaEnrollOut>('/auth/mfa/enroll', { mfa_token: mfaToken }, { anonymous: true }),
    confirmMfa: (mfaToken, code) =>
      api.post<MfaConfirmOut>('/auth/mfa/confirm', { mfa_token: mfaToken, code }, { anonymous: true, credentials: 'include' }),
    refresh: () => api.post<TokenOut>('/auth/refresh', undefined, { anonymous: true, credentials: 'include' }),
    logout: async (token) => {
      await api.post<void>('/auth/logout', undefined, {
        anonymous: true,
        credentials: 'include',
        // A navigation right after sign-out must not abort the revocation.
        keepalive: true,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
    },
    me: (token) => api.get<MeOut>('/auth/me', { anonymous: true, headers: { Authorization: `Bearer ${token}` } }),
  };
}
