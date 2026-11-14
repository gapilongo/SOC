/**
 * The kernel's React Query keys. Every key starts with a namespace: `core`
 * here, a module's id in its API slice (`src/modules/<id>/api/queryKeys.ts`),
 * so invalidating one module's keys can never reach another's (ADR 0015).
 */

/** First element of every kernel key. */
export const CORE = 'core';

export const coreKeys = {
  /** The caller as the API sees it (GET /auth/me), per acting tenant. */
  me: {
    all: [CORE, 'me'] as const,
    forTenant: (tenantId: string) => [CORE, 'me', tenantId] as const,
  },
} as const;
