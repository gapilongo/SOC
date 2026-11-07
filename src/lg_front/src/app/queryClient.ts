import { QueryClient } from '@tanstack/react-query';

import { ApiError } from '../api/client';

/** Retry only transient failures (network, 5xx, 429); never 4xx answers. */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) return false;
  if (error instanceof ApiError) return error.status === 0 || error.status === 429 || error.status >= 500;
  return false;
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        staleTime: 10_000,
        refetchOnWindowFocus: true,
        // Interval polling stops while the tab is hidden.
        refetchIntervalInBackground: false,
      },
      mutations: { retry: false },
    },
  });
}
