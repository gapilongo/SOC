import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext';
import type { Principal } from '../auth/store';
import { LoadingState } from './ui';

/** Render children only for a signed-in user; otherwise go to the sign-in page, remembering where we were. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();
  if (status === 'initializing') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas">
        <LoadingState label="Restoring your session" />
      </div>
    );
  }
  if (status !== 'authenticated') {
    const from = `${location.pathname}${location.search}`;
    return <Navigate to={status === 'expired' ? '/login?reason=expired' : '/login'} replace state={{ from }} />;
  }
  return <>{children}</>;
}

/** Route-level role gate mirroring the API (which enforces it regardless). */
export function RequireRole({ allowed, children }: { allowed: (p: Principal | null) => boolean; children: ReactNode }) {
  const { principal } = useAuth();
  if (!allowed(principal)) {
    return (
      <div className="py-16 text-center">
        <h1 className="text-lg font-semibold text-fg">You do not have access to this page</h1>
        <p className="mt-2 text-sm text-secondary">Your role ({principal?.role ?? 'none'}) does not include it. Ask a tenant admin if you need access.</p>
      </div>
    );
  }
  return <>{children}</>;
}
