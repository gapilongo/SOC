import { QueryClientProvider, type QueryClient } from '@tanstack/react-query';
import { lazy, Suspense, useEffect } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import { SessionProvider, useAuth, useAuthStore } from '../auth/AuthContext';
import { bindQueryCacheToSession } from '../auth/cacheBinding';
import { CALLBACK_PATH } from '../auth/oidc';
import type { Session } from '../auth/session';
import { ErrorBoundary } from '../components/ErrorBoundary';
import { RequireAuth, RequireRole } from '../components/Guards';
import { ExtensionsProvider } from '../components/Slot';
import { ToastProvider } from '../components/Toast';
import { LoadingState } from '../components/ui';
import { LiveProvider } from '../live/LiveProvider';
import { DensityProvider } from '../theme/density';
import { ThemeProvider } from '../theme/theme';
import { Layout } from './Layout';
import { mayOpen } from './registry';
import { APP_ROUTES, BARE_ROUTES, REGISTRY, type AppRoute } from './routes';

// One chunk per route; the signed-in pages come from the registered modules (routes.tsx).
const LoginPage = lazy(() => import('../pages/Login'));
const OidcCallbackPage = lazy(() => import('../pages/OidcCallback'));
const NotFoundPage = lazy(() => import('../pages/NotFound'));

/** A module's page behind its gate: the tenant has the module and the role allows the page. */
function gated(route: AppRoute) {
  const { Page } = route;
  return (
    <RequireRole allowed={(p) => mayOpen(route, p)}>
      <Page />
    </RequireRole>
  );
}

/** Session lifecycle bound to the page: restore on load, refresh when the tab becomes visible. */
function SessionLifecycle() {
  const store = useAuthStore();
  const { status } = useAuth();
  useEffect(() => {
    // The OIDC callback completes its own sign-in; a parallel cookie refresh would race it.
    if (window.location.pathname !== CALLBACK_PATH) void store.init();
  }, [store]);
  useEffect(() => {
    if (status !== 'authenticated') return;
    const onVisible = () => {
      if (document.visibilityState === 'visible') void store.ensureFresh();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  }, [store, status]);
  return null;
}

export function AppRoutes() {
  return (
    <Suspense fallback={<LoadingState />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path={CALLBACK_PATH} element={<OidcCallbackPage />} />
        {/* Pages outside the app layout (the printable report, so only the report prints). */}
        {BARE_ROUTES.map((route) => (
          <Route key={route.path} path={route.path.slice(1)} element={<RequireAuth>{gated(route)}</RequireAuth>} />
        ))}
        <Route
          element={
            <RequireAuth>
              <LiveProvider keysFor={REGISTRY.liveKeys}>
                <Layout />
              </LiveProvider>
            </RequireAuth>
          }
        >
          {APP_ROUTES.map((route) =>
            route.path === '/' ? (
              <Route key={route.path} index element={gated(route)} />
            ) : (
              <Route key={route.path} path={route.path.slice(1)} element={gated(route)} />
            ),
          )}
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Suspense>
  );
}

export function App({ session, queryClient }: { session: Session; queryClient: QueryClient }) {
  // Cached data belongs to one identity: drop it when the session ends or changes hands.
  useEffect(() => bindQueryCacheToSession(session.auth, queryClient), [session.auth, queryClient]);
  return (
    <ErrorBoundary>
      <SessionProvider session={session}>
        <QueryClientProvider client={queryClient}>
          <ThemeProvider>
            <DensityProvider>
              <ToastProvider>
                <ExtensionsProvider contributions={REGISTRY.extensions}>
                  <BrowserRouter>
                    <SessionLifecycle />
                    <AppRoutes />
                  </BrowserRouter>
                </ExtensionsProvider>
              </ToastProvider>
            </DensityProvider>
          </ThemeProvider>
        </QueryClientProvider>
      </SessionProvider>
    </ErrorBoundary>
  );
}
