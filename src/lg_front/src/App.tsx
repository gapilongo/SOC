import { QueryClientProvider, type QueryClient } from '@tanstack/react-query';
import { lazy, Suspense, useEffect } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import { SessionProvider, useAuth, useAuthStore } from './auth/AuthContext';
import { bindQueryCacheToSession } from './auth/cacheBinding';
import { CALLBACK_PATH } from './auth/oidc';
import { can } from './auth/roles';
import type { Session } from './auth/session';
import { ErrorBoundary } from './components/ErrorBoundary';
import { RequireAuth, RequireRole } from './components/Guards';
import { Layout } from './components/Layout';
import { ToastProvider } from './components/Toast';
import { LoadingState } from './components/ui';
import { LiveProvider } from './live/LiveProvider';

// One chunk per route.
const LoginPage = lazy(() => import('./pages/Login'));
const OidcCallbackPage = lazy(() => import('./pages/OidcCallback'));
const DashboardPage = lazy(() => import('./pages/Dashboard'));
const AlertsPage = lazy(() => import('./pages/alerts/AlertsPage'));
const EscalationsPage = lazy(() => import('./pages/escalations/EscalationsPage'));
const ActionsPage = lazy(() => import('./pages/ActionsPage'));
const SuppressionsPage = lazy(() => import('./pages/SuppressionsPage'));
const SourcesPage = lazy(() => import('./pages/SourcesPage'));
const IntegrationsPage = lazy(() => import('./pages/IntegrationsPage'));
const UsersPage = lazy(() => import('./pages/UsersPage'));
const TenantSettingsPage = lazy(() => import('./pages/TenantSettingsPage'));
const UsagePage = lazy(() => import('./pages/UsagePage'));
const AuditPage = lazy(() => import('./pages/AuditPage'));
const PlatformPage = lazy(() => import('./pages/PlatformPage'));
const NotFoundPage = lazy(() => import('./pages/NotFound'));

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
        <Route
          element={
            <RequireAuth>
              <LiveProvider>
                <Layout />
              </LiveProvider>
            </RequireAuth>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="escalations" element={<EscalationsPage />} />
          <Route path="actions" element={<ActionsPage />} />
          <Route path="suppressions" element={<SuppressionsPage />} />
          <Route path="sources" element={<RequireRole allowed={can.admin}><SourcesPage /></RequireRole>} />
          <Route path="integrations" element={<RequireRole allowed={can.admin}><IntegrationsPage /></RequireRole>} />
          <Route path="users" element={<RequireRole allowed={can.admin}><UsersPage /></RequireRole>} />
          <Route path="settings" element={<RequireRole allowed={can.admin}><TenantSettingsPage /></RequireRole>} />
          <Route path="usage" element={<RequireRole allowed={can.admin}><UsagePage /></RequireRole>} />
          <Route path="audit" element={<RequireRole allowed={can.admin}><AuditPage /></RequireRole>} />
          <Route path="platform" element={<RequireRole allowed={can.platform}><PlatformPage /></RequireRole>} />
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
          <ToastProvider>
            <BrowserRouter>
              <SessionLifecycle />
              <AppRoutes />
            </BrowserRouter>
          </ToastProvider>
        </QueryClientProvider>
      </SessionProvider>
    </ErrorBoundary>
  );
}
