import { X } from 'lucide-react';
import { Suspense, useEffect, useRef, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';

import { useAuth, useAuthStore } from '../auth/AuthContext';
import { logoutUrl } from '../auth/oidc';
import { ErrorBoundary, PageFallback } from '../components/ErrorBoundary';
import { ActingTenantBanner } from '../modules/soc/pages/platform/TenantSwitcher';
import { Button, LoadingState } from '../components/ui';
import { useFocusTrap } from '../components/useFocusTrap';
import { getConfig } from '../config';
import { NAV_GROUPS, pageLabel } from './routes';
import { Header } from './shell/Header';
import { Sidebar } from './shell/Sidebar';

/**
 * The app shell: sidebar (a drawer on phones, below 768 px), one header on
 * every page, the acting-tenant banner and the page itself. The page has its
 * own error boundary, reset on navigation, so a crash leaves the shell (and
 * sign-out) working.
 */
export function Layout() {
  const { principal } = useAuth();
  const store = useAuthStore();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);

  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  // The phone menu is modal: focus starts on its close button and Tab stays inside until it closes.
  // Where focus goes on close is decided below, not by the trap.
  useFocusTrap(menuRef, menuOpen, { restoreFocus: false, onEscape: () => setMenuOpen(false) });
  useEffect(() => {
    if (!menuOpen) return;
    const button = menuButtonRef.current;
    return () => {
      // Return focus to the menu button unless navigation already moved it to the page.
      const active = document.activeElement;
      if (!active || active === document.body || active.closest('#mobile-nav')) button?.focus();
    };
  }, [menuOpen]);

  useEffect(() => {
    setMenuOpen(false);
    // Move focus to the new page's content on navigation (announced by screen readers).
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.focus();
  }, [location.pathname]);

  const signOut = async () => {
    const sso = principal?.method === 'oidc' ? getConfig().oidc : null;
    // Signing out also drops cached data (bindQueryCacheToSession in App).
    await store.logout();
    // End the identity provider session too, so the next sign-in asks again.
    const url = sso ? await logoutUrl(sso) : null;
    if (url) window.location.assign(url);
  };

  return (
    <div className="min-h-screen bg-canvas">
      <a
        href="#main"
        className="sr-only z-50 rounded-control bg-accent px-3 py-2 font-semibold text-on-accent focus:not-sr-only focus:fixed focus:left-2 focus:top-2"
      >
        Skip to main content
      </a>
      <aside className="fixed inset-y-0 left-0 hidden w-[232px] overflow-y-auto border-r border-subtle bg-sidebar md:block">
        <Sidebar groups={NAV_GROUPS} />
      </aside>

      {menuOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-black/60" aria-hidden="true" onClick={() => setMenuOpen(false)} />
          <div
            ref={menuRef}
            className="absolute inset-y-0 left-0 flex w-[min(18rem,85vw)] flex-col overflow-y-auto border-r border-subtle bg-sidebar"
            id="mobile-nav"
            role="dialog"
            aria-modal="true"
            aria-label="Main menu"
          >
            <div className="flex justify-end px-3 pt-3">
              <Button
                data-autofocus
                size="lg"
                aria-label="Close menu"
                onClick={() => setMenuOpen(false)}
                icon={<X className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />}
              />
            </div>
            <div className="flex-1">
              <Sidebar groups={NAV_GROUPS} onNavigate={() => setMenuOpen(false)} />
            </div>
          </div>
        </div>
      )}

      <div className="min-w-0 md:pl-[232px]">
        <Header ref={menuButtonRef} page={pageLabel(location.pathname)} menuOpen={menuOpen} onOpenMenu={() => setMenuOpen(true)} onSignOut={() => void signOut()} />
        <ActingTenantBanner />
        <main id="main" ref={mainRef} tabIndex={-1} className="mx-auto w-full max-w-[1600px] px-4 py-6 focus:outline-none md:px-6">
          <ErrorBoundary resetKey={location.pathname} fallback={PageFallback}>
            <Suspense fallback={<LoadingState />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
