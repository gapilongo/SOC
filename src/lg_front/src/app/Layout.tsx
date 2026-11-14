import { X } from 'lucide-react';
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';

import { useTenantLabel } from '../api/hooks';
import { useAuth, useAuthStore } from '../auth/AuthContext';
import { logoutUrl } from '../auth/oidc';
import { ErrorBoundary, PageFallback } from '../components/ErrorBoundary';
import { SlotOutlet } from '../components/Slot';
import { LoadingState } from '../components/ui';
import { useFocusTrap } from '../components/useFocusTrap';
import { getBrand, getConfig } from '../config';
import { SHELL_BANNER } from '../core/slots';
import { NAV_GROUPS, REGISTRY, pageLabel } from './routes';
import { Rail } from './shell/Rail';
import { useSearchKeys, useSingleKeys } from './shell/searchKeys';
import { TopBar } from './shell/TopBar';

// Loaded when the search field first opens.
const CommandPalette = lazy(() => import('./shell/CommandPalette'));

/**
 * The app shell of console v2: the rail (a drawer below 861 px), the top bar
 * on every page (scope, search, live status, notifications, theme), the
 * modules' banners (the `shell.banner` slot: the acting-tenant banner) and
 * the page itself. Everything in it comes from the module registry. The page
 * has its own error boundary, reset on navigation, so a crash leaves the
 * shell (and sign-out) working.
 */
export function Layout() {
  const { principal } = useAuth();
  const store = useAuthStore();
  const location = useLocation();
  const tenantLabel = useTenantLabel();
  const [menuOpen, setMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [singleKeys, setSingleKeys] = useSingleKeys();
  const toggleSearch = useCallback(() => setSearchOpen((open) => !open), []);
  useSearchKeys(toggleSearch, searchOpen, singleKeys);

  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  // The menu of a narrow screen is modal: focus starts on its close button and Tab stays inside until it closes.
  // Where focus goes on close is decided below, not by the trap.
  useFocusTrap(menuRef, menuOpen, { restoreFocus: false, onEscape: () => setMenuOpen(false) });
  useEffect(() => {
    if (!menuOpen) return;
    const button = menuButtonRef.current;
    return () => {
      // Return focus to the menu button unless navigation already moved it to the page.
      const active = document.activeElement;
      if (!active || active === document.body || active.closest('#rail-drawer')) button?.focus();
    };
  }, [menuOpen]);

  const page = pageLabel(location.pathname);
  useEffect(() => {
    // The browser tab names the page, then the console (the brand's name).
    document.title = page ? `${page} · ${getBrand().name}` : getBrand().name;
  }, [page]);

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
  const onSignOut = () => void signOut();

  return (
    <div className="min-h-screen bg-canvas">
      <a
        href="#main"
        className="sr-only z-[70] rounded-control border border-strong bg-raised px-2.5 py-1.5 font-medium text-fg focus:not-sr-only focus:fixed focus:left-2 focus:top-2"
      >
        Skip to main content
      </a>
      <aside className="fixed inset-y-0 left-0 hidden w-[220px] border-r border-subtle bg-sidebar min-[861px]:block">
        <Rail groups={NAV_GROUPS} tenantLabel={tenantLabel} onSignOut={onSignOut} />
      </aside>

      {menuOpen && (
        <div className="fixed inset-0 z-[55] min-[861px]:hidden">
          <div className="absolute inset-0 bg-black/30" aria-hidden="true" onClick={() => setMenuOpen(false)} />
          <div
            ref={menuRef}
            className="absolute inset-y-0 left-0 w-[264px] max-w-[85vw] border-r border-subtle bg-sidebar shadow-popover"
            id="rail-drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Main menu"
          >
            <Rail groups={NAV_GROUPS} tenantLabel={tenantLabel} onNavigate={() => setMenuOpen(false)} onSignOut={onSignOut} />
            <button
              type="button"
              data-autofocus
              aria-label="Close the menu"
              onClick={() => setMenuOpen(false)}
              className="absolute right-2 top-[9px] grid h-[30px] w-[30px] place-items-center rounded-control text-secondary hover:bg-raised-2 hover:text-fg touch:h-11 touch:w-11"
            >
              <X className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
            </button>
          </div>
        </div>
      )}

      <div className="flex min-h-screen min-w-0 flex-col min-[861px]:pl-[220px]">
        <TopBar
          ref={menuButtonRef}
          registry={REGISTRY}
          tenantLabel={tenantLabel}
          menuOpen={menuOpen}
          onOpenMenu={() => setMenuOpen(true)}
          onSearch={() => setSearchOpen(true)}
        />
        <SlotOutlet slot={SHELL_BANNER} props={{}} />
        <main id="main" ref={mainRef} tabIndex={-1} className="w-full min-w-0 max-w-[1640px] flex-1 px-4 pb-10 pt-3.5 focus:outline-none min-[861px]:px-7 min-[861px]:pb-12 min-[861px]:pt-5">
          <ErrorBoundary resetKey={location.pathname} fallback={PageFallback}>
            <Suspense fallback={<LoadingState />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>

      {searchOpen && (
        <Suspense fallback={null}>
          <CommandPalette
            registry={REGISTRY}
            tenantLabel={tenantLabel}
            singleKeys={singleKeys}
            onSingleKeys={setSingleKeys}
            onClose={() => setSearchOpen(false)}
          />
        </Suspense>
      )}
    </div>
  );
}
