import {
  type LucideIcon,
  Activity,
  BarChart3,
  Bell,
  Building2,
  ClipboardCheck,
  FileClock,
  FileText,
  Filter,
  Gauge,
  KeyRound,
  Lock,
  LogOut,
  Menu,
  Plug,
  Rocket,
  Send,
  Settings,
  ShieldAlert,
  X,
} from 'lucide-react';
import { Suspense, useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';

import { useAuth, useAuthStore } from '../auth/AuthContext';
import { logoutUrl } from '../auth/oidc';
import { can, isTenantOverride } from '../auth/roles';
import { getConfig } from '../config';
import type { Principal } from '../auth/store';
import { useLive } from '../live/LiveProvider';
import { ActingTenantBanner, TenantSwitcher } from './TenantSwitcher';
import { Button, DensityToggle, LoadingState, ThemeSwitch, cx } from './ui';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  allowed: (p: Principal | null) => boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: Gauge, allowed: can.view },
  { to: '/getting-started', label: 'Getting started', icon: Rocket, allowed: can.admin },
  { to: '/alerts', label: 'Alerts', icon: Bell, allowed: can.view },
  { to: '/escalations', label: 'Escalations', icon: ShieldAlert, allowed: can.view },
  { to: '/actions', label: 'Actions and approvals', icon: ClipboardCheck, allowed: can.view },
  { to: '/suppressions', label: 'Suppressions', icon: Filter, allowed: can.view },
  { to: '/reports', label: 'Reports', icon: FileText, allowed: can.view },
  { to: '/sources', label: 'Sources', icon: Plug, allowed: can.admin },
  { to: '/integrations', label: 'Integrations', icon: Send, allowed: can.admin },
  { to: '/users', label: 'Users and API keys', icon: KeyRound, allowed: can.admin },
  { to: '/settings', label: 'Tenant settings', icon: Settings, allowed: can.admin },
  { to: '/usage', label: 'LLM usage', icon: BarChart3, allowed: can.admin },
  { to: '/audit', label: 'Audit log', icon: FileClock, allowed: can.admin },
  { to: '/platform', label: 'MSSP console', icon: Building2, allowed: can.platform },
  // Your own account: not while acting on another tenant.
  { to: '/account', label: 'Account security', icon: Lock, allowed: (p) => can.view(p) && !isTenantOverride(p) },
];

function LiveIndicator() {
  const { status } = useLive();
  const { actingTenant } = useAuth();
  const label =
    actingTenant ? 'Live updates off (acting on another tenant)' :
    status === 'open' ? 'Live' :
    status === 'reconnecting' ? 'Reconnecting' :
    status === 'unavailable' ? 'Live updates unavailable' :
    status === 'connecting' ? 'Connecting' : 'Offline';
  const color =
    status === 'open' && !actingTenant ? 'bg-state-ok' :
    status === 'reconnecting' || status === 'connecting' ? 'bg-state-waiting' :
    status === 'unavailable' && !actingTenant ? 'bg-state-bad' : 'bg-muted';
  const hint =
    status === 'unavailable' && !actingTenant
      ? 'The live event stream could not be opened after several attempts; pages still refresh periodically. ' +
        "If this persists, an administrator should check that this site's origin is listed in the API setting api.cors_origins " +
        'and that the proxy in front of the API allows WebSocket upgrades on /api/v1/ws.'
      : undefined;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-secondary" role="status" aria-live="polite" title={hint}>
      <span className={cx('h-2 w-2 rounded-full', color)} aria-hidden="true" />
      {label}
      {hint && <span className="sr-only">. {hint}</span>}
    </span>
  );
}

export function Layout() {
  const { principal } = useAuth();
  const store = useAuthStore();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const override = isTenantOverride(principal);

  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  const menuCloseRef = useRef<HTMLButtonElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!menuOpen) return;
    menuCloseRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    document.addEventListener('keydown', onKey);
    const button = menuButtonRef.current;
    return () => {
      document.removeEventListener('keydown', onKey);
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

  const items = NAV_ITEMS.filter((i) => i.allowed(principal));

  const signOut = async () => {
    const sso = principal?.method === 'oidc' ? getConfig().oidc : null;
    // Signing out also drops cached data (bindQueryCacheToSession in App).
    await store.logout();
    // End the identity provider session too, so the next sign-in asks again.
    const url = sso ? await logoutUrl(sso) : null;
    if (url) window.location.assign(url);
  };

  const nav = (
    <nav aria-label="Main">
      <ul className="space-y-0.5">
        {items.map(({ to, label, icon: Icon }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                cx(
                  'flex items-center gap-2.5 rounded-control px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus',
                  isActive ? 'bg-selected font-semibold text-fg' : 'text-body hover:bg-raised-2 hover:text-fg',
                )
              }
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );

  return (
    <div className="min-h-screen bg-canvas">
      <a
        href="#main"
        className="sr-only z-50 rounded bg-accent px-3 py-2 font-semibold text-on-accent focus:not-sr-only focus:fixed focus:left-2 focus:top-2"
      >
        Skip to main content
      </a>
      <aside className="fixed inset-y-0 left-0 hidden w-60 flex-col border-r border-subtle bg-sidebar lg:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <Activity className="h-5 w-5 text-link" aria-hidden="true" />
          <span className="font-semibold text-fg">LG-SOTF</span>
        </div>
        <div className="flex-1 overflow-y-auto px-2 pb-4">{nav}</div>
      </aside>

      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" aria-hidden="true" onClick={() => setMenuOpen(false)} />
          <div
            className="absolute inset-y-0 left-0 w-64 overflow-y-auto border-r border-subtle bg-sidebar p-2"
            id="mobile-nav"
            role="dialog"
            aria-modal="true"
            aria-label="Main menu"
          >
            <div className="flex items-center justify-between px-2 py-2">
              <span className="font-semibold text-fg">LG-SOTF</span>
              <Button ref={menuCloseRef} variant="quiet" size="sm" aria-label="Close menu" onClick={() => setMenuOpen(false)} icon={<X className="h-4 w-4" aria-hidden="true" />} />
            </div>
            {nav}
          </div>
        </div>
      )}

      <div className="lg:pl-60">
        <header className="sticky top-0 z-30 flex flex-wrap items-center gap-3 border-b border-subtle bg-canvas/95 px-4 py-2.5 backdrop-blur">
          <Button
            ref={menuButtonRef}
            variant="quiet"
            size="sm"
            className="lg:hidden"
            aria-label="Open menu"
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            onClick={() => setMenuOpen(true)}
            icon={<Menu className="h-5 w-5" aria-hidden="true" />}
          />
          <div className="flex min-w-0 items-center gap-2 text-sm">
            <span className="text-muted">Tenant</span>
            <span className={cx('truncate font-medium', override ? 'text-warn-fg' : 'text-fg')} data-testid="tenant-name">
              {principal?.tenantId ?? '-'}
            </span>
            {override && <span className="rounded bg-tint-warn px-1.5 py-0.5 text-xs text-warn-fg">platform admin override</span>}
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-3">
            <TenantSwitcher />
            <LiveIndicator />
            <DensityToggle className="hidden md:inline-flex" />
            <ThemeSwitch />
            <div className="hidden text-right text-xs sm:block">
              <div className="text-fg">{principal?.email ?? 'Signed in'}</div>
              <div className="text-muted">
                {principal?.role ?? 'no role'}
                {principal?.isPlatformAdmin ? ', platform admin' : ''}
                {principal?.method === 'oidc' ? ' (SSO)' : ''}
              </div>
            </div>
            <Button size="sm" variant="quiet" onClick={signOut} icon={<LogOut className="h-4 w-4" aria-hidden="true" />}>
              Sign out
            </Button>
          </div>
        </header>
        <ActingTenantBanner />
        <main id="main" ref={mainRef} tabIndex={-1} className="mx-auto max-w-[1600px] px-4 py-6 focus:outline-none sm:px-6">
          <Suspense fallback={<LoadingState />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  );
}
