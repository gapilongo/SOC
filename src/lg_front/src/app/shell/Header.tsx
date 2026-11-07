import { Building2, Menu } from 'lucide-react';
import { forwardRef } from 'react';

import { useTenantLabel } from '../../api/hooks';
import { useAuth } from '../../auth/AuthContext';
import { isTenantOverride } from '../../auth/roles';
import { TenantSwitcher } from '../../pages/platform/TenantSwitcher';
import { Button, ThemeSwitch, cx } from '../../components/ui';
import { useLive } from '../../live/LiveProvider';
import { UserMenu } from './UserMenu';

export function LiveIndicator() {
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
    <span className="inline-flex min-w-0 items-center gap-1.5 text-ctl text-body" role="status" aria-live="polite" title={hint}>
      <span className={cx('h-2 w-2 flex-none rounded-full', color)} aria-hidden="true" />
      <span className="truncate">{label}</span>
      {hint && <span className="sr-only">. {hint}</span>}
    </span>
  );
}

/** The tenant for everyone else: platform admins get the switcher instead. */
function TenantLabel({ label }: { label: string }) {
  const { principal } = useAuth();
  const override = isTenantOverride(principal);
  return (
    <span className="flex h-8 min-w-0 items-center gap-2 rounded-control border border-subtle bg-raised px-2.5 text-ctl font-semibold text-fg">
      <Building2 className="h-4 w-4 flex-none text-secondary" strokeWidth={1.75} aria-hidden="true" />
      <span className="sr-only">Tenant: </span>
      <span className={cx('truncate', override && 'text-warn-fg')} data-testid="tenant-name">
        {label}
      </span>
    </span>
  );
}

/**
 * The one header of every page: tenant (switcher for platform admins),
 * breadcrumb (`page`, the current page's name), live status, theme switch and
 * the account menu. On phones a top bar with the menu button and the page
 * name comes first.
 */
export const Header = forwardRef<
  HTMLButtonElement,
  { page: string | null; menuOpen: boolean; onOpenMenu: () => void; onSignOut: () => void }
>(function Header({ page, menuOpen, onOpenMenu, onSignOut }, menuButtonRef) {
  const { principal } = useAuth();
  const tenantLabel = useTenantLabel();

  return (
    <header className="sticky top-0 z-30 bg-canvas/95 backdrop-blur">
      <div className="flex h-12 items-center gap-3 border-b border-subtle bg-sidebar px-3 md:hidden">
        <Button
          ref={menuButtonRef}
          size="lg"
          aria-label="Open menu"
          aria-expanded={menuOpen}
          aria-controls="mobile-nav"
          onClick={onOpenMenu}
          icon={<Menu className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />}
        />
        <span className="font-bold text-fg">LG-SOTF</span>
        {page && <span className="truncate text-ctl text-secondary">{page}</span>}
      </div>
      <div className="flex min-h-14 flex-wrap items-center gap-x-3 gap-y-2 border-b border-subtle px-4 py-2 md:px-6">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          {principal?.isPlatformAdmin ? <TenantSwitcher label={tenantLabel} /> : <TenantLabel label={tenantLabel} />}
          {page && (
            <nav aria-label="Breadcrumb" className="hidden min-w-0 md:block">
              <ol className="flex items-center gap-1.5 text-ctl">
                <li className="flex min-w-0 items-center gap-1.5">
                  <span aria-hidden="true" className="text-muted">
                    /
                  </span>
                  <span aria-current="page" className="truncate font-medium text-fg">
                    {page}
                  </span>
                </li>
              </ol>
            </nav>
          )}
        </div>
        <div className="ml-auto flex items-center gap-3.5">
          <LiveIndicator />
          <ThemeSwitch className="hidden sm:inline-flex" />
          <UserMenu tenantLabel={tenantLabel} onSignOut={onSignOut} />
        </div>
      </div>
    </header>
  );
});
