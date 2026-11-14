import { Menu, Monitor, Moon, Search, Sun, type LucideIcon } from 'lucide-react';
import { forwardRef } from 'react';

import { useAuth } from '../../auth/AuthContext';
import { cx } from '../../components/ui';
import { useLive } from '../../live/LiveProvider';
import { THEME_PREFERENCES, useTheme, type ThemePreference } from '../../theme/theme';
import type { Registry } from '../registry';
import { searchPrompt } from './nav';
import { Notifications } from './Notifications';
import { ScopeControl } from './ScopeControl';

const QUIET = 'rounded-control text-secondary hover:bg-raised-2 hover:text-fg';

export function LiveIndicator() {
  const { status } = useLive();
  const { actingTenant } = useAuth();
  const label =
    actingTenant ? 'Live updates off' :
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
      : actingTenant
        ? 'Live updates are off while you work in another tenant; pages still refresh periodically.'
        : undefined;
  return (
    <span className="mr-1.5 inline-flex min-w-0 items-center gap-1.5 text-xs text-secondary" role="status" aria-live="polite" title={hint}>
      <span className={cx('h-[7px] w-[7px] flex-none rounded-full', color)} aria-hidden="true" />
      {/* Narrow screens show the dot only (the word stays for screen readers), so the scope keeps the room. */}
      <span className="sr-only min-[861px]:not-sr-only min-[861px]:truncate">{label}</span>
      {hint && <span className="sr-only">. {hint}</span>}
    </span>
  );
}

const THEMES: Record<ThemePreference, { label: string; says: string; icon: LucideIcon }> = {
  system: { label: 'System', says: 'follows the system', icon: Monitor },
  light: { label: 'Light', says: 'light', icon: Sun },
  dark: { label: 'Dark', says: 'dark', icon: Moon },
};

/** The theme control: one button that says the current choice and steps System, Light, Dark. */
export function ThemeControl() {
  const { preference, setPreference } = useTheme();
  const { label, says, icon: Icon } = THEMES[preference];
  const next = THEME_PREFERENCES[(THEME_PREFERENCES.indexOf(preference) + 1) % THEME_PREFERENCES.length];
  return (
    <button
      type="button"
      // The visible word is part of the name (WCAG 2.5.3).
      aria-label={`Theme: ${label} (${says}). Change to ${THEMES[next].label}`}
      onClick={() => setPreference(next)}
      className={cx(QUIET, 'inline-flex h-7 items-center gap-1.5 px-2.5 text-ctl font-medium touch:min-h-11')}
    >
      <Icon className="h-4 w-4 flex-none" strokeWidth={1.5} aria-hidden="true" />
      {label}
    </button>
  );
}

/**
 * The top bar of every page: the scope (which tenant), the search field
 * (pages, records and commands; Ctrl+K), the live status, notifications and
 * the theme. On a narrow screen the menu button comes first and the search
 * field is its icon.
 */
export const TopBar = forwardRef<
  HTMLButtonElement,
  { registry: Registry; tenantLabel: string; menuOpen: boolean; onOpenMenu: () => void; onSearch: () => void }
>(function TopBar({ registry, tenantLabel, menuOpen, onOpenMenu, onSearch }, menuButtonRef) {
  const { principal } = useAuth();
  return (
    <header className="sticky top-0 z-30 flex h-12 items-center gap-1.5 border-b border-subtle bg-canvas px-3 min-[861px]:gap-2.5 min-[861px]:px-5">
      <button
        ref={menuButtonRef}
        type="button"
        aria-label="Open the menu"
        aria-expanded={menuOpen}
        aria-controls="rail-drawer"
        onClick={onOpenMenu}
        className={cx(QUIET, 'grid h-[30px] w-[30px] flex-none place-items-center touch:h-11 touch:w-11 min-[861px]:hidden')}
      >
        <Menu className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
      </button>
      <ScopeControl label={tenantLabel} />
      <button
        type="button"
        onClick={onSearch}
        aria-keyshortcuts="Control+K"
        className={cx(
          'flex h-[30px] w-[30px] flex-none items-center justify-center gap-2 rounded-control border border-transparent text-left text-ctl text-muted hover:border-control touch:h-11 touch:w-11',
          'min-[861px]:w-auto min-[861px]:max-w-[520px] min-[861px]:flex-1 min-[861px]:justify-start min-[861px]:bg-raised-2 min-[861px]:px-2',
        )}
      >
        <Search className="h-4 w-4 flex-none" strokeWidth={1.5} aria-hidden="true" />
        <span className="sr-only min-[861px]:not-sr-only min-[861px]:flex-1 min-[861px]:truncate">{searchPrompt(registry, principal)}</span>
        <span className="hidden flex-none gap-1 min-[861px]:flex">
          <kbd>Ctrl</kbd>
          <kbd>K</kbd>
        </span>
      </button>
      <div className="ml-auto flex flex-none items-center gap-1">
        <LiveIndicator />
        <Notifications sources={registry.notices} tenantLabel={tenantLabel} />
        <ThemeControl />
      </div>
    </header>
  );
});
