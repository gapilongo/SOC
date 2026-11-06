/**
 * Tenant context for platform admins: a searchable tenant picker in the
 * header and the "acting as tenant" banner.
 *
 * Switching sets the store's acting tenant: requests then carry
 * `X-Tenant-ID` (each one is recorded in that tenant's audit log), live
 * updates stay off, and cached data of the previous tenant is dropped
 * (bindQueryCacheToSession). The tenant list comes from `/platform/tenants`
 * (never sent with the override) and is only fetched when the picker opens.
 */

import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Building2, Check, ChevronDown, LogOut } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';

import { endpoints } from '../api/endpoints';
import { qk } from '../api/queryKeys';
import type { TenantSummaryOut } from '../api/types';
import { useApi, useAuth, useAuthStore } from '../auth/AuthContext';
import { isTenantOverride } from '../auth/roles';
import { Badge } from './Badge';
import { useToast } from './Toast';
import { Button, cx } from './ui';

const TENANT_ID = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const MAX_OPTIONS = 50;

interface Option {
  id: string;
  label: string;
  hint?: string;
  status?: string;
}

/** Tenants whose id or name contains every word of `query` (case-insensitive), home tenant first. */
/** Options a caller of {@link usePlatformTenants} may set; anything left out keeps the client default. */
export interface PlatformTenantsOptions {
  refetchInterval?: number | false;
  staleTime?: number;
  enabled?: boolean;
}

/**
 * Every tenant (platform admins). One query shared by the tenant switcher and
 * the platform page; each caller states its own freshness options.
 */
export function usePlatformTenants(options: PlatformTenantsOptions = {}) {
  const api = useApi();
  // Only the options a caller set: an explicit undefined would override the client defaults.
  const set = Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined)) as PlatformTenantsOptions;
  return useQuery({
    queryKey: qk.platformTenants.all,
    queryFn: ({ signal }) => endpoints.platformTenants(api, signal),
    ...set,
  });
}

export function filterTenants(tenants: readonly TenantSummaryOut[], query: string, home: string): TenantSummaryOut[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return tenants
    .filter((t) => words.every((w) => t.id.includes(w) || t.name.toLowerCase().includes(w)))
    .sort((a, b) => Number(b.id === home) - Number(a.id === home) || a.name.localeCompare(b.name));
}

/** Switch the acting tenant and say what that means; returns false when the store refused. */
export function useSwitchTenant(): (tenant: string | null, name?: string) => boolean {
  const store = useAuthStore();
  const toast = useToast();
  return (tenant, name) => {
    try {
      // Cached data of the previous tenant is dropped by bindQueryCacheToSession (App).
      store.setActingTenant(tenant);
      const home = store.getState().principal?.homeTenantId;
      toast.info(
        tenant && tenant !== home
          ? `Acting as tenant ${name ?? tenant}. Every request is recorded in that tenant's audit log.`
          : 'Back to your home tenant.',
      );
      return true;
    } catch (err) {
      toast.error(err);
      return false;
    }
  };
}

/** `label`: the tenant's display name for the button (defaults to the tenant id). */
export function TenantSwitcher({ label }: { label?: string } = {}) {
  const { principal } = useAuth();
  const switchTo = useSwitchTenant();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const listId = useId();
  const enabled = Boolean(principal?.isPlatformAdmin) && open;
  const tenants = usePlatformTenants({ enabled, staleTime: 60_000 });

  useEffect(() => {
    if (!open) return;
    inputRef.current?.focus();
    const onPointer = (e: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', onPointer);
    return () => document.removeEventListener('pointerdown', onPointer);
  }, [open]);

  const home = principal?.homeTenantId ?? '';
  const options: Option[] = useMemo(() => {
    const matches: Option[] = filterTenants(tenants.data ?? [], query, home)
      .slice(0, MAX_OPTIONS)
      .map((t) => ({ id: t.id, label: t.name, hint: t.id === home ? `${t.id} (home)` : t.id, status: t.status }));
    const typed = query.trim().toLowerCase();
    // The list could not be loaded or does not know the id yet: a typed id still works, as before.
    if (TENANT_ID.test(typed) && matches.length === 0) {
      matches.push({ id: typed, label: `Use tenant id "${typed}"` });
    }
    return matches;
  }, [tenants.data, query, home]);

  if (!principal?.isPlatformAdmin) return null;

  const close = () => {
    setOpen(false);
    setQuery('');
    buttonRef.current?.focus();
  };
  const choose = (option: Option) => {
    if (switchTo(option.id, option.status ? option.label : undefined)) close();
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((i) => Math.min(i + 1, options.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const option = options[active];
      if (option) choose(option);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      close();
    }
  };
  const optionId = (i: number) => `${listId}-opt-${i}`;
  const override = isTenantOverride(principal);

  return (
    <div ref={rootRef} className="relative">
      <Button
        ref={buttonRef}
        size="sm"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => (open ? close() : setOpen(true))}
        className="max-w-full font-semibold"
        icon={<Building2 className="h-4 w-4 flex-none text-secondary" strokeWidth={1.75} aria-hidden="true" />}
      >
        <span className="sr-only">Switch tenant, current: </span>
        <span className={cx('max-w-[12rem] truncate', isTenantOverride(principal) && 'text-warn-fg')} data-testid="tenant-name">
          {label ?? principal.tenantId}
        </span>
        <ChevronDown className="h-3.5 w-3.5 flex-none text-secondary" strokeWidth={2} aria-hidden="true" />
      </Button>
      {open && (
        <div className="absolute left-0 z-40 mt-1 w-80 max-w-[calc(100vw-2rem)] rounded-card border border-strong bg-raised-2 p-2 shadow-popover">
          <label htmlFor={`${listId}-search`} className="sr-only">
            Search tenants
          </label>
          <input
            id={`${listId}-search`}
            ref={inputRef}
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={options[active] ? optionId(active) : undefined}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKey}
            placeholder="Search by name or id"
            autoComplete="off"
            className="mb-2 block w-full rounded-control border border-control bg-canvas px-2 py-1.5 text-sm text-fg placeholder:text-muted focus:border-link focus:outline-none"
          />
          {tenants.isPending && <p className="px-2 py-1 text-xs text-muted">Loading tenants...</p>}
          {tenants.isError && <p className="px-2 py-1 text-xs text-danger-fg">The tenant list could not be loaded; type a tenant id.</p>}
          <ul id={listId} role="listbox" aria-label="Tenants" className="max-h-72 overflow-y-auto">
            {options.map((o, i) => (
              // Keyboard selection runs through the combobox input (aria-activedescendant), as the ARIA pattern prescribes.
              // eslint-disable-next-line jsx-a11y/click-events-have-key-events
              <li
                key={o.id}
                id={optionId(i)}
                role="option"
                aria-selected={i === active}
                onPointerDown={(e) => e.preventDefault()}
                onClick={() => choose(o)}
                onMouseEnter={() => setActive(i)}
                className={cx(
                  'flex cursor-pointer items-center justify-between gap-2 rounded px-2 py-1.5 text-sm',
                  i === active ? 'bg-raised-2 text-fg' : 'text-body',
                )}
              >
                <span className="min-w-0">
                  <span className="block truncate">{o.label}</span>
                  {o.hint && <span className="block truncate font-mono text-xs text-muted">{o.hint}</span>}
                </span>
                <span className="flex flex-none items-center gap-1">
                  {o.status === 'suspended' && <Badge tone="bad">suspended</Badge>}
                  {o.id === principal.tenantId && <Check className="h-4 w-4 text-link" aria-label="current" />}
                </span>
              </li>
            ))}
            {!tenants.isPending && options.length === 0 && <li className="px-2 py-1 text-xs text-muted">No tenant matches.</li>}
          </ul>
          {override && (
            <Button size="sm" variant="quiet" className="mt-2 w-full" onClick={() => choose({ id: home, label: home })}>
              Back to home tenant ({home})
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

/** Shown on every page while a platform admin acts on another tenant. */
export function ActingTenantBanner() {
  const { principal } = useAuth();
  const switchTo = useSwitchTenant();
  if (!principal || !isTenantOverride(principal)) return null;
  return (
    <div role="status" className="flex flex-wrap items-center gap-3 border-b border-warn/60 bg-tint-warn px-4 py-1.5 text-ctl font-medium text-fg md:px-6">
      <AlertTriangle className="h-4 w-4 flex-none text-warn-fg" strokeWidth={1.75} aria-hidden="true" />
      <span className="min-w-0 flex-1">
        Acting as tenant <strong className="font-semibold">{principal.tenantId}</strong>. Every request is recorded in that tenant&apos;s
        audit log; live updates are off.
      </span>
      <Button size="sm" onClick={() => switchTo(null)} icon={<LogOut className="h-3.5 w-3.5" aria-hidden="true" />}>
        Return to {principal.homeTenantId}
      </Button>
    </div>
  );
}
