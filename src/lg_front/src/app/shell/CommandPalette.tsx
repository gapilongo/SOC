/**
 * Search and commands (Ctrl+K, or `/`): one field for pages, the modules'
 * records, tenants and commands.
 *
 * - Pages come from the registry: every page the signed-in person may open.
 * - Records come from each module's `search` (the SOC: alert titles), asked
 *   in the tenant the person works in; every hit names that tenant.
 * - Tenants, for a platform admin: choosing one changes the scope.
 * - Commands: a module's command is a link to the page where the act is
 *   confirmed (`ModuleCommand` has no callback), so nothing here changes
 *   data. The shell's own commands change display settings only.
 *
 * A dialog with a combobox (ARIA 1.2): focus stays in the field, the arrow
 * keys move the highlighted option, Enter opens it, Escape closes and puts
 * focus back where it was. `>` at the start lists commands only.
 */

import { keepPreviousData, useQueries } from '@tanstack/react-query';
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';

import { useTenants } from '../../api/hooks';
import { coreKeys } from '../../api/queryKeys';
import { useApi, useAuth } from '../../auth/AuthContext';
import type { Principal } from '../../auth/store';
import { useToast } from '../../components/Toast';
import { cx } from '../../components/ui';
import { useFocusTrap } from '../../components/useFocusTrap';
import { useDensity } from '../../theme/density';
import { useTheme } from '../../theme/theme';
import { mayOpen, pageLabelIn, type Registry } from '../registry';
import { searchPrompt } from './nav';
import { filterTenants, useChooseTenant } from './tenants';

/** One line of the list. It leads to a page (`to`) or, for a display setting or a change of tenant, acts at once (`act`). */
export type PaletteItem = { id: string; kind: string; title: string; detail?: string } & ({ to: string } | { act: () => void });

const MIN_QUERY = 2;
const MAX_TENANTS = 8;

/** Every page `p` may open that has a name and no parameter in its path. */
export function pageItems(registry: Pick<Registry, 'routes' | 'navGroups'>, p: Principal | null): PaletteItem[] {
  const groupOf = new Map(registry.navGroups.flatMap((g) => g.items.map((i) => [i.to, g.title] as const)));
  return registry.routes.flatMap((r) => {
    const label = r.nav?.label ?? r.label;
    if (!label || r.path.includes(':') || !mayOpen(r, p)) return [];
    return [{ id: `page:${r.path}`, kind: 'Page', title: label, detail: groupOf.get(r.path), to: r.path }];
  });
}

/** The modules' commands `p` may use. Each is a link: it says which page it opens, and that it runs nothing. */
export function commandItems(registry: Pick<Registry, 'routes' | 'commands'>, p: Principal | null): PaletteItem[] {
  return registry.commands
    .filter((c) => mayOpen(c, p))
    .map((c) => {
      const path = c.to.split(/[?#]/)[0];
      // The page itself when it has a name, else the page it belongs to.
      const exact = registry.routes.find((r) => r.path === path);
      const page = exact?.nav?.label ?? exact?.label ?? pageLabelIn(registry.routes, path);
      return { id: `do:${c.module}:${c.label}`, kind: 'Do', title: c.label, detail: `opens ${page ?? 'its page'}, runs nothing`, to: c.to };
    });
}

function useDebounced<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return settled;
}

export default function CommandPalette({
  registry,
  tenantLabel,
  singleKeys,
  onSingleKeys,
  onClose,
}: {
  registry: Registry;
  tenantLabel: string;
  singleKeys: boolean;
  onSingleKeys: (on: boolean) => void;
  onClose: () => void;
}) {
  const { principal } = useAuth();
  const api = useApi();
  const navigate = useNavigate();
  const toast = useToast();
  const chooseTenant = useChooseTenant();
  const { setPreference } = useTheme();
  const { setDensity } = useDensity();
  const [text, setText] = useState('');
  const [active, setActive] = useState(0);
  const panelRef = useRef<HTMLDivElement>(null);
  const listId = useId();
  useFocusTrap(panelRef, true, { onEscape: onClose });

  const commandsOnly = text.trimStart().startsWith('>');
  const query = (commandsOnly ? text.trimStart().slice(1) : text).trim();
  const settled = useDebounced(query, 200);
  const tenants = useTenants(true);
  const searches = registry.searches.filter((s) => mayOpen(s, principal));
  const asked = !commandsOnly && settled.length >= MIN_QUERY;
  const results = useQueries({
    queries: searches.map((s) => ({
      queryKey: coreKeys.search.hits(s.module, principal?.tenantId ?? '', settled),
      queryFn: ({ signal }: { signal: AbortSignal }) => s.find(api, settled, signal),
      enabled: asked,
      staleTime: 30_000,
      placeholderData: keepPreviousData,
    })),
  });

  const items = ((): PaletteItem[] => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    const fits = (i: PaletteItem) => words.every((w) => `${i.kind} ${i.title} ${i.detail ?? ''}`.toLowerCase().includes(w));
    const settings: PaletteItem[] = [
      { id: 'set:theme:system', kind: 'Do', title: 'Theme: follow the system', detail: 'display setting', act: () => setPreference('system') },
      { id: 'set:theme:light', kind: 'Do', title: 'Theme: light', detail: 'display setting', act: () => setPreference('light') },
      { id: 'set:theme:dark', kind: 'Do', title: 'Theme: dark', detail: 'display setting', act: () => setPreference('dark') },
      { id: 'set:rows:compact', kind: 'Do', title: 'Rows: compact', detail: 'display setting', act: () => setDensity('compact') },
      { id: 'set:rows:comfortable', kind: 'Do', title: 'Rows: comfortable', detail: 'display setting', act: () => setDensity('comfortable') },
      {
        id: 'set:keys',
        kind: 'Do',
        title: `Single-key shortcuts: turn ${singleKeys ? 'off' : 'on'}`,
        detail: 'display setting',
        act: () => {
          onSingleKeys(!singleKeys);
          toast.info(`Single-key shortcuts are ${singleKeys ? 'off' : 'on'}. Ctrl K, Tab and Enter always work.`);
        },
      },
    ];
    const commands = [...commandItems(registry, principal), ...settings].filter(fits);
    if (commandsOnly) return commands;
    // A tenant is listed once something is typed: choosing one changes the scope, which the address then carries.
    const places: PaletteItem[] = words.length
      ? filterTenants(tenants.data ?? [], query, principal?.homeTenantId ?? '')
          .slice(0, MAX_TENANTS)
          .map((t) => ({
            id: `tenant:${t.id}`,
            kind: 'Tenant',
            title: t.name,
            detail: t.id === principal?.tenantId ? `${t.id} · you are here` : t.id,
            act: () => chooseTenant(t.id, t.name),
          }))
      : [];
    const records: PaletteItem[] = searches.flatMap((s, n) => {
      const hits = asked ? (results[n].data ?? []) : [];
      const more = s.more && query.length >= MIN_QUERY ? [{ id: `${s.module}:more`, kind: 'Find', ...s.more(query) }] : [];
      return [
        // Every record says which tenant it is in.
        ...hits.map((h) => ({ id: `${s.module}:${h.id}`, kind: h.kind, title: h.title, detail: [h.detail, tenantLabel].filter(Boolean).join(' · '), to: h.to })),
        ...more.map((m) => ({ id: m.id, kind: m.kind, title: m.label, detail: tenantLabel, to: m.to })),
      ];
    });
    return [...pageItems(registry, principal).filter(fits), ...records, ...places, ...commands];
  })();

  const searching = !commandsOnly && query.length >= MIN_QUERY && searches.length > 0 && (settled !== query || results.some((r) => r.isFetching));
  const failed = searches.filter((_, n) => asked && results[n].isError).map((s) => s.label.toLowerCase());
  const at = Math.min(active, items.length - 1);
  const optionId = (i: number) => `${listId}-opt-${i}`;

  useEffect(() => {
    // jsdom has no scrollIntoView.
    document.getElementById(`${listId}-opt-${at}`)?.scrollIntoView?.({ block: 'nearest' });
  }, [at, listId]);

  const run = (item: PaletteItem) => {
    onClose();
    if ('act' in item) item.act();
    else navigate(item.to);
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (items.length > 0) setActive((at + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (items[at]) run(items[at]);
    }
  };

  const status = searching ? 'Searching' : items.length === 0 ? `Nothing matches in ${tenantLabel}` : `${items.length} ${items.length === 1 ? 'result' : 'results'}`;

  return createPortal(
    <div className="fixed inset-0 z-[60]">
      <div className="absolute inset-0 bg-black/30" aria-hidden="true" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Search and commands"
        className="absolute left-1/2 top-[12vh] w-[620px] max-w-[calc(100vw-24px)] -translate-x-1/2 overflow-hidden rounded-[4px] bg-raised shadow-popover"
      >
        <input
          type="text"
          role="combobox"
          aria-label="Search"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={items[at] ? optionId(at) : undefined}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setActive(0);
          }}
          onKeyDown={onKey}
          placeholder={`${searchPrompt(registry, principal)}. Type > for commands`}
          autoComplete="off"
          spellCheck={false}
          className="block h-[46px] w-full border-b border-subtle bg-transparent px-3.5 text-[15px] text-fg focus:outline-none focus-visible:outline-none"
        />
        <ul id={listId} role="listbox" aria-label="Results" aria-busy={searching} className="max-h-[52vh] overflow-y-auto pb-1.5 pt-1">
          {items.map((item, i) => (
            // Keyboard selection runs through the combobox input (aria-activedescendant), as the ARIA pattern prescribes.
            // eslint-disable-next-line jsx-a11y/click-events-have-key-events
            <li
              key={item.id}
              id={optionId(i)}
              role="option"
              aria-selected={i === at}
              onPointerDown={(e) => e.preventDefault()}
              onClick={() => run(item)}
              onMouseEnter={() => setActive(i)}
              className={cx('flex min-h-8 cursor-pointer items-center gap-2 px-3 py-1 text-ctl', i === at ? 'bg-selected text-fg' : 'text-body')}
            >
              <span className="w-[58px] flex-none font-mono text-[10.5px] font-medium uppercase leading-none tracking-[0.05em] text-muted">{item.kind}</span>
              <span className="min-w-0">{item.title}</span>
              {item.detail && <span className="ml-auto min-w-0 flex-none pl-2 text-right text-xs text-muted max-[860px]:hidden">{item.detail}</span>}
            </li>
          ))}
        </ul>
        {items.length === 0 && !searching && (
          <p className="px-3 pb-2.5 text-ctl text-muted">Nothing matches in {tenantLabel}.</p>
        )}
        {failed.length > 0 && <p className="px-3 pb-2 text-xs text-danger-fg">The search for {failed.join(' and ')} failed. Pages and commands still work.</p>}
        <p role="status" className="sr-only">
          {status}
        </p>
        <div className="flex flex-wrap gap-x-3.5 gap-y-1 border-t border-subtle px-3 py-[7px] text-xs text-muted">
          <span>
            <kbd>↑</kbd> <kbd>↓</kbd> move
          </span>
          <span>
            <kbd>Enter</kbd> open
          </span>
          <span>
            <kbd>Esc</kbd> close
          </span>
          <span className="ml-auto">
            {searching ? 'Searching ' : ''}in {tenantLabel}
          </span>
        </div>
      </div>
    </div>,
    document.body,
  );
}
