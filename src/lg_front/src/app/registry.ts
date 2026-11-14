/**
 * What the shell derives from the registered modules (src/app/modules.ts):
 * the route table, the sidebar, the live-event mapping and the extension
 * contributions. The shell iterates this and holds no list of its own, so a
 * new module changes nothing here (ADR 0015).
 */

import type { QueryKey } from '@tanstack/react-query';

import { moduleEnabled, type Allowed, type ModuleManifest, type ModuleRoute, type NavCount } from '../core/module';
import type { Contribution } from '../core/slots';
import type { LucideIcon } from 'lucide-react';

/** A module's route as the shell uses it. */
export interface AppRoute extends ModuleRoute {
  /** Id of the module the route belongs to. */
  module: string;
  /** Whether the principal's tenant has that module (the entitlement hook). */
  enabled: Allowed;
}

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  allowed: Allowed;
  /** Whether the principal's tenant has the item's module; absent means yes. */
  enabled?: Allowed;
  count?: NavCount;
}

export interface NavGroup {
  id: string;
  title: string;
  items: NavItem[];
}

export interface Registry {
  modules: readonly ModuleManifest[];
  /** Signed-in pages inside the app shell, in registration order. */
  routes: readonly AppRoute[];
  /** Signed-in pages outside the shell (printable pages). */
  bareRoutes: readonly AppRoute[];
  /** The sidebar: every route with a nav entry, grouped, each item gated like its route. */
  navGroups: readonly NavGroup[];
  /** Query keys a live event of this type makes stale, across modules; empty for an unknown type. */
  liveKeys: (eventType: string) => readonly QueryKey[];
  /** Every extension contribution, in registration order. */
  extensions: readonly Contribution[];
}

function fail(message: string): never {
  throw new Error(`module registry: ${message}`);
}

/**
 * Build the registry. A manifest that cannot work (a duplicate id or path, a
 * nav entry in a group nobody declared, a path that is not absolute) is a
 * programming error and throws here, where every test of the shell sees it.
 */
export function buildRegistry(modules: readonly ModuleManifest[]): Registry {
  const ids = new Set<string>();
  const paths = new Map<string, string>();
  const groupDefs = new Map<string, { id: string; title: string; order: number; index: number }>();
  const routes: AppRoute[] = [];
  const bareRoutes: AppRoute[] = [];
  const live = new Map<string, QueryKey[]>();
  const extensions: Contribution[] = [];

  for (const m of modules) {
    if (!/^[a-z][a-z0-9-]*$/.test(m.id)) fail(`"${m.id}" is not a module id (lower-case letters, digits and dashes)`);
    if (ids.has(m.id)) fail(`module "${m.id}" is registered twice`);
    ids.add(m.id);
    for (const g of m.navGroups ?? []) {
      // The first module to declare a group names it; later declarations of the same id are ignored.
      if (!groupDefs.has(g.id)) groupDefs.set(g.id, { ...g, index: groupDefs.size });
    }
  }

  for (const m of modules) {
    const enabled: Allowed = (p) => moduleEnabled(m, p);
    for (const r of m.routes) {
      if (!r.path.startsWith('/')) fail(`${m.id}: path "${r.path}" must start with "/"`);
      const owner = paths.get(r.path);
      if (owner) fail(`path "${r.path}" is declared by both "${owner}" and "${m.id}"`);
      paths.set(r.path, m.id);
      if (r.nav && !groupDefs.has(r.nav.group)) fail(`${m.id}: "${r.path}" is in nav group "${r.nav.group}", which no module declares`);
      if (r.nav && r.shell === false) fail(`${m.id}: "${r.path}" is outside the shell and cannot have a nav entry`);
      (r.shell === false ? bareRoutes : routes).push({ ...r, module: m.id, enabled });
    }
    for (const [type, keys] of Object.entries(m.liveEvents ?? {})) {
      live.set(type, [...(live.get(type) ?? []), ...keys]);
    }
    extensions.push(...(m.extensions ?? []));
  }

  const navGroups = [...groupDefs.values()]
    .sort((a, b) => a.order - b.order || a.index - b.index)
    .map(({ id, title }) => ({
      id,
      title,
      items: routes.flatMap((r): NavItem[] =>
        r.nav?.group === id ? [{ to: r.path, label: r.nav.label, icon: r.nav.icon, allowed: r.allowed, enabled: r.enabled, count: r.nav.count }] : [],
      ),
    }));

  return { modules, routes, bareRoutes, navGroups, liveKeys: (type) => live.get(type) ?? [], extensions };
}

/** Page name for the breadcrumb and the phone top bar: the route at `pathname` or its closest parent. */
export function pageLabelIn(routes: readonly AppRoute[], pathname: string): string | null {
  for (const r of routes) {
    const label = r.nav?.label ?? r.label;
    if (!label || r.path.includes(':')) continue;
    if (r.path === '/' ? pathname === '/' : pathname === r.path || pathname.startsWith(`${r.path}/`)) return label;
  }
  return null;
}
