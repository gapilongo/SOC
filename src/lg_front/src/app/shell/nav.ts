/**
 * The rail's navigation model: the capability groups (Work, Detect and
 * respond, Assure, Configure, Platform) and any service group a module
 * declares, filtered for the signed-in person. The groups come from the
 * registered modules' routes (app/registry.ts), so every item is gated
 * exactly like its route.
 */

import type { Principal } from '../../auth/store';
import { mayOpen, type NavGroup, type NavItem, type Registry } from '../registry';

export type { NavCount } from '../../core/module';
export type { NavGroup, NavItem } from '../registry';

/** A group as the rail shows it. `locked`: a service the installation's licence does not include. */
export interface RailGroup extends NavGroup {
  locked: boolean;
}

const hasModule = (item: NavItem, p: Principal | null) => item.enabled?.(p) ?? true;

/**
 * The groups and items `p` sees. An item shows when the tenant has its module
 * and the role allows the page; a group with nothing to show is dropped.
 *
 * A service group whose module is not licensed is the exception: a platform
 * admin sees it locked, each item opening the page that says so; a customer
 * tenant's users do not see it at all (they are never shown something to buy).
 */
export function navFor(groups: readonly NavGroup[], p: Principal | null): RailGroup[] {
  return groups
    .map((g) => {
      const open = g.items.filter((i) => mayOpen(i, p));
      if (open.length > 0 || !g.service || !p?.isPlatformAdmin) return { ...g, locked: false, items: open };
      return { ...g, locked: true, items: g.items.filter((i) => !hasModule(i, p)) };
    })
    .filter((g) => g.items.length > 0);
}

/** What the search field finds for `p`, as its prompt: "Search pages and alerts". */
export function searchPrompt(registry: Pick<Registry, 'searches'>, p: Principal | null): string {
  const kinds = ['pages', ...registry.searches.filter((s) => mayOpen(s, p)).map((s) => s.label.toLowerCase())];
  return `Search ${kinds.length > 1 ? `${kinds.slice(0, -1).join(', ')} and ${kinds[kinds.length - 1]}` : kinds[0]}`;
}
