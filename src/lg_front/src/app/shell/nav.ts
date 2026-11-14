/**
 * The sidebar's navigation model: groups (Operate / Report / Configure /
 * Platform, and any a module declares) of items filtered by role. The groups
 * come from the registered modules' routes (app/registry.ts), so every item
 * is gated exactly like its route.
 */

import { can } from '../../auth/roles';
import type { Principal } from '../../auth/store';
import { mayOpen, type NavGroup } from '../registry';

export type { NavCount } from '../../core/module';
export type { NavGroup, NavItem } from '../registry';

/** The groups and items `p` may use (the tenant has the module and the role allows the page); empty groups are dropped. */
export function navFor(groups: readonly NavGroup[], p: Principal | null): NavGroup[] {
  return groups
    .map((g) => ({ ...g, items: g.items.filter((i) => mayOpen(i, p)) }))
    .filter((g) => g.items.length > 0);
}

/** "Signed in as ..." under the nav, saying why pages may be missing. */
export function roleNote(p: Principal | null): string {
  if (!p) return '';
  if (can.platform(p)) return 'Signed in as a platform admin.';
  if (can.admin(p)) return p.isPlatformAdmin ? 'Signed in as a platform admin acting on a tenant.' : 'Signed in as a tenant admin.';
  if (p.role === 'analyst') return 'Signed in as an analyst. Admin pages are hidden.';
  return 'Signed in as a viewer. Admin pages are hidden.';
}
