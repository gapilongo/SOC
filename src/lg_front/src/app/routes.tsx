/**
 * The route table: one entry per signed-in page, with its role gate and,
 * for pages in the sidebar, its nav entry. It is derived from the registered
 * modules (modules.ts): each module's manifest declares its pages, and
 * App.tsx renders the routes, the sidebar and the breadcrumb from here, so a
 * page's gate and its nav visibility cannot diverge.
 *
 * Public routes (sign-in and the OIDC callback) stay inline in App.tsx.
 */

import { MODULES } from './modules';
import { buildRegistry, pageLabelIn } from './registry';

export type { AppRoute, NavGroup, NavItem } from './registry';

/** Everything the shell derives from the registered modules. */
export const REGISTRY = buildRegistry(MODULES);

/** Signed-in pages, inside the app shell. Within each nav group, the sidebar follows this order. */
export const APP_ROUTES = REGISTRY.routes;

/** Signed-in pages outside the app shell (the printable monthly report). */
export const BARE_ROUTES = REGISTRY.bareRoutes;

/** The sidebar: every route with a nav entry, grouped, each item gated like its route. */
export const NAV_GROUPS = REGISTRY.navGroups;

/** Page name for the header breadcrumb and the phone top bar: the route at `pathname` or its closest parent. */
export function pageLabel(pathname: string): string | null {
  return pageLabelIn(APP_ROUTES, pathname);
}
