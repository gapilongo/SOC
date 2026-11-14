/**
 * The contract between the shell and a service module (ADR 0015).
 *
 * A module is a folder under `src/modules/<id>/` whose `index.ts` exports one
 * manifest. The manifest is static data: the shell reads it to build routes,
 * the sidebar, navigation counts, the live-event mapping and the extension
 * points without running the module's pages. Page and widget code is reached
 * only through `lazy()`, so a module that is not used is not downloaded.
 *
 * Registering a module is one line in `src/app/modules.ts`.
 */

import type { QueryKey } from '@tanstack/react-query';
import type { LucideIcon } from 'lucide-react';
import type { ComponentType } from 'react';

import type { ApiClient } from '../api/client';
import type { Principal } from '../auth/store';
import type { Contribution } from './slots';

/** An access rule: the server is the authority, the UI only hides what it would refuse. */
export type Allowed = (p: Principal | null) => boolean;

/** A count chip on a nav item. The module supplies the number through a hook of its own API slice. */
export interface NavCount {
  /** The current number, or undefined for no chip (not loaded, zero, or not sent by the API). */
  useCount: () => number | undefined;
  tone: 'warn' | 'approval';
  /** What the number counts, for screen readers. */
  meaning: (n: number) => string;
}

/** A group of the rail. Groups are shared: a module adds items to a group another module declared by using its id. */
export interface NavGroupDef {
  id: string;
  title: string;
  /** Position in the rail, ascending. */
  order: number;
  /**
   * A service group: the pages only this module has, under the service's own name ("Vulnerabilities").
   * When the installation's licence does not include the module, a platform admin sees the group
   * locked and labelled "Not licensed", and a customer tenant's users do not see it. A group
   * without the flag is a capability group (Work, Configure): it only ever lists pages that open.
   */
  service?: boolean;
}

/** One record a module's search found (an alert, a finding), for the shell's search field. */
export interface SearchHit {
  /** Unique among the module's hits. */
  id: string;
  /** One word for the kind of record: "Alert", "Host". */
  kind: string;
  title: string;
  /** What tells this record from its neighbours: severity, state, a reference. */
  detail?: string;
  /** The page that shows it. */
  to: string;
}

/** A module's search over its own records. The shell calls it with what was typed and lists the hits. */
export interface ModuleSearch {
  /** Who may search; the API enforces it. */
  allowed: Allowed;
  /** What a hit is, in the plural, for the list heading: "Alerts". */
  label: string;
  /** Hits for `query` (trimmed, at least two characters) in the tenant the caller acts on. */
  find: (api: ApiClient, query: string, signal: AbortSignal) => Promise<readonly SearchHit[]>;
  /** A page that lists every match, when the module has one: "all alerts with this in the title". */
  more?: (query: string) => { label: string; to: string };
}

/**
 * A command in the shell's search field. A command is a link: it opens the page where the act is
 * confirmed and has no callback, so nothing a module declares can change data from the search field.
 */
export interface ModuleCommand {
  label: string;
  to: string;
  allowed: Allowed;
}

/** Something that needs an act now: a deadline about to pass, approvals waiting, a source that stopped. */
export interface Notice {
  /** Unique among the module's notices. */
  id: string;
  kind: 'deadline' | 'approval' | 'source';
  text: string;
  detail?: string;
  /** The page where the act happens. */
  to: string;
}

export interface ModuleRoute {
  /** URL path (`/` is the index route); may hold route parameters. */
  path: string;
  /** The page, loaded with `lazy()`. */
  Page: ComponentType;
  /** Role gate; the nav entry, if any, shows exactly when this allows. */
  allowed: Allowed;
  /** Page name for the breadcrumb, when the page has no nav entry. */
  label?: string;
  nav?: { group: string; label: string; icon: LucideIcon; count?: NavCount };
  /** `false` for a page rendered outside the app shell (a printable page). Default: inside. */
  shell?: boolean;
}

export interface ModuleManifest {
  /** Folder name under `src/modules/`, and the first element of every query key of the module. */
  id: string;
  title: string;
  /**
   * The entitlement that turns the module on for a tenant. Absent: always on.
   * The server will send a tenant's entitlements with `GET /auth/me`
   * (ARCH-E10.2); until then `moduleEnabled` lets every module through.
   */
  entitlement?: string;
  /** What the service adds, in a few lines, for the page shown where the licence does not include it. */
  offers?: readonly string[];
  /** Rail groups this module declares. */
  navGroups?: readonly NavGroupDef[];
  /** Pages. Within a nav group, the rail follows this order. */
  routes: readonly ModuleRoute[];
  /**
   * The module's access rules, by name. Route gates are taken from here, so
   * a page's gate and the buttons inside it name the same function. A rule
   * takes the principal and may take more (the escalation, the risk level):
   * `...rest: never[]` accepts any such signature without letting the shell
   * call one with arguments it does not have.
   */
  permissions?: Readonly<Record<string, (p: Principal | null, ...rest: never[]) => boolean>>;
  /** Live event type -> the module's own query keys that the event makes stale. */
  liveEvents?: Readonly<Record<string, readonly QueryKey[]>>;
  /** Components the module renders in extension points owned by the shell or by another module. */
  extensions?: readonly Contribution[];
  /** The module's records in the shell's search field. */
  search?: ModuleSearch;
  /** Commands in the shell's search field: links to the pages where an act is confirmed. */
  commands?: readonly ModuleCommand[];
  /** What needs an act now, for the shell's notifications. A hook of the module's API slice, like a nav count. */
  useNotices?: () => readonly Notice[];
}

/** Type-checks a manifest where it is written. */
export function defineModule(manifest: ModuleManifest): ModuleManifest {
  return manifest;
}

/**
 * Whether `p`'s tenant has this module. The hook for server-supplied
 * entitlements: the route guard and the sidebar both ask here. Today every
 * registered module is on, because the session carries no entitlement yet
 * (ARCH-E10.2 adds the field to `GET /auth/me` and to `Principal`).
 */
export function moduleEnabled(_manifest: Pick<ModuleManifest, 'id' | 'entitlement'>, _p: Principal | null): boolean {
  return true;
}
