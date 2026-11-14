/**
 * The smallest complete module (ADR 0015): one page behind a gate, a service
 * group of its own in the rail with a counted item, a query-key namespace, a
 * live event, one contribution to another module's extension point, and what
 * it adds to the shell's search field and notifications.
 *
 * It is a test fixture: src/app/scaffold.test.tsx registers it with one line
 * and shows that the shell picks everything up. It is also the shape to copy
 * when a service starts: this folder becomes `src/modules/<id>/`, and
 * `src/app/modules.ts` gains the one entry.
 */

import { Boxes } from 'lucide-react';
import { lazy } from 'react';

import { roleAtLeast } from '../../auth/roles';
import type { Principal } from '../../auth/store';
import { defineModule, type Notice } from '../../core/module';
import { contribute } from '../../core/slots';
// Another module is reached through its public surface only.
import { ALERT_ENTITY } from '../../modules/soc/public';
import { useThingCount } from './api/hooks';
import { scaffoldKeys } from './api/queryKeys';

// Pages and widgets are reached through lazy() only.
const ScaffoldPage = lazy(() => import('./pages/ScaffoldPage'));
const EntityNote = lazy(() => import('./EntityNote'));

/** What needs an act: the things that wait, as one notice (the hook behind the nav count, so one request). */
function useScaffoldNotices(): readonly Notice[] {
  const waiting = useThingCount();
  return waiting ? [{ id: 'waiting', kind: 'deadline', text: `${waiting} scaffold things wait`, to: '/scaffold' }] : [];
}

/** The module's own access rules, built on the kernel's role ladder. */
export const canScaffold = {
  useThings: (p: Principal | null) => roleAtLeast(p?.role, 'analyst'),
};

export const scaffold = defineModule({
  id: 'scaffold',
  title: 'Scaffold',
  entitlement: 'scaffold',
  permissions: canScaffold,
  offers: ['Scaffold things: the things that wait, in one list', 'On every alert: a note next to each host'],
  // A service group: the pages only this module has. Locked for a platform admin when the licence leaves the module out.
  navGroups: [{ id: 'scaffold', title: 'Scaffold', order: 15, service: true }],
  routes: [
    {
      path: '/scaffold',
      Page: ScaffoldPage,
      allowed: canScaffold.useThings,
      nav: {
        group: 'scaffold',
        label: 'Scaffold things',
        icon: Boxes,
        count: { useCount: useThingCount, tone: 'warn', meaning: (n) => (n === 1 ? 'thing waiting' : 'things waiting') },
      },
    },
  ],
  liveEvents: {
    'scaffold.updated': [scaffoldKeys.things.all],
  },
  extensions: [contribute(ALERT_ENTITY, EntityNote)],
  search: {
    allowed: canScaffold.useThings,
    label: 'Things',
    find: async (api, query, signal) => {
      const found = await api.get<Array<{ id: string; name: string }>>('/scaffold/things', { query: { q: query }, signal });
      return found.map((t) => ({ id: t.id, kind: 'Thing', title: t.name, to: '/scaffold' }));
    },
  },
  // A command is a link to the page where the act is confirmed.
  commands: [{ label: 'Sort the scaffold things', to: '/scaffold', allowed: canScaffold.useThings }],
  useNotices: useScaffoldNotices,
});
