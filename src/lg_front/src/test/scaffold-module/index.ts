/**
 * The smallest complete module (ADR 0015): one page behind a gate, a nav
 * group with a counted item, a query-key namespace, a live event and one
 * contribution to another module's extension point.
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
import { defineModule } from '../../core/module';
import { contribute } from '../../core/slots';
// Another module is reached through its public surface only.
import { ALERT_ENTITY } from '../../modules/soc/public';
import { useThingCount } from './api/hooks';
import { scaffoldKeys } from './api/queryKeys';

// Pages and widgets are reached through lazy() only.
const ScaffoldPage = lazy(() => import('./pages/ScaffoldPage'));
const EntityNote = lazy(() => import('./EntityNote'));

/** The module's own access rules, built on the kernel's role ladder. */
export const canScaffold = {
  useThings: (p: Principal | null) => roleAtLeast(p?.role, 'analyst'),
};

export const scaffold = defineModule({
  id: 'scaffold',
  title: 'Scaffold',
  entitlement: 'scaffold',
  permissions: canScaffold,
  navGroups: [{ id: 'scaffold', title: 'Scaffold', order: 15 }],
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
});
