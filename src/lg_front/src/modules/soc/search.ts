/**
 * What the SOC adds to the shell's search field: alerts by title, and the
 * commands that open the pages where a SOC act is confirmed.
 *
 * The API searches alert titles only (`GET /alerts?q=`, the last 30 days of
 * the tenant the caller acts on). It has no search over entities or cases
 * yet, so the field does not offer one: a host that is in no title would
 * come back empty and read as "no alerts on this host".
 */

import { can } from '../../auth/roles';
import type { ModuleCommand, ModuleSearch } from '../../core/module';
import { humanize } from '../../lib/format';
import { endpoints } from './api/endpoints';
import { alertHref, alertsHref, APPROVALS_HREF, POV_WIZARD_HREF } from './lib/links';

/** How many alerts the field lists; the Alerts page shows the rest. */
const SEARCH_LIMIT = 8;

export const alertSearch: ModuleSearch = {
  allowed: can.view,
  label: 'Alerts',
  find: async (api, query, signal) => {
    const page = await endpoints.alertTitles(api, query, SEARCH_LIMIT, signal);
    return page.items.map((a) => ({
      id: a.id,
      kind: 'Alert',
      title: a.title,
      detail: `${humanize(a.severity)} · ${humanize(a.status)}`,
      to: alertHref(a.id),
    }));
  },
  more: (query) => ({ label: `All alerts with "${query}" in the title`, to: alertsHref({ q: query, view: 'all' }) }),
};

/** Links, never acts: each opens the page where a person confirms. */
export const socCommands: readonly ModuleCommand[] = [
  { label: 'Approve or reject waiting actions', to: APPROVALS_HREF, allowed: can.view },
  { label: 'Write a suppression rule', to: '/suppressions', allowed: can.createSuppression },
  { label: 'Connect an alert source', to: '/sources', allowed: can.admin },
  { label: 'Add a person or an API key', to: '/users', allowed: can.admin },
  { label: 'Start a proof of value', to: POV_WIZARD_HREF, allowed: can.admin },
];
