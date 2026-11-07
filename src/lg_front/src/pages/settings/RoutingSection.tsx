/** Tenant settings: response routing (which connector executes each action type). */

import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import { ROUTE_NAMES, type JsonObject, type RouteOut, type TenantSettingsOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { ErrorMessage, LoadingState, SelectField } from '../../components/ui';
import { humanize } from '../../lib/format';
import { asObject } from '../../lib/json';
import { Section, useSave } from './shared';

const ROUTE_SOURCE_LABELS: Record<string, string> = {
  kill_switch: 'install dry run',
  tenant_dry_run: 'tenant dry run',
  sample: 'onboarding sample',
  pinned: 'pinned',
  explicit: 'your override',
  ticketing: 'ticketing integration',
  capability: 'Microsoft capability',
  default: 'tenant default',
};

/** Merge patch of response.routes from the override choices ("" = automatic); null clears them all. */
export function routesPatch(choice: Record<string, string>): JsonObject {
  const routes: Record<string, string> = {};
  for (const [type, route] of Object.entries(choice)) if (route) routes[type] = route;
  return { response: { routes: Object.keys(routes).length ? routes : null } };
}

export function describeRoute(route: RouteOut): string {
  const why = [ROUTE_SOURCE_LABELS[route.source] ?? route.source];
  if (route.capability) why.push(route.capability);
  if (route.live === false) why.push('rehearsal');
  else if (route.live) why.push('live');
  return `${humanize(route.connector)} (${why.join(', ')})`;
}

export function RoutingSection({ data }: { data: TenantSettingsOut }) {
  const api = useApi();
  const q = useQuery({ queryKey: qk.responseRoutes.forSettings(data.updated_at), queryFn: ({ signal }) => endpoints.responseRoutes(api, signal) });
  const stored = asObject(asObject(data.settings.response).routes) as Record<string, string>;
  const [choice, setChoice] = useState<Record<string, string>>(stored);
  const save = useSave();
  const routes = Object.entries(asObject(q.data?.routes)) as Array<[string, RouteOut]>;
  return (
    <Section
      title="Response routing"
      saveLabel="Save response routing"
      description="Which connector executes each action type: the kill switches first, then your overrides, a ticketing integration for create_ticket, an enabled Microsoft capability, and finally the tenant default connector."
      onSubmit={() => save.mutate(routesPatch(choice))}
      busy={save.isPending}
      error={save.error}
    >
      {q.data?.dry_run_forced && (
        <p role="status" className="rounded-control border border-warn/60 bg-tint-warn px-3 py-2 text-sm text-warn-fg">
          Dry run is on: nothing executes. Actions are recorded as dry runs until the install and tenant dry run switches are off.
        </p>
      )}
      {q.isPending && <LoadingState label="Loading routes" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />}
      {routes.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Response routes</caption>
            <thead className="border-b border-subtle text-xs uppercase tracking-wide text-muted">
              <tr>
                <th scope="col" className="px-2 py-1">Action</th>
                <th scope="col" className="px-2 py-1">Executes through</th>
                <th scope="col" className="px-2 py-1">Override</th>
              </tr>
            </thead>
            <tbody>
              {routes.map(([type, route]) => (
                <tr key={type} className="border-b border-subtle align-top">
                  <th scope="row" className="px-2 py-1 text-left font-normal text-fg">
                    {humanize(type)}
                  </th>
                  <td className="px-2 py-1 text-xs text-secondary">
                    {describeRoute(route)}
                    {route.problem && <span className="block text-danger-fg">{route.problem}</span>}
                  </td>
                  <td className="px-2 py-1">
                    <SelectField
                      label={<span className="sr-only">Route for {humanize(type)}</span>}
                      value={choice[type] ?? ''}
                      onChange={(e) => setChoice({ ...choice, [type]: e.target.value })}
                    >
                      <option value="">auto</option>
                      {ROUTE_NAMES.map((name) => (
                        <option key={name} value={name} disabled={name === 'ticketing' && type !== 'create_ticket'}>
                          {humanize(name)}
                        </option>
                      ))}
                    </SelectField>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}
