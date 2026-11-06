import { useQuery } from '@tanstack/react-query';
import { Activity } from 'lucide-react';
import { useId } from 'react';
import { Link, NavLink } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import { useApi, useAuth } from '../../auth/AuthContext';
import { usePollInterval } from '../../lib/visibility';
import { CountChip, cx } from '../ui';
import { navCounts, navFor, roleNote } from './nav';

/** The dashboard window the counts come from (the overview page's default, so the query is shared). */
const COUNT_WINDOW_HOURS = 24;

/** Nav counts (escalations breaching SLA, approvals waiting on me) from the dashboard summary. */
export function useNavCounts() {
  const api = useApi();
  const interval = usePollInterval(60_000);
  const q = useQuery({
    queryKey: qk.dashboard.summary(COUNT_WINDOW_HOURS),
    queryFn: ({ signal }) => endpoints.dashboard(api, COUNT_WINDOW_HOURS, signal),
    refetchInterval: interval,
    refetchIntervalInBackground: false,
  });
  return navCounts(q.data);
}

/**
 * The sidebar: brand, role-filtered groups of links (the current page has
 * aria-current="page", set by NavLink), counts with their meaning for screen
 * readers, and a note on the role that explains hidden pages.
 */
export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { principal } = useAuth();
  const counts = useNavCounts();
  const idPrefix = useId();
  const groups = navFor(principal);

  return (
    <nav aria-label="Main" className="flex min-h-full flex-col gap-5 px-3 pb-5 pt-3.5 text-sm">
      <Link to="/" onClick={onNavigate} className="flex items-center gap-2.5 rounded-control px-2 py-1 text-fg">
        <span aria-hidden="true" className="grid h-7 w-7 flex-none place-items-center rounded-control bg-accent text-on-accent">
          <Activity className="h-4 w-4" strokeWidth={2} />
        </span>
        <span className="flex flex-col leading-tight">
          <span className="font-bold tracking-[0.02em]">LG-SOTF</span>
          <span className="text-2xs text-secondary">Security operations</span>
        </span>
      </Link>
      {groups.map((g) => {
        const headingId = `${idPrefix}-${g.id}`;
        return (
          <div key={g.id} className="flex flex-col gap-1">
            <h2 id={headingId} className="eyebrow px-2.5 pb-1">
              {g.title}
            </h2>
            {/* role="list" keeps list semantics in Safari despite list-style: none. */}
            {/* eslint-disable-next-line jsx-a11y/no-redundant-roles */}
            <ul role="list" aria-labelledby={headingId} className="flex flex-col gap-0.5">
              {g.items.map(({ to, label, icon: Icon, count }) => {
                const n = count ? counts[count.field] : undefined;
                return (
                  <li key={to}>
                    <NavLink
                      to={to}
                      end={to === '/'}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        cx(
                          'flex min-h-[34px] items-center gap-2.5 rounded-control px-2.5 touch:min-h-11',
                          isActive ? 'bg-selected font-semibold text-fg' : 'text-body hover:bg-raised-2 hover:text-fg',
                        )
                      }
                    >
                      <Icon className="h-4 w-4 flex-none" strokeWidth={1.75} aria-hidden="true" />
                      <span className="flex-1">{label}</span>
                      {count && n !== undefined && <CountChip count={n} tone={count.tone} meaning={count.meaning(n)} />}
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
      <p className="mt-auto border-t border-subtle px-2.5 pt-2.5 text-xs text-secondary">{roleNote(principal)}</p>
    </nav>
  );
}
