import { Activity } from 'lucide-react';
import { useId } from 'react';
import { Link, NavLink } from 'react-router-dom';

import { useAuth } from '../../auth/AuthContext';
import { CountChip, cx } from '../../components/ui';
import { navFor, roleNote, type NavCount, type NavGroup } from './nav';

/** A nav item's count chip. The number comes from the hook the item's module supplies; nothing shows without one. */
function NavCountChip({ count }: { count: NavCount }) {
  const n = count.useCount();
  return n === undefined ? null : <CountChip count={n} tone={count.tone} meaning={count.meaning(n)} />;
}

/**
 * The sidebar: brand, role-filtered groups of links (`groups` is the route
 * table's nav, NAV_GROUPS in app/routes.tsx) (the current page has
 * aria-current="page", set by NavLink), the modules' counts with their
 * meaning for screen readers, and a note on the role that explains hidden
 * pages.
 */
export function Sidebar({ groups: allGroups, onNavigate }: { groups: readonly NavGroup[]; onNavigate?: () => void }) {
  const { principal } = useAuth();
  const idPrefix = useId();
  const groups = navFor(allGroups, principal);

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
                      {count && <NavCountChip count={count} />}
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
