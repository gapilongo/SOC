import { Lock } from 'lucide-react';
import { useId } from 'react';
import { Link, NavLink } from 'react-router-dom';

import { useAuth } from '../../auth/AuthContext';
import { VisuallyHidden, cx } from '../../components/ui';
import { getBrand } from '../../config';
import { AccountMenu } from './AccountMenu';
import { BrandMark } from './BrandMark';
import { navFor, type NavCount, type NavGroup, type NavItem } from './nav';

/** A nav item's count. The number comes from the hook the item's module supplies; nothing shows without one. */
function RailCount({ count }: { count: NavCount }) {
  const n = count.useCount();
  if (n === undefined) return null;
  const meaning = count.meaning(n);
  return (
    <span className="ml-auto font-mono text-[11.5px] font-medium tabular-nums text-fg" title={`${n} ${meaning}`}>
      {n}
      <VisuallyHidden> {meaning}</VisuallyHidden>
    </span>
  );
}

const ITEM = 'flex h-[30px] items-center gap-[9px] border-l-2 pl-3 pr-3.5 touch:min-h-11';

function RailLink({ item, locked, onNavigate }: { item: NavItem; locked: boolean; onNavigate?: () => void }) {
  const { to, label, icon: Icon, count } = item;
  return (
    <NavLink
      to={to}
      end={to === '/'}
      onClick={onNavigate}
      className={({ isActive }) =>
        cx(
          ITEM,
          isActive ? 'border-accent bg-selected font-semibold text-fg' : 'border-transparent hover:bg-raised-2 hover:text-fg',
          !isActive && (locked ? 'text-muted' : 'text-secondary'),
        )
      }
    >
      <Icon className="h-4 w-4 flex-none" strokeWidth={1.5} aria-hidden="true" />
      <span className="min-w-0 truncate">
        {label}
        {locked && <VisuallyHidden>, not licensed</VisuallyHidden>}
      </span>
      {locked ? <Lock className="ml-auto h-3.5 w-3.5 flex-none" strokeWidth={1.5} aria-hidden="true" /> : count && <RailCount count={count} />}
    </NavLink>
  );
}

/**
 * The rail: the brand, the capability groups (and a service group per
 * licensed service) with the pages the signed-in person may open, each
 * module's counts with their meaning, and the person at the bottom.
 * `groups` is the registry's navigation; the current page has
 * aria-current="page" (set by NavLink). A service the installation's licence
 * does not include is listed locked for a platform admin and not at all for
 * anyone else.
 */
export function Rail({
  groups: allGroups,
  tenantLabel,
  onNavigate,
  onSignOut,
}: {
  groups: readonly NavGroup[];
  tenantLabel: string;
  onNavigate?: () => void;
  onSignOut: () => void;
}) {
  const { principal } = useAuth();
  const idPrefix = useId();
  const brand = getBrand();
  const groups = navFor(allGroups, principal);

  return (
    <nav aria-label="Main" className="flex h-full min-h-0 flex-col text-ctl">
      <Link to="/" onClick={onNavigate} className="flex h-12 flex-none items-center gap-2.5 border-b border-subtle px-3.5">
        <BrandMark brand={brand} />
        <span className="min-w-0 leading-[1.15]">
          <span className="block truncate font-semibold text-fg">{brand.name}</span>
          <span className="block truncate text-[10.5px] text-muted">{brand.tagline}</span>
        </span>
      </Link>
      <div className="min-h-0 flex-1 overflow-y-auto pb-3 pt-1.5">
        {groups.map((g) => {
          const headingId = `${idPrefix}-${g.id}`;
          return (
            <div key={g.id}>
              <h2 id={headingId} className="eyebrow flex items-center gap-1.5 whitespace-nowrap px-3.5 pb-1 pt-3">
                {g.title}
                {g.locked && (
                  <span className="ml-auto rounded-[2px] border border-strong px-1 py-0.5 font-mono text-[9.5px] font-medium leading-none tracking-[0.05em] text-secondary">
                    Not licensed
                  </span>
                )}
              </h2>
              {/* role="list" keeps list semantics in Safari despite list-style: none. */}
              {/* eslint-disable-next-line jsx-a11y/no-redundant-roles */}
              <ul role="list" aria-labelledby={headingId}>
                {g.items.map((item) => (
                  <li key={item.to}>
                    <RailLink item={item} locked={g.locked} onNavigate={onNavigate} />
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
      <AccountMenu tenantLabel={tenantLabel} onSignOut={onSignOut} />
    </nav>
  );
}
