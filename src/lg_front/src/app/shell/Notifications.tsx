/**
 * Notifications: only what needs an act, now. Each registered module says
 * what that is through the `useNotices` hook of its manifest (deadlines about
 * to pass, approvals waiting, a source that stopped); the shell lists them
 * under the bell, names the tenant on each line and counts them on the badge.
 * There is no read state: a line leaves when the thing it names is done.
 */

import { Bell, CircleDot, CircleSlash, Diamond, type LucideIcon } from 'lucide-react';
import { useId, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { useAuth } from '../../auth/AuthContext';
import { cx } from '../../components/ui';
import type { Notice } from '../../core/module';
import type { Registry } from '../registry';
import { usePopover } from './usePopover';

type Source = Registry['notices'][number];
type Listed = Notice & { key: string };

/** Shape first, colour second: a diamond for a deadline, a ring for an approval, a struck circle for a source. */
const MARK: Record<Notice['kind'], { icon: LucideIcon; tone: string }> = {
  deadline: { icon: Diamond, tone: 'text-state-bad' },
  approval: { icon: CircleDot, tone: 'text-state-approval' },
  source: { icon: CircleSlash, tone: 'text-sev-info' },
};

/**
 * Runs each source's hook in a component of its own (a module that is off is never asked), then
 * hands every notice found to `children`.
 */
function Gather({ sources, found, children }: { sources: readonly Source[]; found: readonly Listed[]; children: (all: readonly Listed[]) => ReactNode }) {
  if (sources.length === 0) return <>{children(found)}</>;
  return (
    <FromModule source={sources[0]} rest={sources.slice(1)} found={found}>
      {children}
    </FromModule>
  );
}

function FromModule({ source, rest, found, children }: { source: Source; rest: readonly Source[]; found: readonly Listed[]; children: (all: readonly Listed[]) => ReactNode }) {
  const mine = source.useNotices().map((n) => ({ ...n, key: `${source.module}:${n.id}` }));
  return (
    <Gather sources={rest} found={[...found, ...mine]}>
      {children}
    </Gather>
  );
}

/** `sources`: the registry's notice hooks. `tenantLabel`: the tenant every line belongs to (the current scope). */
export function Notifications({ sources, tenantLabel }: { sources: readonly Source[]; tenantLabel: string }) {
  const { principal } = useAuth();
  const mine = sources.filter((s) => s.enabled(principal));
  return (
    <Gather sources={mine} found={[]}>
      {(all) => <NoticeBell notices={all} tenantLabel={tenantLabel} />}
    </Gather>
  );
}

function NoticeBell({ notices, tenantLabel }: { notices: readonly Listed[]; tenantLabel: string }) {
  const { open, setOpen, close, rootRef, buttonRef } = usePopover();
  const popId = useId();
  const n = notices.length;

  return (
    <div ref={rootRef} className="relative">
      <button
        ref={buttonRef}
        type="button"
        aria-label={n === 0 ? 'Notifications: nothing needs you' : `Notifications: ${n} ${n === 1 ? 'needs' : 'need'} an act`}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? popId : undefined}
        onClick={() => (open ? close() : setOpen(true))}
        className="relative grid h-[30px] w-[30px] place-items-center rounded-control text-secondary hover:bg-raised-2 hover:text-fg touch:h-11 touch:w-11"
      >
        <Bell className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
        {n > 0 && (
          <span aria-hidden="true" className="absolute right-0 top-px h-[15px] min-w-[15px] rounded-full bg-fg px-[3px] text-center text-[10px] font-semibold leading-[15px] text-canvas">
            {n}
          </span>
        )}
      </button>
      {open && (
        <div
          id={popId}
          role="dialog"
          aria-label="Notifications"
          className="absolute right-0 top-full z-50 mt-1.5 w-[400px] max-w-[calc(100vw-24px)] rounded-[4px] bg-raised shadow-popover max-[860px]:fixed max-[860px]:right-3 max-[860px]:top-11"
        >
          <p className="eyebrow px-3 pb-1.5 pt-2.5">Needs an act</p>
          {n === 0 && <p className="border-t border-subtle px-3 py-2.5 text-ctl text-secondary">Nothing needs you right now in {tenantLabel}.</p>}
          {/* eslint-disable-next-line jsx-a11y/no-redundant-roles */}
          <ul role="list">
            {notices.map(({ key, kind, text, detail, to }) => {
              const { icon: Icon, tone } = MARK[kind];
              return (
                <li key={key} className="border-t border-subtle">
                  <Link to={to} onClick={() => close(false)} className="grid grid-cols-[16px_minmax(0,1fr)] gap-x-2 gap-y-0.5 px-3 py-[9px] text-ctl hover:bg-raised-2">
                    <Icon className={cx('mt-0.5 h-3.5 w-3.5', tone)} strokeWidth={2} aria-hidden="true" />
                    <span className="text-fg">{text}</span>
                    <span className="col-start-2 text-xs text-muted">{[tenantLabel, detail].filter(Boolean).join(' · ')}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
