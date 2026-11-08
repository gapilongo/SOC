/** The escalation queue's table: one row per escalation, or groups of the same rule that expand into rows. */

import { useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';

import { endpoints, type EscalationFilters } from '../../api/endpoints';
import { decidedByLabel, escalationConflictNotice, escalationOwner, escalationSeverity, escalationTitle, formatEntities, readAiReason, readRouting } from '../../api/fields';
import { useEscalationList } from '../../api/hooks';
import { afterEscalationChange } from '../../api/invalidate';
import type { EscalationGroupOut, EscalationOut } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { useToast } from '../../components/Toast';
import { Button, ErrorMessage, SEVERITIES, SeverityTag, Spinner, buttonClass, cx } from '../../components/ui';
import { formatDateTime, formatRelative } from '../../lib/format';
import { escalationHref, escalationQueueHref } from '../../lib/links';
import { slaStatus } from '../../lib/sla';
import { bandLabel, decisionLabel, percent, routingLabel } from './labels';

/** Rows per page of the queue and of an expanded group (a bulk request takes at most 50). */
export const QUEUE_PAGE_SIZE = 50;

const ACTIVE = new Set(['open', 'claimed', 'expired']);

export interface Selection {
  isSelected: (id: string) => boolean;
  /** Add or remove rows (adding stops at the bulk maximum). */
  set: (rows: readonly EscalationOut[], on: boolean) => void;
  /** No row can be added (the bulk maximum is reached). */
  full: boolean;
  /** Viewers cannot act in bulk: no checkboxes. */
  enabled: boolean;
}

const COLUMNS = 9;

function Sla({ e, now }: { e: EscalationOut; now: number }) {
  if (!ACTIVE.has(e.status)) {
    return (
      <span className="text-secondary">
        {e.decision ? decisionLabel(e.decision) : e.status}
        {e.decided_at && <span className="block text-xs text-muted">{formatRelative(e.decided_at, now)}</span>}
      </span>
    );
  }
  const s = slaStatus(e.sla_deadline, now, e.created_at);
  const hot = s.state === 'breaching' || s.state === 'at_risk';
  return (
    <span className={cx('whitespace-nowrap tabular-nums', hot ? 'text-warn' : 'text-body', s.state === 'breaching' && 'font-semibold')} title={e.sla_deadline ? `SLA deadline ${formatDateTime(e.sla_deadline)}` : undefined}>
      {s.text}
      {hot && <span className="block text-xs font-semibold">{s.state === 'breaching' ? 'breaching' : 'at risk'}</span>}
    </span>
  );
}

function Routing({ e }: { e: EscalationOut }) {
  const routing = readRouting(e.routing);
  if (!routing) return <span className="text-muted">-</span>;
  const conf = percent(routing.confidence);
  const band = bandLabel(routing);
  return (
    <span className="tabular-nums">
      {conf ? <span className="font-semibold text-fg">{conf}</span> : <span className="text-secondary">{routingLabel(routing.code)}</span>}
      {conf && <span className="block whitespace-nowrap text-xs text-muted">{band ?? routingLabel(routing.code)}</span>}
    </span>
  );
}

function RowAction({ e }: { e: EscalationOut }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const location = useLocation();
  const { principal } = useAuth();
  const [busy, setBusy] = useState(false);
  const owner = escalationOwner(e, principal?.userId);
  const title = escalationTitle(e);
  if (!ACTIVE.has(e.status)) return null;
  if (owner.kind === 'you') {
    return (
      <Link to={escalationHref(e)} state={{ from: `${location.pathname}${location.search}` }} className={buttonClass('secondary', 'sm', 'whitespace-nowrap')} aria-label={`Decide ${title}`}>
        Decide
      </Link>
    );
  }
  if (!can.claimEscalation(principal, e)) return null;
  const takeOver = owner.kind === 'other';
  const claim = async () => {
    setBusy(true);
    try {
      await endpoints.claim(api, e.id, e.version);
      toast.success(takeOver ? 'Escalation taken over.' : 'Escalation claimed.');
    } catch (err) {
      const notice = escalationConflictNotice(err, 'the list has been refreshed');
      if (notice) toast.info(notice);
      else toast.error(err, 'Claim failed');
    } finally {
      setBusy(false);
      void afterEscalationChange(client);
    }
  };
  return (
    <Button size="sm" variant={takeOver ? 'secondary' : 'primary'} busy={busy} onClick={() => void claim()} className="whitespace-nowrap" aria-label={`${takeOver ? 'Take over' : 'Claim'} ${title}`}>
      {takeOver ? 'Take over' : 'Claim'}
    </Button>
  );
}

export function QueueRow({ e, now, selection, nested = false }: { e: EscalationOut; now: number; selection: Selection; nested?: boolean }) {
  const { principal } = useAuth();
  const location = useLocation();
  const title = escalationTitle(e);
  const entities = formatEntities(e.entities_preview, 2);
  const reason = readAiReason(e);
  const owner = ACTIVE.has(e.status) ? escalationOwner(e, principal?.userId) : null;
  const decider = owner ? null : decidedByLabel(e, principal?.userId);
  const selected = selection.isSelected(e.id);
  return (
    <tr className={cx('border-t border-subtle align-top', selected && 'bg-selected', nested && 'bg-canvas')}>
      <td className={cx('w-8 py-2 pl-3.5 pr-1.5', nested && 'pl-6')}>
        {selection.enabled && (
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 accent-accent disabled:cursor-not-allowed"
            aria-label={`Select ${title}`}
            checked={selected}
            disabled={!selected && selection.full}
            onChange={(ev) => selection.set([e], ev.target.checked)}
          />
        )}
      </td>
      <td className="px-2 py-2">
        <Sla e={e} now={now} />
      </td>
      <td className="px-2 py-2">
        <SeverityTag value={escalationSeverity(e)} />
      </td>
      <td className="min-w-[224px] px-2 py-2">
        <Link to={escalationHref(e)} state={{ from: `${location.pathname}${location.search}` }} className="font-medium text-fg hover:underline">
          {title}
        </Link>
        {entities && (
          <span className="line-clamp-2 break-words text-xs text-muted" title={entities}>
            {entities}
          </span>
        )}
      </td>
      <td className="w-[26%] max-w-0 px-2 py-2 text-xs text-body">
        <span className="block truncate" title={reason ? `${reason.text}${reason.source ? ` (written by the ${reason.source === 'model' ? 'model' : 'rules'})` : ''}` : e.reason}>
          {reason?.text ?? e.reason}
        </span>
        {reason?.source && <span className="block text-muted">by the {reason.source === 'model' ? 'model' : 'rules'}</span>}
      </td>
      <td className="px-2 py-2">
        <Routing e={e} />
      </td>
      <td className="px-2 py-2 text-secondary">{e.level}</td>
      <td className="px-2 py-2">
        {owner ? (
          <span title={owner.label} className={cx('block max-w-[160px] truncate', owner.kind === 'you' ? 'font-medium text-fg' : owner.kind === 'none' ? 'text-muted' : 'text-secondary')}>{owner.label}</span>
        ) : (
          <span title={decider ?? undefined} className="block max-w-[160px] truncate text-secondary">{decider ? `Decided by ${decider}` : '-'}</span>
        )}
      </td>
      <td className="py-2 pl-2 pr-3.5 text-right">
        <RowAction e={e} />
      </td>
    </tr>
  );
}

/** "2 high, 30 medium, 6 low", most severe first. */
export function severityMix(bySeverity: Record<string, number>): string {
  const order = [...SEVERITIES, ...Object.keys(bySeverity).filter((k) => !(SEVERITIES as readonly string[]).includes(k))];
  return order
    .filter((s) => (bySeverity[s] ?? 0) > 0)
    .map((s) => `${bySeverity[s]} ${s}`)
    .join(', ');
}

function worstSeverity(bySeverity: Record<string, number>): string | null {
  return SEVERITIES.find((s) => (bySeverity[s] ?? 0) > 0) ?? null;
}

function confidenceRange(g: EscalationGroupOut): string | null {
  const lo = percent(g.min_confidence);
  const hi = percent(g.max_confidence);
  if (!lo || !hi) return null;
  return lo === hi ? `confidence ${lo}` : `confidence ${lo.replace('%', '')}–${hi}`;
}

/** Filters listing one group's escalations (`?source_id=&rule=`), active ones, soonest deadline first. */
export function groupFilters(g: Pick<EscalationGroupOut, 'source_id' | 'rule'>, assignedTo: string | undefined): EscalationFilters {
  return { status: ['open', 'claimed'], source_id: g.source_id, rule: g.rule, assigned_to: assignedTo, order: 'sla_deadline' };
}

/** A group's header row and, once expanded, its escalations (paged like the queue). */
export function GroupRows({ g, now, selection, assignedTo }: { g: EscalationGroupOut; now: number; selection: Selection; assignedTo: string | undefined }) {
  const [expanded, setExpanded] = useState(false);
  const [selectWhenLoaded, setSelectWhenLoaded] = useState(false);
  const members = useEscalationList(groupFilters(g, assignedTo), { enabled: expanded, limit: QUEUE_PAGE_SIZE });
  const items = members.items;
  const bySeverity = g.by_severity ?? {};
  const mix = severityMix(bySeverity);
  const worst = worstSeverity(bySeverity);
  const mixed = Object.values(bySeverity).filter((n) => n > 0).length > 1;
  const selectedCount = items.filter((e) => selection.isSelected(e.id)).length;
  const all = items.length > 0 && selectedCount === items.length;
  const box = useRef<HTMLInputElement>(null);
  const { set } = selection;

  useEffect(() => {
    if (box.current) box.current.indeterminate = selectedCount > 0 && !all;
  }, [selectedCount, all]);

  useEffect(() => {
    if (selectWhenLoaded && members.isSuccess) {
      set(items, true);
      setSelectWhenLoaded(false);
    }
  }, [selectWhenLoaded, members.isSuccess, items, set]);

  const sla = g.earliest_sla_deadline ? slaStatus(g.earliest_sla_deadline, now) : null;
  const meta = [
    g.source_name ?? null,
    `${g.unassigned} unassigned`,
    g.overdue ? `${g.overdue} overdue` : null,
    confidenceRange(g),
    mix || null,
  ].filter(Boolean);

  return (
    <>
      <tr className="border-t border-subtle bg-sidebar align-top">
        <td className="w-8 py-2 pl-3.5 pr-1.5">
          {selection.enabled && (
            <input
              ref={box}
              type="checkbox"
              className="mt-0.5 h-4 w-4 accent-accent disabled:cursor-not-allowed"
              aria-label={`Select all ${g.size} in the group ${g.rule}`}
              checked={all}
              disabled={!all && selectedCount === 0 && selection.full}
              onChange={(ev) => {
                if (!ev.target.checked) {
                  set(items, false);
                  return;
                }
                if (members.isSuccess) set(items, true);
                else {
                  setExpanded(true);
                  setSelectWhenLoaded(true);
                }
              }}
            />
          )}
        </td>
        <td className="px-2 py-2">
          {sla && (
            <span className={cx('whitespace-nowrap tabular-nums', sla.state === 'breaching' || sla.state === 'at_risk' ? 'text-warn' : 'text-body', sla.state === 'breaching' && 'font-semibold')}>
              {sla.text}
              {(sla.state === 'breaching' || sla.state === 'at_risk') && <span className="block text-xs font-semibold">{sla.state === 'breaching' ? 'breaching' : 'at risk'}</span>}
              <span className="block text-xs font-normal text-muted">soonest in group</span>
            </span>
          )}
        </td>
        <td className="px-2 py-2">
          <SeverityTag value={worst} />
          {mixed && <span className="block text-xs text-muted">and lower</span>}
        </td>
        <td colSpan={COLUMNS - 4} className="px-2 py-2">
          <button
            type="button"
            aria-expanded={expanded}
            onClick={() => setExpanded(!expanded)}
            className="-ml-1.5 inline-flex items-center gap-2 rounded-tag px-1.5 py-1 text-left text-ctl font-semibold text-fg hover:bg-raised-2"
          >
            {expanded ? <ChevronDown className="h-3.5 w-3.5 flex-none" strokeWidth={2} aria-hidden="true" /> : <ChevronRight className="h-3.5 w-3.5 flex-none" strokeWidth={2} aria-hidden="true" />}
            {g.rule} ×{g.size}
          </button>
          <span className="text-xs text-secondary"> · {meta.join(' · ')}</span>
        </td>
        <td className="py-2 pl-2 pr-3.5 text-right">
          <Link to={escalationQueueHref({ source_id: g.source_id, rule: g.rule })} className={buttonClass('secondary', 'sm', 'whitespace-nowrap')}>
            Show as list
          </Link>
        </td>
      </tr>
      {expanded && members.isPending && <MessageRow>{<Spinner label={`Loading ${g.rule}`} />}</MessageRow>}
      {expanded && members.isError && (
        <MessageRow>
          <ErrorMessage error={members.error} compact onRetry={() => void members.refetch()} />
        </MessageRow>
      )}
      {expanded && items.map((e) => <QueueRow key={e.id} e={e} now={now} selection={selection} nested />)}
      {expanded && members.hasNextPage && (
        <MessageRow>
          <Button size="sm" busy={members.isFetchingNextPage} onClick={() => void members.fetchNextPage()}>
            Load more of {g.rule}
          </Button>
        </MessageRow>
      )}
    </>
  );
}

export function MessageRow({ children }: { children: ReactNode }) {
  return (
    <tr className="border-t border-subtle">
      <td colSpan={COLUMNS} className="px-3.5 py-2.5 pl-6">
        {children}
      </td>
    </tr>
  );
}

/** The table shell: the header checkbox selects (or clears) the rows shown, up to the bulk maximum. */
export function QueueTable({
  caption,
  rows,
  selection,
  children,
}: {
  caption: string;
  /** The individual rows shown (for the header checkbox). */
  rows: readonly EscalationOut[];
  selection: Selection;
  children: ReactNode;
}) {
  const box = useRef<HTMLInputElement>(null);
  const selectedCount = rows.filter((e) => selection.isSelected(e.id)).length;
  const all = rows.length > 0 && (selectedCount === rows.length || (selection.full && selectedCount > 0));
  useEffect(() => {
    if (box.current) box.current.indeterminate = selectedCount > 0 && !all;
  }, [selectedCount, all]);
  return (
    // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
    <div role="region" aria-label="Escalation queue" tabIndex={0} className="relative overflow-x-auto">
      <table className="w-full min-w-[980px] border-collapse text-ctl">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="text-left text-xs text-secondary">
            <th scope="col" className="w-8 py-2 pl-3.5 pr-1.5">
              {selection.enabled ? (
                <input
                  ref={box}
                  type="checkbox"
                  className="h-4 w-4 accent-accent"
                  aria-label="Select the escalations shown (at most 50)"
                  checked={all}
                  disabled={rows.length === 0}
                  onChange={(ev) => selection.set(ev.target.checked ? rows : rows.filter((e) => selection.isSelected(e.id)), ev.target.checked)}
                />
              ) : (
                <span className="sr-only">Select</span>
              )}
            </th>
            <th scope="col" className="w-32 px-2 py-2 font-medium">
              SLA
            </th>
            <th scope="col" className="w-24 px-2 py-2 font-medium">
              Severity
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              Escalation
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              Why it needs you
            </th>
            <th scope="col" className="w-28 px-2 py-2 font-medium">
              Routing
            </th>
            <th scope="col" className="w-12 px-2 py-2 font-medium">
              Level
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              Owner
            </th>
            <th scope="col" className="py-2 pl-2 pr-3.5">
              <span className="sr-only">Action</span>
            </th>
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
