/**
 * The preview beside the list: the highlighted row in full, from the fields
 * the list already holds (no request of its own), with Open and Claim.
 */

import { useQueryClient } from '@tanstack/react-query';
import { useCallback, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { escalationConflictNotice, escalationOwner, escalationSeverity, escalationTitle, formatEntities, readAiReason } from '../../api/fields';
import { afterEscalationChange } from '../../api/invalidate';
import type { EscalationOut } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { useToast } from '../../components/Toast';
import { cx } from '../../components/ui';
import { formatDuration, shortId } from '../../lib/format';
import { escalationHref } from '../../lib/links';
import { QButton, qbuttonClass } from './controls';
import { OutcomeMark, SeverityBars } from './marks';
import { dueIn, lookAlike, rowOutcome, rowReason } from './model';

/** Claim one item (or, for an admin, take it over); the lists refresh whatever the answer. */
export function useClaim() {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const { principal } = useAuth();
  const [busy, setBusy] = useState(false);
  const claim = useCallback(
    async (e: EscalationOut) => {
      if (!can.claimEscalation(principal, e)) {
        toast.info(escalationOwner(e, principal?.userId).kind === 'you' ? 'You already own this item.' : 'Already owned. Taking over needs the owner or an admin.');
        return;
      }
      setBusy(true);
      try {
        await endpoints.claim(api, e.id, e.version);
        toast.success(`Claimed: ${escalationTitle(e)}. It is in Mine.`);
      } catch (err) {
        const notice = escalationConflictNotice(err, 'the queue has been refreshed');
        if (notice) toast.info(notice);
        else toast.error(err, 'Claim failed');
      } finally {
        setBusy(false);
        void afterEscalationChange(client);
      }
    },
    [api, client, principal, toast],
  );
  return { claim, busy };
}

export function PreviewPane({
  row,
  now,
  maxHeight,
  onClaim,
  claiming,
}: {
  row: EscalationOut | null;
  now: number;
  maxHeight: string;
  onClaim: (row: EscalationOut) => void;
  claiming: boolean;
}) {
  const { principal } = useAuth();
  return (
    <aside aria-label="Preview of the highlighted row" style={{ maxHeight }} className="overflow-y-auto border-l border-strong py-3.5 pl-[18px]">
      {row ? <Preview e={row} now={now} canClaim={can.claimEscalation(principal, row)} userId={principal?.userId ?? null} onClaim={onClaim} claiming={claiming} /> : <p className="text-ctl text-muted">No row is highlighted.</p>}
    </aside>
  );
}

function Preview({ e, now, canClaim, userId, onClaim, claiming }: { e: EscalationOut; now: number; canClaim: boolean; userId: string | null; onClaim: (row: EscalationOut) => void; claiming: boolean }) {
  const title = escalationTitle(e);
  const ai = readAiReason(e);
  const reason = rowReason(e);
  const severity = escalationSeverity(e);
  const due = dueIn(e.sla_deadline, now);
  const owner = escalationOwner(e, userId);
  const entities = formatEntities(e.entities_preview, 6);
  const group = lookAlike(e);
  const related = e.related_alert_ids?.length ?? 0;
  const created = new Date(e.created_at).getTime();
  const waited = Number.isNaN(created) ? null : Math.max(0, (now - created) / 1000);
  const facts: Array<[string, ReactNode]> = [
    ['Why it is here', reason ?? '-'],
    ['Entities', entities ? <span className="break-words font-mono text-xs">{entities}</span> : 'None extracted'],
    ['Rule', e.rule ?? '-'],
    ['Source', e.source_name ?? '-'],
    ['Attached', related ? `${related} more alert${related === 1 ? ' waits' : 's wait'} on this decision` : 'No other alert'],
    ...(group ? ([['Look-alikes', `${group.size} alerts: same rule, same source, same finding`]] as Array<[string, ReactNode]>) : []),
    ['Level', e.level],
    ['Owner', owner.label],
    ['Waiting', waited === null ? '-' : formatDuration(waited)],
  ];
  return (
    <>
      <OutcomeMark outcome={rowOutcome(e)} text="long" className="text-[12.5px]" />
      <h2 className="mb-0.5 mt-1.5 text-[15px] font-semibold leading-[1.3] text-fg">{title}</h2>
      <p className="mb-2.5 flex flex-wrap items-center gap-x-1.5 text-xs text-muted">
        <span className="font-mono" title={`Alert ${e.alert_id}`}>
          {shortId(e.alert_id)}
        </span>
        <span aria-hidden="true">·</span>
        <SeverityBars value={severity} className="!font-normal !text-muted" />
        <span aria-hidden="true">·</span>
        <span className={cx(due.state === 'overdue' || due.state === 'soon' ? 'font-semibold text-danger-fg' : undefined)}>{due.label}</span>
      </p>
      <p className="my-2 text-[14.5px] leading-[1.4] text-fg">{ai?.text ?? reason ?? 'The analysis left no summary.'}</p>
      {ai?.source && <p className="text-xs text-muted">Written by the {ai.source === 'model' ? 'model' : 'rules'}.</p>}
      <dl className="mt-2.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-[3px] text-[12.5px]">
        {facts.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted">{label}</dt>
            <dd className="min-w-0 break-words text-body">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-3 flex flex-wrap gap-2">
        <Link to={escalationHref(e)} className={qbuttonClass('primary')}>
          Open <kbd className="border-on-accent/50 text-on-accent">Enter</kbd>
        </Link>
        {canClaim && (
          <QButton busy={claiming} onClick={() => onClaim(e)}>
            {owner.kind === 'other' ? 'Take over' : 'Claim'} <kbd>C</kbd>
          </QButton>
        )}
      </div>
    </>
  );
}
