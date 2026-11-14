/**
 * One escalation, decided here: the header (severity, SLA, owner, level,
 * routing), the claim or take-over banner, the investigation tabs, under
 * them the expected response plan of a true positive, and the decision
 * form. Deciding needs your claim: an unclaimed escalation offers
 * Claim, one claimed by someone else offers Take over to admins only (as
 * the API enforces).
 */

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Clock, Hand } from 'lucide-react';
import { useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';

import { ApiError } from '../../api/client';
import { endpoints } from '../../api/endpoints';
import { decidedByLabel, escalationConflictNotice, escalationOwner, escalationSeverity, escalationTitle, readRouting } from '../../api/fields';
import { useEscalation, useLivePollInterval } from '../../api/hooks';
import { afterEscalationChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import type { DecisionOut, EscalationOut } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can, decisionBlockedReason } from '../../auth/roles';
import { useToast } from '../../components/Toast';
import { Banner, Button, ErrorMessage, LoadingState, SeverityTag, cx } from '../../components/ui';
import { formatDateTime, formatRelative, shortId } from '../../lib/format';
import { alertsHref, escalationHref, escalationQueueHref } from '../../lib/links';
import { slaLabel, slaStatus } from '../../lib/sla';
import { useNow } from '../../lib/useNow';
import { DecisionForm } from './DecisionForm';
import { Investigation } from './Investigation';
import { bandLabel, decisionLabel, percent, routingLabel, routingSentence } from './labels';
import { findNextEscalation } from './nextEscalation';

const ACTIVE = new Set(['open', 'claimed', 'expired']);

/** Where "Escalations" in the page header leads: the queue the analyst came from, else the SLA-ordered queue. */
function useQueueHref(): string {
  const location = useLocation();
  const from = (location.state as { from?: unknown } | null)?.from;
  return typeof from === 'string' && from.startsWith('/escalations') ? from : escalationQueueHref({ order: 'sla_deadline' });
}

function SlaBadge({ e, now }: { e: EscalationOut; now: number }) {
  if (!ACTIVE.has(e.status)) return null;
  const s = slaStatus(e.sla_deadline, now, e.created_at);
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-control bg-raised-2 px-2.5 py-1 text-ctl tabular-nums',
        s.state === 'breaching' || s.state === 'at_risk' ? 'font-semibold text-warn' : 'text-body',
      )}
      title={e.sla_deadline ? `SLA deadline ${formatDateTime(e.sla_deadline)}` : undefined}
    >
      <Clock className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
      SLA {slaLabel(s)}
    </span>
  );
}

function Header({ e, now, queueHref }: { e: EscalationOut; now: number; queueHref: string }) {
  const { principal } = useAuth();
  const routing = readRouting(e.routing);
  const owner = escalationOwner(e, principal?.userId);
  const sentence = routingSentence(e.routing) ?? e.reason;
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 flex-col gap-1.5">
        <nav aria-label="Back" className="text-ctl">
          <Link to={queueHref} className="inline-flex items-center gap-1 text-link hover:text-link-hover hover:underline">
            <ArrowLeft className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
            Escalations
          </Link>
        </nav>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-secondary">
          <SeverityTag value={escalationSeverity(e)} className="font-semibold" />
          <span>
            <span className="sr-only">Level </span>
            {e.level}
          </span>
          <span className="font-mono" title={e.id}>
            <span className="sr-only">Escalation </span>
            {shortId(e.id)}
          </span>
          <Link to={alertsHref({ alert: e.alert_id })} className="text-link hover:text-link-hover hover:underline">
            Alert {shortId(e.alert_id)}
          </Link>
          <span>
            Owner: <span className={owner.kind === 'you' ? 'font-medium text-fg' : 'text-body'}>{owner.label}</span>
          </span>
          {routing && (
            <span>
              {routingLabel(routing.code)}
              {percent(routing.confidence) && <> · confidence {percent(routing.confidence)}</>}
              {bandLabel(routing) && <> ({bandLabel(routing)})</>}
            </span>
          )}
        </div>
        <h1 className="break-words text-xl font-semibold text-fg">{escalationTitle(e)}</h1>
        <p className="text-ctl text-body">{sentence}</p>
      </div>
      <SlaBadge e={e} now={now} />
    </div>
  );
}

/** Claimed by you, by someone else (take over for admins), unclaimed (claim), or closed. */
function ClaimState({ e, now }: { e: EscalationOut; now: number }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const { principal } = useAuth();
  const [busy, setBusy] = useState(false);
  const owner = escalationOwner(e, principal?.userId);

  if (!ACTIVE.has(e.status)) {
    const by = decidedByLabel(e, principal?.userId);
    return (
      <Banner tone="info" role="status" title={e.decision ? `Decided: ${decisionLabel(e.decision)}` : `This escalation is ${e.status}`}>
        {by && <>By {by}</>}
        {e.decided_at && <> on {formatDateTime(e.decided_at)}</>}
        {e.decision_notes && <p className="mt-1 whitespace-pre-wrap">{e.decision_notes}</p>}
      </Banner>
    );
  }

  const claim = async () => {
    setBusy(true);
    try {
      await endpoints.claim(api, e.id, e.version);
      toast.success(owner.kind === 'other' ? 'Escalation taken over.' : 'Escalation claimed.');
    } catch (err) {
      const notice = escalationConflictNotice(err, 'it has been reloaded');
      if (notice) toast.info(notice);
      else toast.error(err, 'Claim failed');
    } finally {
      setBusy(false);
      void afterEscalationChange(client);
    }
  };

  const mayClaim = can.claimEscalation(principal, e);
  if (owner.kind === 'you') {
    return <p className="text-ctl text-secondary">Claimed by you{e.claimed_at ? ` ${formatRelative(e.claimed_at, now)}` : ''}.</p>;
  }
  if (owner.kind === 'other') {
    return (
      <Banner
        tone="attention"
        role="status"
        title={`Claimed by ${owner.label}${e.claimed_at ? ` ${formatRelative(e.claimed_at, now)}` : ''}`}
        actions={
          mayClaim ? (
            <Button onClick={() => void claim()} busy={busy} icon={<Hand className="h-4 w-4" aria-hidden="true" />}>
              Take over
            </Button>
          ) : undefined
        }
      >
        {mayClaim ? 'Take over to record a decision; the change of owner is audited.' : 'Only they or an admin can record a decision.'}
      </Banner>
    );
  }
  return (
    <Banner
      tone="attention"
      role="status"
      title="Unassigned"
      actions={
        mayClaim ? (
          <Button variant="primary" size="lg" onClick={() => void claim()} busy={busy} icon={<Hand className="h-4 w-4" aria-hidden="true" />}>
            Claim
          </Button>
        ) : undefined
      }
    >
      {mayClaim ? 'Claim this escalation to record a decision.' : (decisionBlockedReason(principal) ?? 'You cannot claim this escalation.')}
    </Banner>
  );
}

/** Why the form is read-only, or null when the caller may record a decision now. */
function formBlockedReason(e: EscalationOut, principal: ReturnType<typeof useAuth>['principal']): string | null {
  const general = decisionBlockedReason(principal);
  if (general) return general;
  if (!e.assigned_to) return 'Claim the escalation to record a decision.';
  if (e.assigned_to !== principal?.userId) {
    return can.admin(principal) ? 'Take over the escalation to record a decision.' : 'Claimed by another analyst; only they or an admin can decide it.';
  }
  return null;
}

export default function DecisionPage() {
  const { id = '' } = useParams();
  const api = useApi();
  const navigate = useNavigate();
  const toast = useToast();
  const { principal } = useAuth();
  const queueHref = useQueueHref();
  const interval = useLivePollInterval();
  const now = useNow(1_000);
  const [planSlot, setPlanSlot] = useState<HTMLDivElement | null>(null);
  const q = useEscalation(id, { refetchInterval: interval });
  const e = q.data;
  const alert = useQuery({
    queryKey: qk.alert.detail(e?.alert_id ?? null),
    queryFn: ({ signal }) => endpoints.alert(api, e?.alert_id as string, signal),
    enabled: Boolean(e?.alert_id),
  });

  const onDecided = async (_out: DecisionOut, openNext: boolean) => {
    if (!openNext) return;
    try {
      const next = await findNextEscalation(api, principal, id);
      if (next) navigate(escalationHref(next), { state: { from: queueHref } });
      else {
        toast.info('No other escalation is waiting for you.');
        navigate(queueHref);
      }
    } catch (err) {
      toast.error(err, 'Could not open the next escalation');
    }
  };

  if (q.isPending) return <LoadingState label="Loading escalation" />;
  if (q.isError || !e) {
    const missing = q.error instanceof ApiError && q.error.status === 404;
    return (
      <div className="flex flex-col gap-4">
        <h1 className="text-xl font-semibold text-fg">{missing ? 'Escalation not found' : 'Escalation'}</h1>
        <ErrorMessage error={q.error} onRetry={missing ? undefined : () => void q.refetch()} />
        <Link to={queueHref} className="text-ctl text-link hover:text-link-hover hover:underline">
          Back to the escalation queue
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <Header e={e} now={now} queueHref={queueHref} />
      <ClaimState e={e} now={now} />
      <div className="flex flex-wrap items-start gap-5">
        <div className="flex min-w-0 flex-[999_1_520px] flex-col gap-5">
          <Investigation
            escalation={e}
            alert={alert.data}
            alertState={{ isPending: alert.isPending && alert.fetchStatus !== 'idle', error: alert.error, retry: () => void alert.refetch() }}
          />
          {/* The decision form shows the expected response plan here: this column has the room to name every target. */}
          <div ref={setPlanSlot} className="empty:hidden" />
        </div>
        {ACTIVE.has(e.status) && (
          <div className="w-full min-w-0 flex-[1_1_380px]">
            {/* A new form per escalation: "Record and open next" must not carry the verdict or the pre-approvals over. */}
            <DecisionForm key={e.id} escalation={e} planSlot={planSlot} disabledReason={formBlockedReason(e, principal)} onDecided={onDecided} />
          </div>
        )}
      </div>
    </div>
  );
}
