/**
 * The Overview: the analyst's own work first (unassigned and breaching
 * escalations, what they hold, approvals they can act on, the next SLA
 * deadlines), then the chosen window's figures, then (admins only) platform
 * health. Every figure says what it counts and over what window; means and
 * rates over fewer than MIN_SAMPLE observations read "Not enough data".
 */

import { ArrowRight, CircleCheck, Clock, RefreshCw, UserCheck } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { readQueueFigures, totalOf, type QueueFigures } from '../../api/fields';
import { useDashboardSummary, useLivePollInterval } from '../../api/hooks';
import type { DashboardOut } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { approvalRoleFor, can, roleAtLeast } from '../../auth/roles';
import { OnboardingBanner } from '../onboarding/Onboarding';
import { SetupCallout } from '../setup/SetupCallout';
import { Button, Card, ErrorMessage, LoadingState, PageHeader, Segmented, buttonClass, cx } from '../../components/ui';
import { formatInt, formatRelative, formatUsd } from '../../lib/format';
import { alertsHref, escalationQueueHref, APPROVALS_HREF } from '../../lib/links';
import { formatHours } from '../../lib/reports';
import { useNow } from '../../lib/useNow';
import { DEFAULT_WINDOW_HOURS, RISK_ORDER, WINDOWS, handledFigure, mttaFigure, mttrFigure, plural, windowPhrase } from './figures';
import { NextDeadlines, MostOverdue, MyClaimedList } from './EscalationPanels';
import { Breakdown, SeverityBar, StatusPipeline } from './charts';

function SectionHeading({ id, children }: { id: string; children: ReactNode }) {
  return (
    <h2 id={id} className="eyebrow">
      {children}
    </h2>
  );
}

/** The big number of a "needs you now" card and its qualifier. */
function Headline({ value, children }: { value: number; children?: ReactNode }) {
  return (
    <p className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
      <span className="text-display font-semibold tabular-nums text-fg">{formatInt(value)}</span>
      {children}
    </p>
  );
}

function CardLink({ to, primary = false, children }: { to: string; primary?: boolean; children: ReactNode }) {
  return (
    <Link to={to} className={buttonClass(primary ? 'primary' : 'secondary', 'md', 'self-start')}>
      {children}
      {primary && <ArrowRight className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />}
    </Link>
  );
}

function UnassignedCard({ queue, now, interval }: { queue: QueueFigures; now: number; interval: number | false }) {
  const { principal } = useAuth();
  const breaching = queue.unassignedBreaching;
  const claimer = can.claim(principal);
  return (
    <Card variant={breaching > 0 ? 'attention' : 'default'} className="flex flex-col">
      <div className="flex flex-col gap-2.5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <Clock className={cx('h-4 w-4', breaching > 0 ? 'text-state-waiting' : 'text-secondary')} strokeWidth={1.75} aria-hidden="true" />
          Unassigned escalations
        </h3>
        <Headline value={queue.unassigned}>
          {breaching > 0 ? (
            <span className="font-semibold text-warn">{formatInt(breaching)} breaching SLA</span>
          ) : (
            <span className="text-secondary">none breaching SLA</span>
          )}
        </Headline>
        <p className="text-xs text-muted">Open or claimed escalations nobody holds, right now.</p>
        {breaching > 0 && <MostOverdue now={now} interval={interval} />}
        {queue.unassigned > 0 &&
          (breaching > 0 ? (
            <CardLink to={escalationQueueHref({ assigned_to: 'none', overdue: true, order: 'sla_deadline' })} primary={claimer}>
              Triage breaching first
            </CardLink>
          ) : (
            <CardLink to={escalationQueueHref({ assigned_to: 'none', order: 'sla_deadline' })}>Open the unassigned queue</CardLink>
          ))}
      </div>
    </Card>
  );
}

function MyClaimedCard({ queue, now, interval }: { queue: QueueFigures; now: number; interval: number | false }) {
  return (
    <Card className="flex flex-col">
      <div className="flex flex-col gap-2.5">
        <h3 className="text-sm font-semibold text-fg">My claimed escalations</h3>
        <Headline value={queue.myClaimed}>
          <span className="text-secondary">{queue.myClaimed > 0 ? 'open or claimed by you, soonest SLA first' : 'open or claimed by you'}</span>
        </Headline>
        {queue.myClaimed > 0 ? (
          <MyClaimedList now={now} interval={interval} total={queue.myClaimed} />
        ) : (
          <p className="text-ctl text-body">You hold no escalations. Claim one from the queue to see it here.</p>
        )}
        <CardLink to={escalationQueueHref({ assigned_to: 'me', order: 'sla_deadline' })}>Open my queue</CardLink>
      </div>
    </Card>
  );
}

function ApprovalsCard({ queue }: { queue: QueueFigures }) {
  const { principal } = useAuth();
  const isAdmin = can.admin(principal);
  const mine = queue.pendingMine;
  const adminOnly = isAdmin
    ? 0
    : Object.entries(queue.pendingByRisk).reduce((sum, [risk, n]) => sum + (approvalRoleFor(risk) === 'admin' ? n : 0), 0);
  const risks = [...RISK_ORDER.filter((r) => queue.pendingByRisk[r]), ...Object.keys(queue.pendingByRisk).filter((r) => !(RISK_ORDER as readonly string[]).includes(r) && queue.pendingByRisk[r])];
  return (
    <Card variant={mine > 0 ? 'approval' : 'default'} className="flex flex-col">
      <div className="flex flex-col gap-2.5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <UserCheck className={cx('h-4 w-4', mine > 0 ? 'text-state-approval' : 'text-secondary')} strokeWidth={1.75} aria-hidden="true" />
          Approvals you can act on
        </h3>
        <Headline value={mine}>
          <span className="text-secondary">
            of {formatInt(queue.pendingTotal)} pending
            {adminOnly > 0 && <> · {plural(adminOnly, 'needs an admin', 'need an admin')}</>}
          </span>
        </Headline>
        <p className="text-xs text-muted">Response actions waiting for a human, right now; yours under the autonomy policy.</p>
        {risks.length > 0 && (
          <ul className="flex flex-wrap gap-x-4 gap-y-1 text-ctl text-body" aria-label="Pending approvals by risk">
            {risks.map((r) => (
              <li key={r}>
                <span className="text-secondary"><span className="capitalize">{r}</span> risk</span> <span className="font-semibold tabular-nums text-fg">{formatInt(queue.pendingByRisk[r])}</span>
              </li>
            ))}
          </ul>
        )}
        {queue.pendingTotal > 0 ? (
          <CardLink to={APPROVALS_HREF}>Review approvals</CardLink>
        ) : (
          <p className="flex items-center gap-1.5 text-ctl text-body">
            <CircleCheck className="h-4 w-4 text-state-ok" strokeWidth={1.75} aria-hidden="true" />
            Nothing waiting for approval.
          </p>
        )}
      </div>
    </Card>
  );
}

function Kpi({ label, value, sub, to }: { label: string; value: string; sub: string; to?: string }) {
  return (
    // A subgrid of the row: labels, values and notes line up across the tiles even when a label wraps.
    <div className="row-span-3 grid min-w-0 grid-rows-subgrid gap-1 rounded-card border border-subtle bg-raised px-4 py-3.5">
      <dt className="text-xs text-secondary">{to ? <Link to={to} className="text-secondary hover:text-fg hover:underline">{label}</Link> : label}</dt>
      <dd className="text-2xl font-semibold tabular-nums text-fg">{value}</dd>
      <dd className="text-xs text-muted">{sub}</dd>
    </div>
  );
}

function WindowFigures({ d, queue, phrase }: { d: DashboardOut; queue: QueueFigures | null; phrase: string }) {
  const handled = handledFigure(d, phrase);
  const mtta = mttaFigure(d, phrase);
  const mttr = mttrFigure(d, phrase);
  const since = { from: d.since };
  return (
    <dl className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <Kpi label="Alerts ingested" value={formatInt(d.alerts_total)} sub={`In ${phrase}`} to={alertsHref(since)} />
      <Kpi
        label="Open escalations"
        value={formatInt(d.open_escalations)}
        sub={queue ? `Right now · ${formatInt(queue.overdue)} past SLA` : 'Right now'}
        to={escalationQueueHref({ order: 'sla_deadline' })}
      />
      {queue && (
        <Kpi
          label="Pending approvals"
          value={formatInt(queue.pendingTotal)}
          sub={`Right now · ${formatInt(queue.pendingMine)} you can approve`}
          to={APPROVALS_HREF}
        />
      )}
      <Kpi label="Handled without a human" value={handled.value} sub={handled.sub} />
      <Kpi label="Mean time to acknowledge" value={mtta.value} sub={mtta.sub} />
      <Kpi label="Mean time to resolve" value={mttr.value} sub={mttr.sub} />
    </dl>
  );
}

function AdminFigures({ d, phrase }: { d: DashboardOut; phrase: string }) {
  const finished = (d.handled_without_human ?? 0) + (d.needed_human ?? 0);
  return (
    <section aria-labelledby="ov-admin" className="flex flex-col gap-3">
      <SectionHeading id="ov-admin">Platform health · admins only</SectionHeading>
      <dl className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <Kpi label="Queue depth" value={formatInt(d.queue_depth)} sub="Workflow runs waiting to start, right now" />
        <Kpi
          label="LLM cost"
          value={formatUsd(d.llm_cost_usd)}
          sub={`${formatInt(d.llm_tokens)} tokens in ${phrase}${d.llm_model ? ` · ${d.llm_model}` : d.llm_model === null ? ' · LLM use is off' : ''}`}
          to="/usage"
        />
        <Kpi
          label="Analyst hours saved"
          value={formatHours(d.analyst_hours_saved ?? 0)}
          sub={`Estimate over ${formatInt(finished)} finished alerts: ${formatInt(d.minutes_per_alert ?? 15)} min per handled alert`}
          to="/reports"
        />
      </dl>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-3 lg:grid-cols-2">
        <Breakdown
          title="Worker health"
          meta="Workflow runs not finished yet, by status, right now"
          counts={d.runs_by_status}
          order={['queued', 'running', 'waiting', 'retrying']}
          empty="No workflow run is waiting or running."
        />
        <Breakdown
          title="Alert disposition"
          meta={`Alerts ingested in ${phrase}, by automated disposition`}
          counts={d.by_disposition}
          order={['malicious', 'benign', 'inconclusive']}
          linkFor={(k) => alertsHref({ disposition: k, from: d.since })}
          empty="No disposition recorded in this window."
        />
      </div>
    </section>
  );
}

export default function OverviewPage() {
  const { principal } = useAuth();
  const isAdmin = can.admin(principal);
  const [windowHours, setWindowHours] = useState(DEFAULT_WINDOW_HOURS);
  const interval = useLivePollInterval();
  const q = useDashboardSummary(windowHours, { refetchInterval: interval });
  const now = useNow(30_000);
  const d = q.data;
  const queue = readQueueFigures(d);
  const phrase = windowPhrase(windowHours);
  const analyst = roleAtLeast(principal?.role, 'analyst');

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          <>
            Your work first, then {phrase}.
            {d && (
              <>
                {' '}
                <span role="status">Updated {formatRelative(d.generated_at, now)}.</span>
              </>
            )}
          </>
        }
        actions={
          <>
            <Segmented
              label="Time window"
              options={WINDOWS.map((w) => ({ value: w.hours, label: w.short, title: w.phrase.replace(/^the l/, 'L') }))}
              value={windowHours}
              onChange={setWindowHours}
            />
            <Button
              aria-label="Refresh"
              title="Refresh"
              onClick={() => void q.refetch()}
              busy={q.isFetching}
              icon={<RefreshCw className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />}
            />
          </>
        }
      />
      {can.setup(principal) && <SetupCallout />}
      {isAdmin && <OnboardingBanner />}
      {q.isPending && <LoadingState label="Loading the overview" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {d && (
        <div className="flex flex-col gap-6">
          {queue && (
            <section aria-labelledby="ov-now" className="flex flex-col gap-3">
              <SectionHeading id="ov-now">Needs you now</SectionHeading>
              <div className="grid grid-cols-[repeat(auto-fit,minmax(min(300px,100%),1fr))] gap-3">
                <UnassignedCard queue={queue} now={now} interval={interval} />
                {can.claim(principal) && <MyClaimedCard queue={queue} now={now} interval={interval} />}
                {analyst && <ApprovalsCard queue={queue} />}
              </div>
            </section>
          )}

          <section aria-labelledby="ov-window" className="flex flex-col gap-3">
            <SectionHeading id="ov-window">{phrase.replace(/^the l/, 'L')}</SectionHeading>
            <WindowFigures d={d} queue={queue} phrase={phrase} />
            {d.alerts_total === 0 && (
              <p className="rounded-control border border-subtle bg-raised px-4 py-3 text-ctl text-secondary">
                No alerts were ingested in {phrase}.{' '}
                {isAdmin ? 'Connect a source under Sources or send alerts to the ingest API.' : 'Figures appear as alerts arrive.'}
              </p>
            )}
          </section>

          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(420px,100%),1fr))] gap-3">
            {queue && (
              <SeverityBar
                id="ov-esc-sev"
                title="Open escalations by severity"
                meta={`Right now · ${plural(totalOf(queue.openBySeverity), 'open or claimed escalation', 'open or claimed escalations')}`}
                counts={queue.openBySeverity}
              />
            )}
            <SeverityBar
              id="ov-alert-sev"
              title="Alert severity"
              meta={`${plural(d.alerts_total, 'alert', 'alerts')} ingested in ${phrase}`}
              counts={d.by_severity}
              linkFor={(sev) => alertsHref({ severity: sev, from: d.since })}
            />
          </div>

          <StatusPipeline
            title={`Alerts from ${phrase} by current status`}
            counts={d.by_status}
            linkFor={(status) => alertsHref({ status, from: d.since })}
          />

          {queue && <NextDeadlines queue={queue} now={now} interval={interval} />}

          {isAdmin && <AdminFigures d={d} phrase={phrase} />}
        </div>
      )}
    </>
  );
}
