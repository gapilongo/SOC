/**
 * The case page (/cases/:key): one case, its alerts, and who or what closed
 * each one and why. It answers "what did the AI close on this host while
 * this case was open, and why" on one page.
 *
 * A case is today's escalation with its alerts, and its key is the
 * escalation's id. The page renders the case read model
 * (`GET /cases/{id}`, see useCase.ts):
 *
 *   the header     the state, the severity, the deadline and the owner
 *   the alerts     oldest first, each with its state, who or what closed it
 *                  and the recorded reason
 *   the safety net alerts the AI closed that were linked and left closed,
 *                  and those that were reopened, with what reopened them
 *   the response   the actions on the ledger with their status; one that
 *                  waits is approved or rejected here, by the Approvals rules
 *   the timeline   the case's and its alerts' events, merged
 *   the decision   the decision bar of the investigation view
 *
 * What the read model lists in `not_available` is said on the page in its
 * own words, and nothing is shown in its place. J and K move through the
 * alerts and Enter opens one; they obey the console's single-key switch.
 */

import { useQueryClient } from '@tanstack/react-query';
import { useId, useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { ApiError } from '../../../../api/client';
import { useTenantLabel } from '../../api/hooks';
import { afterEscalationChange } from '../../api/invalidate';
import type { CaseActionOut, CaseAlertOut, CaseOut, CasePersonOut, CaseTimelineEntryOut, ProposedActionOut } from '../../api/types';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';
import { AlertWhy, ClosedBy, CloserMark, decisionWords, reopenedByPerson, type CloserKind } from '../../components/case';
import { FactChip, Keycap, OutcomeTag, SeverityBars, SmallTag, StepList, VoiceTag } from '../../components/investigation';
import { clockOf } from '../../components/investigation/clock';
import { useToast } from '../../../../components/Toast';
import { Banner, Button, ErrorMessage, LoadingState, buttonClass, cx } from '../../../../components/ui';
import { formatDateTime, formatRelative, humanize, shortId } from '../../../../lib/format';
import { APPROVALS_HREF, QUEUE_HREF, alertHref, alertsHref, caseHref } from '../../lib/links';
import { ApprovalDialog, type DecidableAction, type PendingDecision } from '../actions/ApprovalDialog';
import { approvalAccess } from '../approvals/approvals';
import { findNextEscalation } from '../escalations/nextEscalation';
import { SlaChip, blockedReason, useClaim } from '../investigation/claim';
import { DecisionDock } from '../investigation/DecisionDock';
import { isSingleKey, useKeydown, useSingleKeys } from '../investigation/keys';
import { ResponseTable } from '../investigation/ResponseTable';
import { ReopenDialog, type PendingReopen } from './ReopenDialog';
import { useCase } from './useCase';

const LINK = 'text-link underline hover:text-link-hover';
const SMALL = 'block text-xs text-muted';
const NONE: ReadonlySet<string> = new Set();
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** A section of the page: its heading over a rule, a note beside it, then the content. */
function Section({ title, note, right, children, className }: { title: string; note?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={cx('min-w-0 pt-5', className)}>
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-strong pb-2">
        <h2 id={id} className="text-base font-semibold leading-5 text-fg">
          {title}
        </h2>
        {note && <span className="text-ctl text-muted">{note}</span>}
        {right && <span className="ml-auto flex flex-wrap items-center gap-x-3.5 gap-y-1">{right}</span>}
      </div>
      {children}
    </section>
  );
}

/** "9 alerts: 3 with a person, 1 being investigated, 5 closed." */
export function statement(counts: Pick<CaseOut['counts'], 'alerts' | 'open' | 'processing' | 'closed'>): string {
  const parts = [
    counts.open > 0 ? `${counts.open} with a person` : null,
    counts.processing > 0 ? `${counts.processing} being investigated` : null,
    counts.closed > 0 ? `${counts.closed} closed` : null,
  ].filter((part): part is string => part !== null);
  return `${plural(counts.alerts, 'alert', 'alerts')}${parts.length > 0 ? `: ${parts.join(', ')}` : ''}.`;
}

/** A person the read model names: "you", the e-mail, else a short id. */
export function personLabel(person: CasePersonOut | null, userId: string | null | undefined): string | null {
  if (!person) return null;
  if (userId && person.user_id === userId) return 'you';
  return person.email ?? shortId(person.user_id);
}

// The header ----------------------------------------------------------------------------

/** Where the case stands: what it waits for while it is open, else the decision. */
function CaseState({ c }: { c: CaseOut }) {
  if (c.active) {
    if (c.category === 'needs_decision') return <OutcomeTag kind="needs_decision" />;
    if (c.category === 'needs_review') return <OutcomeTag kind="needs_review" />;
    return <VoiceTag voice="decided">Open</VoiceTag>;
  }
  if (c.decision) return <VoiceTag voice="person">Decided: {decisionWords(c.decision.decision)}</VoiceTag>;
  return <VoiceTag voice="decided">{humanize(c.status)}</VoiceTag>;
}

const DT = 'font-mono text-2xs font-medium uppercase leading-snug tracking-label text-muted';

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className={DT}>{label}</dt>
      <dd className="break-words text-ctl font-medium text-fg">{children}</dd>
    </div>
  );
}

function Facts({ c, userId }: { c: CaseOut; userId: string | null | undefined }) {
  const owner = c.owner ? (personLabel(c.owner, userId) ?? '') : null;
  const waiting = c.counts.actions_awaiting_approval;
  return (
    <dl className="flex flex-wrap gap-x-7 gap-y-1.5 border-y border-b-subtle border-t-strong py-2.5">
      <Fact label="Owner">
        {owner ? (
          <>
            {owner === 'you' ? 'You' : owner}
            {c.owner?.since && <span className="font-normal text-secondary">, since {formatDateTime(c.owner.since)}</span>}
          </>
        ) : (
          'Unassigned'
        )}
      </Fact>
      <Fact label="Opened">
        <time dateTime={c.opened_at}>{formatDateTime(c.opened_at)}</time>
        <span className="font-normal text-secondary">, {formatRelative(c.opened_at)}</span>
      </Fact>
      {c.active && c.sla_deadline && (
        <Fact label="Deadline">
          <time dateTime={c.sla_deadline}>{formatDateTime(c.sla_deadline)}</time>
        </Fact>
      )}
      <Fact label="Response">
        {c.actions.length === 0 ? (
          <span className="font-normal text-secondary">No action is recorded</span>
        ) : waiting > 0 ? (
          <a href="#case-response" className={LINK}>
            {plural(waiting, 'action waits', 'actions wait')} for an approval
          </a>
        ) : (
          <a href="#case-response" className={LINK}>
            {plural(c.actions.length, 'action', 'actions')}, none waits
          </a>
        )}
      </Fact>
      {c.reason && (
        <div className="min-w-0 basis-full">
          <dt className={DT}>{c.active ? 'Why it is with a person' : 'Why it was with a person'}</dt>
          <dd className="max-w-[62em] text-ctl text-body">{c.reason.sentence}</dd>
        </div>
      )}
    </dl>
  );
}

// The alerts ------------------------------------------------------------------------------

const TH = 'whitespace-nowrap px-2.5 py-1.5 text-left first:pl-0';
const TD = 'block px-0 py-0.5 align-top text-ctl min-[900px]:table-cell min-[900px]:border-b min-[900px]:border-subtle min-[900px]:px-2.5 min-[900px]:py-1.5 min-[900px]:first:pl-0';

/** The column name before a value, for the stacked records of a narrow screen. */
function Label({ children }: { children: string }) {
  return <span className="mr-2 inline-block min-w-[92px] font-mono text-2xs font-medium uppercase tracking-label text-muted min-[900px]:hidden">{children}</span>;
}

/** The time of an alert; its day too when that is not the day the case was opened. */
function When({ at, day }: { at: string; day: string | undefined }) {
  const clock = clockOf(at);
  return (
    <time dateTime={at} title={formatDateTime(at)} className="font-mono text-2xs leading-normal text-muted">
      {clock && clock.day !== day && <span className="mr-1.5 min-[900px]:mr-0 min-[900px]:block">{clock.day}</span>}
      {clock?.time ?? at}
    </time>
  );
}

/** Ask to reopen or flag an alert; null when the person may not (the API would refuse a viewer). */
type AskReopen = ((pending: PendingReopen) => void) | null;

function AlertRow({ alert, c, userId, ask }: { alert: CaseAlertOut; c: CaseOut; userId: string | null | undefined; ask: AskReopen }) {
  const open = alert.state !== 'closed';
  return (
    <tr
      data-alert={alert.id}
      data-role={alert.role}
      data-state={alert.state}
      className={cx(
        'block border-b border-strong py-2.5 focus-within:bg-selected min-[900px]:table-row min-[900px]:border-0 min-[900px]:py-0',
        open && 'min-[900px]:bg-raised-2/60',
      )}
    >
      <td className={cx(TD, 'min-[900px]:whitespace-nowrap')}>
        <Label>Time</Label>
        <When at={alert.occurred_at} day={clockOf(c.opened_at)?.day} />
      </td>
      <td className={cx(TD, 'min-[900px]:whitespace-nowrap')}>
        <Label>Severity</Label>
        <SeverityBars value={alert.severity} />
      </td>
      <td className={TD}>
        <Link to={alertHref(alert.id)} data-case-alert className="break-words font-medium text-fg hover:underline">
          {alert.title}
        </Link>
        <small className={cx(SMALL, 'break-all font-mono text-2xs')}>
          <span title={alert.id}>{shortId(alert.id)}</span>
          {alert.entities.map((e) => (
            <span key={`${e.kind}:${e.value}`}> · {e.value}</span>
          ))}
        </small>
        {alert.role === 'primary' && c.alerts.length > 1 && <small className={SMALL}>The case was opened for this alert.</small>}
      </td>
      <td className={TD}>
        <Label>{open ? 'State' : 'Closed by'}</Label>
        <span className="inline-block align-top">
          <ClosedBy alert={alert} userId={userId} />
        </span>
      </td>
      <td className={cx(TD, 'text-body min-[900px]:max-w-[34em]')}>
        <Label>Why</Label>
        <span className="inline-block max-w-full align-top">
          <AlertWhy alert={alert} caseId={c.id} />
        </span>
      </td>
      <td className={cx(TD, 'min-[900px]:whitespace-nowrap min-[900px]:text-right')}>
        {alert.can_reopen && ask && (
          <span className="flex flex-wrap items-center gap-1.5 pt-1 min-[900px]:justify-end min-[900px]:pt-0">
            <Button size="sm" onClick={() => ask({ alert, verb: 'reopen' })}>
              Reopen<span className="sr-only">: {alert.title}</span>
            </Button>
            <Button size="sm" variant="quiet" onClick={() => ask({ alert, verb: 'flag' })}>
              Flag<span className="sr-only">: {alert.title}</span>
            </Button>
          </span>
        )}
      </td>
    </tr>
  );
}

function Alerts({ c, userId, ask }: { c: CaseOut; userId: string | null | undefined; ask: AskReopen }) {
  const id = useId();
  const reopenable = c.alerts.some((a) => a.can_reopen);
  return (
    <section aria-labelledby={id} className="pt-5">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 pb-2">
        <h2 id={id} className="text-base font-semibold leading-5 text-fg">
          Alerts in this case
        </h2>
        <span className="text-ctl text-muted">
          {plural(c.alerts.length, 'alert', 'alerts')}, oldest first, with who or what closed each one and the recorded reason.
          {c.alerts_truncated && ` The case has ${c.counts.alerts}: the newest ${c.alerts.length - 1} that joined are listed with the alert it was opened for.`}
        </span>
        <span className="ml-auto hidden items-center gap-1.5 text-xs text-muted min-[900px]:flex">
          <Keycap>J</Keycap>
          <Keycap>K</Keycap> move <Keycap>Enter</Keycap> opens the alert
        </span>
      </div>
      <table data-rows="free" aria-labelledby={id} className="block w-full border-collapse border-t border-strong min-[900px]:table min-[900px]:border-t-0">
        <thead className="sr-only min-[900px]:not-sr-only min-[900px]:table-header-group">
          <tr>
            <th scope="col" className={TH}>
              Time
            </th>
            <th scope="col" className={TH}>
              Severity
            </th>
            <th scope="col" className={TH}>
              Alert
            </th>
            <th scope="col" className={TH}>
              State and closed by
            </th>
            <th scope="col" className={TH}>
              Why
            </th>
            <th scope="col" className={TH}>
              <span className="sr-only">Reopen or flag</span>
            </th>
          </tr>
        </thead>
        <tbody className="block min-[900px]:table-row-group">
          {c.alerts.map((alert) => (
            <AlertRow key={alert.id} alert={alert} c={c} userId={userId} ask={ask} />
          ))}
        </tbody>
      </table>
      {reopenable && (
        <p data-reopen-note className="max-w-[62em] pt-2 text-xs text-muted">
          {ask
            ? 'Reopen puts an alert the AI closed on the model’s word back in front of a person and stops the AI from closing it that way again. Flag does the same and records that the close was wrong. Both ask for a reason.'
            : 'An analyst can reopen an alert the AI closed on the model’s word, or flag the close as wrong.'}
        </p>
      )}
    </section>
  );
}

// The safety net ----------------------------------------------------------------------------

const MODE_WORDS: Record<string, string> = {
  folded: 'It joined this case: the decision on the case settles it.',
  requeued: 'A new run reviews it on its own.',
};

/** The alert as a link by its title, for the lists that name alerts of the case. */
function AlertRef({ alert }: { alert: CaseAlertOut }) {
  return (
    <Link to={alertHref(alert.id)} className="break-words font-medium text-fg hover:underline">
      {alert.title}
    </Link>
  );
}

function SafetyNet({ c, userId }: { c: CaseOut; userId: string | null | undefined }) {
  const linked = c.alerts.filter((a) => a.role === 'linked' && a.link);
  // What the safety net reopened; an alert a person reopened or flagged says so in its own row.
  const reopened = c.alerts.filter((a) => a.role === 'reopened' && a.reopened && !reopenedByPerson(a.reopened));
  if (linked.length === 0 && reopened.length === 0) return null;
  return (
    <Section title="Linked by the safety net" note="Alerts the AI closed on the model's word that share a host, a user or an address with this case.">
      {linked.length > 0 && (
        <div data-linked className="pt-3">
          <h3 className="text-ctl font-semibold text-fg">{plural(linked.length, 'alert is', 'alerts are')} linked and left closed</h3>
          <ul className="mt-1.5">
            {linked.map((a) => (
              <li key={a.id} data-linked-alert={a.id} className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 border-b border-subtle py-1 text-ctl">
                <SmallTag>Linked</SmallTag>
                <AlertRef alert={a} />
                <span className="text-xs text-muted">
                  {a.link?.at ? `linked ${formatDateTime(a.link.at)}` : 'linked'}
                  {a.link?.threat_alert_id && a.link.threat_alert_id !== c.alert_id && (
                    <>
                      {' '}
                      to the threat{' '}
                      <Link to={alertHref(a.link.threat_alert_id)} className={cx('font-mono', LINK)} title={a.link.threat_alert_id}>
                        {shortId(a.link.threat_alert_id)}
                      </Link>
                    </>
                  )}
                  {' · stays closed'}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {reopened.length > 0 && (
        <div data-reopened className="pt-3">
          <h3 className="text-ctl font-semibold text-fg">{plural(reopened.length, 'alert was', 'alerts were')} reopened</h3>
          <ul className="mt-1.5">
            {reopened.map((a) => {
              const r = a.reopened;
              const by = personLabel(r?.by ?? null, userId);
              return (
                <li key={a.id} data-reopened-alert={a.id} className="border-b border-subtle py-1.5 text-ctl">
                  <span className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
                    <SmallTag tone="warn">Reopened</SmallTag>
                    <AlertRef alert={a} />
                    <span className="text-xs text-muted">
                      {r?.at ? formatDateTime(r.at) : 'time not recorded'}
                      {by && ` · confirmed by ${by}`}
                    </span>
                  </span>
                  <span className="mt-0.5 block max-w-[62em] text-body">
                    {r?.reason.sentence} {r?.mode ? (MODE_WORDS[r.mode] ?? '') : ''}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </Section>
  );
}

// The response --------------------------------------------------------------------------------

function decidable(a: CaseActionOut): DecidableAction | null {
  if (!a.action_id) return null;
  const verdict = a.guardrail?.verdict === 'passed' ? ('passed' as const) : a.guardrail?.verdict === 'blocked' ? ('blocked' as const) : null;
  return {
    id: a.action_id,
    alert_id: a.alert_id,
    action_type: a.action_type,
    target: a.target,
    risk_level: a.risk,
    guardrail: a.guardrail && verdict ? { verdict, evaluated: 'now', code: a.guardrail.code, reason: a.guardrail.reason } : null,
    reversible: a.reversible,
    irreversible_note: a.irreversible_note,
  };
}

function Response({ c, onDecided }: { c: CaseOut; onDecided: () => void }) {
  const { principal } = useAuth();
  const [pending, setPending] = useState<PendingDecision | null>(null);
  const titles = new Map(c.alerts.map((a) => [a.id, a.title]));
  const under = (shown: ProposedActionOut) => {
    const a = shown as CaseActionOut;
    const action = a.status === 'awaiting_approval' ? decidable(a) : null;
    const access = action ? approvalAccess(principal, action) : null;
    const name = `${humanize(a.action_type)} on ${a.target}`;
    return (
      <>
        {c.alerts.length > 1 && titles.has(a.alert_id) && (
          <small className={SMALL}>
            For{' '}
            <Link to={alertHref(a.alert_id)} className={LINK}>
              {titles.get(a.alert_id)}
            </Link>
          </small>
        )}
        {action && access && (access.approve || access.reject || access.lock) && (
          <span className="mt-1 flex flex-wrap items-center gap-1.5">
            {access.approve && (
              <Button size="sm" variant="primary" onClick={() => setPending({ action, verb: 'approve' })}>
                Approve<span className="sr-only">: {name}</span>
              </Button>
            )}
            {access.reject && (
              <Button size="sm" onClick={() => setPending({ action, verb: 'reject' })}>
                Reject<span className="sr-only">: {name}</span>
              </Button>
            )}
            {access.lock && <span className="text-xs text-muted">{access.lock}</span>}
          </span>
        )}
      </>
    );
  };
  return (
    <div id="case-response" className="scroll-mt-20">
      <Section
        title="Response"
        note={
          <>
            The actions the workflow recorded for the alerts of this case, each with its status. All that wait are also in{' '}
            <Link to={APPROVALS_HREF} className={LINK}>
              Approvals
            </Link>
            .
          </>
        }
      >
        {c.actions.length === 0 ? (
          <p className="py-3 text-ctl text-muted">No response action is recorded for the alerts of this case.</p>
        ) : (
          <ResponseTable actions={c.actions} planned selected={NONE} onChange={() => undefined} disabled decide={under} />
        )}
      </Section>
      {pending && (
        <ApprovalDialog
          pending={pending}
          onClose={() => {
            setPending(null);
            onDecided();
          }}
        />
      )}
    </div>
  );
}

// The timeline and what the case touches ----------------------------------------------------------

function Timeline({ c, userId }: { c: CaseOut; userId: string | null | undefined }) {
  const titles = new Map(c.alerts.map((a) => [a.id, a.title]));
  const detail = (index: number) => {
    const entry: CaseTimelineEntryOut = c.timeline[index];
    const title = entry.alert_id ? titles.get(entry.alert_id) : undefined;
    const by = personLabel(entry.by, userId);
    if (!title && !by) return null;
    return (
      <small className={SMALL}>
        {title && entry.alert_id && (
          <Link to={alertHref(entry.alert_id)} className="hover:underline">
            {title}
          </Link>
        )}
        {title && by && ' · '}
        {by && `by ${by}`}
      </small>
    );
  };
  return (
    <Section
      title="Timeline"
      note="What happened to the case and to its alerts. The steps of each investigation are on the alert's own page."
      right={
        <>
          <VoiceTag voice="observed">Code</VoiceTag>
          <VoiceTag voice="claimed">Model</VoiceTag>
          <VoiceTag voice="decided">Check or policy</VoiceTag>
          <VoiceTag voice="person">Person</VoiceTag>
        </>
      }
    >
      {c.timeline_truncated && <p className="pt-2 text-xs text-muted">Older entries are left out: the newest {c.timeline.length} are shown.</p>}
      <div className="pt-2">
        <StepList steps={c.timeline} detail={detail} />
      </div>
    </Section>
  );
}

const ENTITY_WORDS: Record<string, string> = {
  user: 'User',
  host: 'Host',
  ip: 'IP address',
  email: 'E-mail address',
  domain: 'Domain',
  url: 'URL',
  process: 'Process',
  hash: 'File hash',
};

const WITHOUT_A_PERSON: ReadonlyArray<{ kind: CloserKind; key: keyof CaseOut['counts']['closed_by'] }> = [
  { kind: 'ai_evidence', key: 'ai_evidence' },
  { kind: 'ai_audit', key: 'ai_audit' },
  { kind: 'suppression_rule', key: 'suppression_rule' },
  { kind: 'cached_verdict', key: 'cached_verdict' },
];

function Touches({ c }: { c: CaseOut }) {
  const closed = WITHOUT_A_PERSON.filter((row) => c.counts.closed_by[row.key] > 0);
  const total = c.alerts.length;
  return (
    <Section title="What the case touches">
      {c.entities.length === 0 ? (
        <p className="py-3 text-ctl text-muted">The alerts of this case name no host, user or other entity.</p>
      ) : (
        <ul aria-label="Entities of the case" className="pt-1">
          {c.entities.map((e) => (
            <li key={`${e.kind}:${e.value}`} className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 border-b border-subtle py-1 text-ctl">
              <span className="w-24 flex-none font-mono text-2xs font-medium uppercase tracking-label text-muted">{ENTITY_WORDS[e.kind] ?? humanize(e.kind)}</span>
              <Link to={alertsHref({ view: 'all', q: e.value })} title={`Alerts whose title names ${e.value}`} className={cx('min-w-0 break-all font-mono text-xs', LINK)}>
                {e.value}
                <span className="sr-only">: alerts whose title names it</span>
              </Link>
              <span className="text-xs text-muted">{total > 1 ? `${e.alerts} of the ${total} alerts` : 'this alert'}</span>
            </li>
          ))}
        </ul>
      )}
      <h3 className="pb-1 pt-4 text-ctl font-semibold text-fg">Closed without a person in this case</h3>
      {closed.length === 0 ? (
        <p className="text-ctl text-muted">No alert of this case was closed without a person.</p>
      ) : (
        <table className="w-full border-collapse border-t border-strong">
          <tbody>
            {closed.map((row) => (
              <tr key={row.kind} data-closed-count={row.kind}>
                <th scope="row" className="border-b border-subtle pr-2.5 text-left font-normal">
                  <CloserMark kind={row.kind} />
                </th>
                <td className="border-b border-subtle text-right font-mono text-ctl tabular-nums text-fg">{c.counts.closed_by[row.key]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {c.counts.withheld > 0 && (
        <p className="pt-2 text-xs text-muted">
          {plural(c.counts.withheld, 'alert waits', 'alerts wait')} for a blind-audit label and {c.counts.withheld === 1 ? 'is' : 'are'} not counted here.
        </p>
      )}
    </Section>
  );
}

/** What the read model cannot give yet, in its own words; nothing when it lists nothing. */
function NotAvailable({ c }: { c: CaseOut }) {
  if (c.not_available.length === 0) return null;
  return (
    <details data-not-available className="pt-5 text-xs text-muted">
      <summary className="flex min-h-6 w-fit cursor-pointer items-center text-link">Not yet available on this page ({c.not_available.length})</summary>
      <ul className="list-disc pl-5">
        {c.not_available.map((n) => (
          <li key={n.field}>{n.reason}</li>
        ))}
      </ul>
    </details>
  );
}

/** A decision already recorded on the case: who decided what, when, and their note. */
function DecisionRecord({ c, userId }: { c: CaseOut; userId: string | null | undefined }) {
  const d = c.decision;
  if (!d) {
    return (
      <Section title="Decision">
        <p className="pt-3 text-ctl text-muted">This case is {humanize(c.status).toLowerCase()}: no decision is recorded on it.</p>
      </Section>
    );
  }
  const by = personLabel(d.decided_by, userId);
  return (
    <Section title="Decision">
      <div className="pt-3 text-ctl text-body">
        <p className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
          <VoiceTag voice="person">Decided by a person</VoiceTag>
          <b className="font-semibold text-fg">{humanize(decisionWords(d.decision))}</b>
          {by && <span>by {by}</span>}
          {d.decided_at && <time dateTime={d.decided_at}>{formatDateTime(d.decided_at)}</time>}
        </p>
        {d.notes && <p className="mt-1.5 max-w-[62em] whitespace-pre-wrap break-words">{d.notes}</p>}
      </div>
    </Section>
  );
}

// The page ------------------------------------------------------------------------------------

/** Move the focus to the next (or the previous) alert of the list; from outside the list, to its first alert. */
function moveThroughAlerts(step: 1 | -1): void {
  const links = [...document.querySelectorAll<HTMLElement>('a[data-case-alert]')];
  if (links.length === 0) return;
  const at = links.indexOf(document.activeElement as HTMLElement);
  const next = at === -1 ? (step === 1 ? 0 : links.length - 1) : Math.min(links.length - 1, Math.max(0, at + step));
  links[next].focus();
  links[next].scrollIntoView?.({ block: 'nearest' });
}

function Case({ caseId }: { caseId: string }) {
  const api = useApi();
  const navigate = useNavigate();
  const toast = useToast();
  const client = useQueryClient();
  const { principal } = useAuth();
  const tenant = useTenantLabel();
  const { model, escalation, active } = useCase(caseId);
  const [singleKeys, setSingleKeys] = useSingleKeys(principal?.userId);
  const [reopening, setReopening] = useState<PendingReopen | null>(null);
  const e = active ? escalation.data : undefined;
  const claim = useClaim(e);
  const userId = principal?.userId;

  useKeydown((event) => {
    if (!singleKeys || !isSingleKey(event)) return;
    const key = event.key.toLowerCase();
    if (key !== 'j' && key !== 'k') return;
    event.preventDefault();
    moveThroughAlerts(key === 'j' ? 1 : -1);
  });

  if (model.isPending) return <LoadingState label="Loading the case" />;
  if (model.isError || !model.data) {
    const missing = model.error instanceof ApiError && model.error.status === 404;
    return (
      <div className="flex flex-col gap-4">
        <h1 className="text-xl font-semibold text-fg">{missing ? 'Case not found' : 'Case'}</h1>
        <ErrorMessage error={model.error} onRetry={missing ? undefined : () => void model.refetch()} />
        <Link to={QUEUE_HREF} className={cx('text-ctl', LINK)}>
          Back to the queue
        </Link>
      </div>
    );
  }

  const c = model.data;
  const mine = Boolean(e && e.assigned_to && e.assigned_to === userId);
  const owner = personLabel(c.owner, userId);
  const linked = c.counts.linked;
  // Reopening and flagging are attributed to a person, as a decision is: an analyst with an account here.
  const mayReopen = can.decide(principal);

  const openNext = async () => {
    try {
      const next = await findNextEscalation(api, principal, c.id);
      if (next) navigate(caseHref(next.id));
      else toast.info('No other escalation is waiting for you.');
    } catch (err) {
      toast.error(err, 'Could not open the next escalation');
    }
  };

  return (
    <div data-case={c.status}>
      <nav aria-label="Breadcrumb" className="mb-1.5 flex flex-wrap items-center gap-1.5 text-xs text-muted">
        <Link to={QUEUE_HREF} className="text-secondary hover:underline">
          Queue
        </Link>
        <span aria-hidden="true">/</span>
        <span>
          Case{' '}
          <span className="font-mono" title={c.id}>
            {shortId(c.id)}
          </span>
        </span>
        <span aria-hidden="true">·</span>
        <span>{tenant}</span>
      </nav>
      <div className="mb-2 flex flex-wrap items-end gap-x-4 gap-y-2">
        <h1 className="min-w-0 break-words text-xl font-semibold text-fg">{c.title}</h1>
        <div className="flex flex-wrap items-center gap-2 min-[900px]:ml-auto">
          <CaseState c={c} />
          <SeverityBars value={c.severity} />
          {c.active && <SlaChip e={{ sla_deadline: c.sla_deadline, created_at: c.opened_at }} />}
          {c.active && owner && <FactChip label="Owner">{owner}</FactChip>}
          <Link to={alertHref(c.alert_id)} className={buttonClass(c.active ? 'primary' : 'secondary')}>
            Review the evidence
          </Link>
        </div>
      </div>
      <p data-statement className="mb-3 max-w-[44em] text-lg leading-snug text-fg">
        {statement(c.counts)}
      </p>

      <Facts c={c} userId={userId} />

      {linked > 0 && (
        <Banner tone="info" className="mt-3" title={`${plural(linked, 'alert', 'alerts')} closed by the AI ${linked === 1 ? 'is' : 'are'} linked here and ${linked === 1 ? 'stays' : 'stay'} closed`}>
          {c.alerts.find((a) => a.link)?.link?.reason.sentence}
          {mayReopen && ' You can reopen or flag any of them yourself, now.'}
        </Banner>
      )}

      <Alerts c={c} userId={userId} ask={mayReopen ? setReopening : null} />
      {reopening && <ReopenDialog pending={reopening} caseId={c.id} onClose={() => setReopening(null)} />}
      <SafetyNet c={c} userId={userId} />
      <Response c={c} onDecided={() => void afterEscalationChange(client)} />

      <div className="grid grid-cols-1 items-start gap-x-10 min-[1100px]:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Timeline c={c} userId={userId} />
        <Touches c={c} />
      </div>

      {!c.active && <DecisionRecord c={c} userId={userId} />}
      <NotAvailable c={c} />

      {e && (
        <DecisionDock
          escalation={e}
          blockedReason={blockedReason(e, principal)}
          claim={mine ? null : { label: e.assigned_to ? 'Take over' : 'Claim', busy: claim.busy, run: claim.run }}
          planned={[]}
          preapproved={NONE}
          recordingAs={principal?.email ?? 'you'}
          tenant={tenant}
          singleKeys={singleKeys}
          onSingleKeys={setSingleKeys}
          onDecided={openNext}
        />
      )}
    </div>
  );
}

export default function CasePage() {
  const { key = '' } = useParams();
  // A new page per case: "Record and open next" must not carry the verdict or the note over.
  return <Case key={key} caseId={key} />;
}
