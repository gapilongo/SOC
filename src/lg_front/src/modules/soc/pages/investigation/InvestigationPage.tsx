/**
 * The investigation view (/alerts/:id): a full page that explains the AI's
 * decision on one alert, in the same six sections for every alert.
 *
 *   01 the outcome and the verdict as a sentence, why the alert is with a
 *      person (or why it was closed), the alert's subject, the track record
 *   02 the claims, each beside the observations it rests on
 *   03 what is not established (three kinds)
 *   04 what the investigation did, in plain words
 *   05 the proposed response, with exact targets
 *   06 the decision bar
 *
 * Three voices are kept apart everywhere: what a tool returned (observed),
 * what the model wrote (claimed), what a check, the policy or a person
 * decided. "Hide the verdict" (V) withholds the verdict and the claims so
 * the reader judges from the evidence first.
 */

import { useQueryClient } from '@tanstack/react-query';
import { Clock } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { ApiError } from '../../../../api/client';
import { endpoints } from '../../api/endpoints';
import { decidedByLabel, escalationConflictNotice, escalationOwner, text } from '../../api/fields';
import { useTenantLabel } from '../../api/hooks';
import type { ClaimOut, InvestigationOut, ObservationOut } from '../../api/investigation';
import { afterEscalationChange } from '../../api/invalidate';
import type { AlertDetailOut, EscalationOut } from '../../api/types';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can, escalationDecisionBlockedReason } from '../../../../auth/roles';
import type { Principal } from '../../../../auth/store';
import {
  ClaimRow,
  FactChip,
  Keycap,
  NotEstablished,
  Observation,
  OutcomeHeadline,
  SeverityBars,
  StepList,
  TrackRecord,
  VoiceTag,
  outcomeKind,
  type OutcomeKind,
} from '../../components/investigation';
import { useToast } from '../../../../components/Toast';
import { Banner, Button, ErrorMessage, LoadingState, Spinner, cx } from '../../../../components/ui';
import { formatDateTime } from '../../../../lib/format';
import { APPROVALS_HREF, alertHref, alertsHref, escalationHref } from '../../lib/links';
import { asObjectOrNull } from '../../../../lib/json';
import { slaLabel, slaStatus } from '../../lib/sla';
import { useNow } from '../../../../lib/useNow';
import { EvidenceWarning, ResponseActions } from '../alerts/AlertSections';
import { EvidenceActions } from '../alerts/EvidenceActions';
import { readEntities, strings } from '../escalations/evidence';
import { decisionLabel } from '../escalations/labels';
import { findNextEscalation } from '../escalations/nextEscalation';
import { DecisionDock } from './DecisionDock';
import { isSingleKey, useKeydown, useSingleKeys } from './keys';
import { ResponseTable } from './ResponseTable';
import { useInvestigation } from './useInvestigation';

// Layout ---------------------------------------------------------------------------

/** A numbered section of the page: the margin number, the heading with its note, then the content. */
function DocSection({ n, title, note, right, children }: { n: string; title: string; note?: ReactNode; right?: ReactNode; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="grid grid-cols-1 pt-[18px] min-[900px]:grid-cols-[40px_minmax(0,1fr)]">
      <div aria-hidden="true" className="hidden font-mono text-2xs font-medium leading-5 tracking-[0.04em] text-muted min-[900px]:block">
        {n}
      </div>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-strong pb-2">
          <h2 id={id} className="text-[15px] font-semibold leading-5 text-fg">
            {title}
          </h2>
          {note && <span className="text-[12.5px] text-muted">{note}</span>}
          {right && <span className="ml-auto flex flex-wrap items-center gap-x-3.5 gap-y-1">{right}</span>}
        </div>
        {children}
      </div>
    </section>
  );
}

const LINK = 'text-link underline hover:text-link-hover';

// 01: the subject of the alert -------------------------------------------------------

const ENTITY_WORDS: Record<string, string> = {
  hosts: 'Host',
  users: 'User',
  ips: 'IP address',
  domains: 'Domain',
  urls: 'URL',
  hashes: 'File hash',
  processes: 'Process',
  command_lines: 'Command line',
  emails: 'E-mail address',
};
/** Values shown per entity kind; the rest are counted. */
const MAX_PER_KIND = 2;

function Subject({ alert }: { alert: AlertDetailOut }) {
  const normalized = asObjectOrNull(alert.normalized);
  const techniques = strings(asObjectOrNull(normalized?.mitre)?.techniques);
  const rule = text(normalized?.rule_name);
  return (
    <ul aria-label="Subject of the alert" className="mt-3 flex flex-wrap gap-1.5">
      {readEntities(alert).flatMap(([kind, values]) => {
        const label = ENTITY_WORDS[kind] ?? kind.replace(/_/g, ' ');
        const shown = values.slice(0, MAX_PER_KIND).map((value, i) => (
          <li key={`${kind}-${i}`} className="max-w-full">
            <FactChip label={label} mono>
              {value}
            </FactChip>
          </li>
        ));
        if (values.length > MAX_PER_KIND) {
          shown.push(
            <li key={`${kind}-more`}>
              <FactChip label={label}>+{values.length - MAX_PER_KIND} more</FactChip>
            </li>,
          );
        }
        return shown;
      })}
      <li>
        <FactChip label="Happened">
          <time dateTime={alert.occurred_at}>{formatDateTime(alert.occurred_at)}</time>
        </FactChip>
      </li>
      {techniques.length > 0 && (
        <li>
          <FactChip label="ATT&CK">{techniques.join(', ')}</FactChip>
        </li>
      )}
      {rule && (
        <li className="max-w-full">
          <FactChip label="Rule">{rule}</FactChip>
        </li>
      )}
    </ul>
  );
}

const TRACK_OUTCOME: Partial<Record<OutcomeKind, string>> = {
  needs_decision_malicious: 'alerts sent to a person as likely malicious',
  needs_decision_unsure: 'alerts sent to a person as unsure',
  ai_closed: 'alerts the AI closed',
  ai_closed_audit: 'alerts the AI closed and sampled for audit',
};

/** "2 of the 5 claims are backed by what the tools returned; 3 cite no fact." */
export function checkLine(claims: readonly ClaimOut[]): string | undefined {
  if (claims.length === 0) return undefined;
  const backed = claims.filter((c) => c.check === 'supported').length;
  const rejected = claims.filter((c) => c.check === 'rejected').length;
  const bare = claims.length - backed - rejected;
  const parts = [`${backed} of the ${claims.length} ${claims.length === 1 ? 'claim' : 'claims'} ${backed === 1 ? 'is' : 'are'} backed by what the tools returned`];
  if (rejected > 0) parts.push(`${rejected} ${rejected === 1 ? 'was' : 'were'} rejected`);
  if (bare > 0) parts.push(`${bare} ${bare === 1 ? 'cites' : 'cite'} no fact`);
  return `${parts.join('; ')}.`;
}

// 02: claims beside their observations ---------------------------------------------------

function Claims({
  investigation,
  hidden,
  selected,
  onSelect,
}: {
  investigation: InvestigationOut;
  hidden: boolean;
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const byId = new Map(investigation.observations.map((o) => [o.id, o]));
  const shown = new Set<string>();
  const rows = investigation.claims.map((claim, i) => {
    const cited = claim.observation_ids.flatMap((id): ObservationOut[] => (byId.has(id) ? [byId.get(id) as ObservationOut] : []));
    const observations = cited.map((o) => {
      const repeated = shown.has(o.id);
      shown.add(o.id);
      return <Observation key={o.id} observation={o} repeated={repeated} />;
    });
    return (
      <ClaimRow key={claim.id} claim={claim} number={i + 1} selected={selected === claim.id} hidden={hidden} onSelect={() => onSelect(claim.id)}>
        {observations.length > 0 ? observations : undefined}
      </ClaimRow>
    );
  });
  // What the tools returned that no claim cites: still on the page. Lookups that found nothing or failed are in section 03.
  const uncited = investigation.observations.filter((o) => !shown.has(o.id) && o.outcome === 'success');
  return (
    <>
      {rows.length === 0 && (
        <p className="py-3 text-ctl text-muted">
          {investigation.observations.length === 0 && !investigation.summary
            ? 'No investigation ran for this alert: there are no claims and no observations.'
            : 'The analysis recorded no claim for this alert.'}
        </p>
      )}
      {rows}
      {uncited.length > 0 && (
        <div className="py-3">
          <h3 className="mb-2 text-ctl font-semibold text-fg">Returned by the tools, cited by no claim</h3>
          <div className="flex flex-col gap-1.5">
            {uncited.map((o) => (
              <Observation key={o.id} observation={o} />
            ))}
          </div>
        </div>
      )}
    </>
  );
}

// The header ----------------------------------------------------------------------------

/** The time left to the deadline of an escalation that still waits (its own clock: the page does not re-render every second). */
function SlaChip({ e }: { e: EscalationOut }) {
  const now = useNow(1_000);
  const sla = slaStatus(e.sla_deadline, now, e.created_at);
  if (sla.state === 'none') return null;
  return (
    <span
      className={cx(
        'inline-flex min-h-[22px] items-center gap-[5px] whitespace-nowrap rounded-[2px] bg-raised-2 px-[7px] text-xs tabular-nums',
        sla.state === 'ok' ? 'text-secondary' : 'font-semibold text-warn',
      )}
      title={e.sla_deadline ? `Deadline ${formatDateTime(e.sla_deadline)}` : undefined}
    >
      <Clock className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
      {slaLabel(sla)}
    </span>
  );
}

// 06: the decision ----------------------------------------------------------------------

/** Why the caller cannot decide this escalation here, or null when they may (after a claim, if it is not theirs yet). */
function blockedReason(e: EscalationOut, principal: Principal | null): string | null {
  const general = escalationDecisionBlockedReason(principal, e);
  if (general) return general;
  if (e.assigned_to !== principal?.userId && !can.claimEscalation(principal, e)) return 'You cannot claim this escalation.';
  return null;
}

function useClaim(e: EscalationOut | undefined) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!e) return;
    setBusy(true);
    try {
      await endpoints.claim(api, e.id, e.version);
      toast.success(e.assigned_to ? 'Escalation taken over.' : 'Escalation claimed.');
    } catch (err) {
      const notice = escalationConflictNotice(err, 'it has been reloaded');
      if (notice) toast.info(notice);
      else toast.error(err, 'Claim failed');
    } finally {
      setBusy(false);
      void afterEscalationChange(client);
    }
  };
  return { busy, run: () => void run() };
}

/** A decision already recorded: who decided what, when, and their note. */
function DecisionRecord({ e, userId }: { e: EscalationOut; userId: string | null | undefined }) {
  const by = decidedByLabel(e, userId);
  return (
    <div className="pt-3 text-ctl text-body">
      <p className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <VoiceTag voice="person">Decided by a person</VoiceTag>
        <b className="font-semibold text-fg">{e.decision ? decisionLabel(e.decision) : `This escalation is ${e.status}`}</b>
        {by && <span>by {by}</span>}
        {e.decided_at && <time dateTime={e.decided_at}>{formatDateTime(e.decided_at)}</time>}
      </p>
      {e.decision_notes && <p className="mt-1.5 max-w-[62em] whitespace-pre-wrap break-words">{e.decision_notes}</p>}
    </div>
  );
}

// The page ------------------------------------------------------------------------------

function Investigation({ alertId }: { alertId: string }) {
  const api = useApi();
  const navigate = useNavigate();
  const toast = useToast();
  const { principal } = useAuth();
  const tenant = useTenantLabel();
  const { alert, escalation, escalationLoading, events, preview, investigation, active } = useInvestigation(alertId);
  const [blind, setBlind] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [preapproved, setPreapproved] = useState<Set<string>>(new Set());
  const [singleKeys, setSingleKeys] = useSingleKeys();
  const e = escalation.data;
  const claim = useClaim(e);
  const a = alert.data;
  // A blind-audit sample: the API withholds the AI's side for everyone, so there is nothing to reveal.
  const withheld = Boolean(a?.hidden_for_blind_audit);
  const hidden = withheld || blind;

  const select = (id: string) => {
    setSelected(id);
    const row = [...document.querySelectorAll<HTMLElement>('[data-claim]')].find((el) => el.dataset.claim === id);
    row?.scrollIntoView?.({ block: 'nearest' });
  };

  useKeydown((event) => {
    if (!singleKeys || !isSingleKey(event) || !investigation) return;
    const key = event.key.toLowerCase();
    if (key === 'v' && !withheld) setBlind((on) => !on);
    else if (/^[1-9]$/.test(key)) {
      const picked = investigation.claims[Number(key) - 1];
      if (picked) select(picked.id);
    }
  });

  if (alert.isPending) return <LoadingState label="Loading the investigation" />;
  if (alert.isError || !a || !investigation) {
    const missing = alert.error instanceof ApiError && alert.error.status === 404;
    return (
      <div className="flex flex-col gap-4">
        <h1 className="text-xl font-semibold text-fg">{missing ? 'Alert not found' : 'Alert'}</h1>
        <ErrorMessage error={alert.error} onRetry={missing ? undefined : () => void alert.refetch()} />
        <Link to="/alerts" className={cx('text-ctl', LINK)}>
          Back to the alerts
        </Link>
      </div>
    );
  }

  const kind = outcomeKind(investigation.outcome, a.status);
  const owner = e && active ? escalationOwner(e, principal?.userId) : null;
  const planned = investigation.response?.actions ?? [];
  const gaps = new Set(investigation.not_yet_available);
  const description = text(asObjectOrNull(a.normalized)?.description);

  const openNext = async () => {
    if (!e) return;
    try {
      const next = await findNextEscalation(api, principal, e.id);
      if (next) navigate(alertHref(next.alert_id));
      else toast.info('No other escalation is waiting for you.');
    } catch (err) {
      toast.error(err, 'Could not open the next escalation');
    }
  };

  const mine = Boolean(e && e.assigned_to && e.assigned_to === principal?.userId);

  return (
    <div data-investigation={hidden ? 'hidden' : 'shown'}>
      <nav aria-label="Breadcrumb" className="mb-1.5 flex flex-wrap items-center gap-1.5 text-xs text-muted">
        <Link to="/alerts" className="text-secondary hover:underline">
          Alerts
        </Link>
        {a.case_key && (
          <>
            <span aria-hidden="true">/</span>
            <span>Case {a.case_key}</span>
          </>
        )}
        <span aria-hidden="true">/</span>
        <span className="font-mono" title={a.id}>
          {a.id.slice(0, 8)}
        </span>
        <span aria-hidden="true">·</span>
        <span>{tenant}</span>
        {a.source_name && (
          <>
            <span aria-hidden="true">·</span>
            <span>from {a.source_name}</span>
          </>
        )}
      </nav>
      <div className="mb-3.5 flex flex-wrap items-end gap-x-4 gap-y-2">
        <h1 className="min-w-0 break-words text-xl font-semibold leading-[1.2] tracking-[-0.01em] text-fg">{a.title}</h1>
        <div className="flex flex-wrap items-center gap-2 min-[900px]:ml-auto">
          <SeverityBars value={a.severity} />
          {e && active && <SlaChip e={e} />}
          {owner && <FactChip label="Owner">{owner.kind === 'you' ? 'you' : owner.label}</FactChip>}
          <Button size="sm" aria-pressed={hidden} disabled={withheld} onClick={() => setBlind((on) => !on)}>
            {hidden ? 'Show the verdict' : 'Hide the verdict'}
            <Keycap className="hidden min-[900px]:inline-flex">V</Keycap>
          </Button>
          <a href="#evidence-record" className="inline-flex min-h-8 items-center whitespace-nowrap rounded-control border border-control bg-raised px-3 py-1 text-ctl font-medium text-fg hover:bg-raised-2 touch:min-h-11">
            Evidence record
          </a>
        </div>
      </div>

      <div className="mb-3 empty:hidden">
        <EvidenceWarning alert={a} />
      </div>

      {/* 01 */}
      <div className="grid grid-cols-1 border-b border-strong pb-[18px] pt-1 min-[900px]:grid-cols-[40px_minmax(0,1fr)] min-[1200px]:grid-cols-[40px_minmax(0,1fr)_328px]">
        <div aria-hidden="true" className="hidden font-mono text-2xs font-medium leading-5 tracking-[0.04em] text-muted min-[900px]:block">
          01
        </div>
        <div className="min-w-0">
          <OutcomeHeadline
            outcome={investigation.outcome}
            summary={investigation.summary}
            status={a.status}
            hidden={hidden}
            canReveal={!withheld}
            checkLine={checkLine(investigation.claims)}
          >
            <Subject alert={a} />
          </OutcomeHeadline>
          {description && (
            <div className="mt-3 max-w-[62em]">
              <VoiceTag voice="observed">The alert, as {a.source_name ?? 'its source'} sent it</VoiceTag>
              <p className="mt-1 whitespace-pre-wrap break-words text-ctl text-body">{description}</p>
            </div>
          )}
        </div>
        <aside
          aria-labelledby="track-h"
          className="mt-3.5 border-t border-subtle pt-3 min-[900px]:col-start-2 min-[1200px]:col-start-3 min-[1200px]:ml-7 min-[1200px]:mt-0 min-[1200px]:border-l min-[1200px]:border-t-0 min-[1200px]:pl-5 min-[1200px]:pt-0"
        >
          <h2 id="track-h" className="mb-1.5 font-mono text-2xs font-medium uppercase leading-[1.3] tracking-[0.06em] text-muted">
            Track record of this outcome
          </h2>
          {hidden ? (
            <p className="text-ctl text-muted">Hidden with the verdict.</p>
          ) : (
            <TrackRecord record={investigation.track_record} outcome={TRACK_OUTCOME[kind] ?? 'alerts with this outcome'} scope={tenant} />
          )}
        </aside>
      </div>

      <div className="grid grid-cols-1 items-start gap-x-7 min-[1200px]:grid-cols-[minmax(0,1fr)_300px]">
        <div className="min-w-0">
          <DocSection
            n="02"
            title="Claims, each beside the fact it rests on"
            note={investigation.summary?.source === 'rules' ? 'Left: what the analysis rules state. Right: what a tool returned, unedited.' : 'Left: what the model says. Right: what a tool returned, unedited.'}
            right={
              <>
                <VoiceTag voice="claimed">Claimed</VoiceTag>
                <VoiceTag voice="observed">Observed</VoiceTag>
              </>
            }
          >
            <Claims investigation={investigation} hidden={hidden} selected={selected} onSelect={select} />
            {gaps.has('claims.check') && investigation.claims.length > 0 && !hidden && (
              <p className="pt-2 text-xs text-muted">
                Not yet available: the evidence checker. Until it is in place, a claim counts as backed when it names the target of a lookup that returned data,
                and observations carry no hash.
              </p>
            )}
          </DocSection>
        </div>
        <div className="min-w-0 min-[1200px]:sticky min-[1200px]:top-16">
          <DocSection n="03" title="What is not established">
            <NotEstablished
              value={investigation.not_established}
              notCheckedNote={gaps.has('not_established.not_checked') ? 'Not yet available: what the playbook leaves out. This lists only the indicators of the alert that no lookup was recorded for.' : undefined}
            />
          </DocSection>
        </div>
      </div>

      <div className="max-w-[1180px]">
        <DocSection
          n="04"
          title="What the investigation did"
          note="A log of actions, written by code. It is not the model's reasoning."
          right={
            <>
              <VoiceTag voice="observed">Code</VoiceTag>
              <VoiceTag voice="claimed">Model</VoiceTag>
              <VoiceTag voice="decided">Check or policy</VoiceTag>
              <VoiceTag voice="person">Person</VoiceTag>
            </>
          }
        >
          {events.isPending && (
            <div className="py-3">
              <Spinner label="Loading the steps" />
            </div>
          )}
          {events.isError && (
            <div className="py-3">
              <ErrorMessage error={events.error} onRetry={() => void events.refetch()} compact />
            </div>
          )}
          {events.isSuccess && investigation.steps.length === 0 && <p className="py-3 text-ctl text-muted">No step is recorded for this alert yet.</p>}
          <StepList steps={investigation.steps} hideModelOutput={hidden} />
          {events.hasNextPage && (
            <Button size="sm" className="mt-3" onClick={() => void events.fetchNextPage()} busy={events.isFetchingNextPage}>
              Load more steps
            </Button>
          )}
          <p className="mt-2 text-xs text-muted">Not yet available: the cost of the run, its tool budget and the check of the evidence chain.</p>
          <div id="evidence-record" className="mt-4 scroll-mt-20">
            <h3 className="mb-1.5 text-ctl font-semibold text-fg">Evidence record</h3>
            <EvidenceActions alertId={a.id} />
          </div>
        </DocSection>

        {e && active ? (
          <DocSection
            n="05"
            title="Proposed response"
            note={
              <>
                Nothing has run. Tick what should run the moment you record a true positive; the rest waits in{' '}
                <Link to={APPROVALS_HREF} className={LINK}>
                  Approvals
                </Link>
                .
              </>
            }
          >
            {preview.isPending && (
              <div className="py-3">
                <Spinner label="Computing the proposed response" />
              </div>
            )}
            {preview.isError && (
              <div className="py-3">
                <ErrorMessage error={preview.error} onRetry={() => void preview.refetch()} compact />
              </div>
            )}
            {investigation.response?.dry_run_forced && (
              <Banner tone="info" title="Dry run" className="mt-3">
                Response actions are recorded but not executed (the tenant’s dry-run setting or kill switch).
              </Banner>
            )}
            {preview.isSuccess && planned.length === 0 && <p className="py-3 text-ctl text-muted">The policy plans no response action for this alert.</p>}
            {planned.length > 0 && (
              <ResponseTable actions={planned} selected={preapproved} onChange={setPreapproved} disabled={!mine || blockedReason(e, principal) !== null} />
            )}
          </DocSection>
        ) : (
          <DocSection n="05" title="Response" note="What ran, what waits for an approval and what was blocked.">
            <div className="pt-3">{escalationLoading ? <Spinner label="Loading the escalation" /> : <ResponseActions alertId={a.id} />}</div>
          </DocSection>
        )}

        {!(e && active) && (
          <DocSection n="06" title="Decision">
            {e && <DecisionRecord e={e} userId={principal?.userId} />}
            {!e && escalationLoading && (
              <div className="pt-3">
                <Spinner label="Loading the escalation" />
              </div>
            )}
            {!e && escalation.isError && (
              <div className="pt-3">
                <ErrorMessage error={escalation.error} onRetry={() => void escalation.refetch()} compact />
              </div>
            )}
            {!e && !escalationLoading && !escalation.isError && <p className="pt-3 text-ctl text-muted">No decision was asked of a person for this alert.</p>}
            {e && (
              <p className="pt-2 text-xs">
                <Link to={escalationHref(e)} className={LINK}>
                  Open the escalation
                </Link>
              </p>
            )}
          </DocSection>
        )}
        <p className="pt-4 text-xs text-muted">
          Notes, tickets and the NIS2 report of this alert are in{' '}
          <Link to={alertsHref({ alert: a.id })} className={LINK}>
            its panel on the alert list
          </Link>
          .
        </p>
      </div>

      {/* 06 */}
      {e && active && (
        <DecisionDock
          escalation={e}
          blockedReason={blockedReason(e, principal)}
          claim={mine ? null : { label: e.assigned_to ? 'Take over' : 'Claim', busy: claim.busy, run: claim.run }}
          planned={planned}
          preapproved={preapproved}
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

export default function InvestigationPage() {
  const { id = '' } = useParams();
  // A new page per alert: "Record and open next" must not carry the verdict, the note or the ticks over.
  return <Investigation key={id} alertId={id} />;
}
