/**
 * The sections of one alert, shared by the Alerts page's side panel and the
 * alert drawer other pages open (escalations, actions): the escalation and
 * its claim, the simulated-evidence warning, the automated triage and what
 * it is based on, entities, e-mail, timeline, response actions, tickets,
 * notes, evidence and reporting, the alert's details and its raw record.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { RotateCcw } from 'lucide-react';
import { useId, useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { ApiError } from '../../api/client';
import { endpoints } from '../../api/endpoints';
import { decidedByLabel, escalationOwner, readFindings } from '../../api/fields';
import { useEscalation } from '../../api/hooks';
import { afterAlertChange, afterAlertTimelineChange, afterEscalationChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import type { ActionOut, AlertDetailOut, AlertEventOut, EscalationOut, FindingOut, JsonObject } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { ActionControls, ActionDetails } from '../../components/actions/ActionDetails';
import { VerificationBadge } from '../../components/actions/VerificationBadge';
import { RiskBadge, StatusBadge } from '../../components/Badge';
import { ConfirmDialog } from '../../components/Dialog';
import { TicketLinks } from '../../components/TicketLinks';
import { useToast } from '../../components/Toast';
import { Banner, Button, DefinitionList, EmptyState, ErrorMessage, JsonBlock, LoadingState, TextAreaField, buttonClass, cx } from '../../components/ui';
import { formatDateTime, formatRelative, humanize } from '../../lib/format';
import { escalationHref } from '../../lib/links';
import { useKeysetList } from '../../lib/pagination';
import { slaLabel, slaStatus } from '../../lib/sla';
import { useNow } from '../../lib/useNow';
import { aiVerdict, escalationIdOf, evidenceFlags, isSimulatedFinding, kindWords, originWords } from './alertSummary';
import { EmailPanel, emailSection } from './EmailPanel';
import { EvidenceActions } from './EvidenceActions';
import { IncidentReportDialog } from './IncidentReportDialog';
import { asObjectOrNull } from '../../lib/json';

function text(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return null;
}

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).filter(Boolean) : [];
}

/** A titled block of the panel; its heading names the region. */
export function Section({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={cx('border-t border-subtle pt-4', className)}>
      <h3 id={id} className="mb-2 text-sm font-semibold text-fg">
        {title}
      </h3>
      {children}
    </section>
  );
}

function Chip({ children, tone = 'neutral', title }: { children: ReactNode; tone?: 'neutral' | 'danger'; title?: string }) {
  return (
    <span
      title={title}
      className={cx('inline-flex items-center rounded-tag bg-raised-2 px-2 py-0.5 text-xs', tone === 'danger' ? 'font-semibold text-danger-fg' : 'text-body')}
    >
      {children}
    </span>
  );
}

// Escalation ---------------------------------------------------------------------

/** The alert's escalation: SLA, owner, an explicit Claim (or Take over), and the way to open it. */
export function EscalationBox({ escalationId }: { escalationId: string }) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const now = useNow(30_000);
  const q = useEscalation(escalationId);
  const claim = useMutation({
    mutationFn: (e: EscalationOut) => endpoints.claim(api, e.id, e.version),
    onSuccess: (_out, e) => toast.success(e.status === 'claimed' ? 'Escalation taken over.' : 'Escalation claimed.'),
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) toast.info('Someone else changed this escalation first; it has been refreshed.');
      else toast.error(err, 'Claim failed');
    },
    onSettled: () => afterEscalationChange(client),
  });

  if (q.isPending) return <LoadingState label="Loading escalation" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />;
  const e = q.data;
  const active = e.status === 'open' || e.status === 'claimed' || e.status === 'expired';
  const sla = active ? slaStatus(e.sla_deadline, now, e.created_at) : null;
  const owner = escalationOwner(e, principal?.userId);
  const decidedBy = decidedByLabel(e, principal?.userId);
  const canClaim = can.claimEscalation(principal, e);
  return (
    <div className="space-y-2 rounded-control bg-raised-2 p-3 text-ctl" data-testid="escalation-box">
      <div className="flex flex-wrap justify-between gap-2">
        <span className="text-fg">
          Escalation <span className="font-mono text-xs">{e.id.slice(0, 8)}</span> · {e.level}
        </span>
        {sla && sla.state !== 'none' && (
          <span className={cx('font-semibold tabular-nums', sla.state === 'breaching' ? 'text-danger-fg' : sla.state === 'at_risk' ? 'text-warn-fg' : 'text-body')}>
            {slaLabel(sla)}
          </span>
        )}
        {!active && <span className="text-secondary">{humanize(e.status)}</span>}
      </div>
      <p className="text-secondary">
        Owner: {owner.label}
        {owner.kind !== 'none' && e.claimed_at ? `, claimed ${formatRelative(e.claimed_at, now)}` : ''}
      </p>
      {e.decision && (
        <p className="text-body">
          Decided {humanize(e.decision).toLowerCase()}
          {decidedBy ? ` by ${decidedBy}` : ''}
          {e.decided_at ? `, ${formatRelative(e.decided_at, now)}` : ''}.
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        {canClaim && (
          <Button size="sm" variant={e.status === 'claimed' ? 'secondary' : 'primary'} busy={claim.isPending} onClick={() => claim.mutate(e)}>
            {e.status === 'claimed' ? 'Take over' : 'Claim'}
          </Button>
        )}
        <Link to={escalationHref(e)} className={buttonClass('secondary', 'sm')}>
          Open escalation
        </Link>
      </div>
    </div>
  );
}

// Simulated evidence -----------------------------------------------------------------

/** The red warning when evidence was simulated or the response only a dry run (as far as the alert records it). */
export function EvidenceWarning({ alert }: { alert: AlertDetailOut }) {
  const flags = evidenceFlags(alert);
  if (!flags.simulated && !flags.dryRun) return null;
  return (
    <div className="space-y-2">
      {flags.simulated && (
        <Banner tone="warning" role="alert" title="Some evidence was simulated.">
          {flags.simulatedSources.length > 0
            ? `Results from ${flags.simulatedSources.join(', ')} came from a test fixture, not a live lookup. `
            : 'Part of the evidence came from a test fixture, not a live lookup. '}
          Verify before acting.
        </Banner>
      )}
      {flags.dryRun && (
        <Banner tone="warning" role="alert" title="The response ran as a dry run.">
          Its actions were recorded but changed nothing in your systems.
        </Banner>
      )}
    </div>
  );
}

// Automated triage -------------------------------------------------------------------

function FindingItem({ f }: { f: FindingOut }) {
  const simulated = isSimulatedFinding(f);
  return (
    <li className="rounded-control border border-subtle p-2 text-xs">
      <div className="flex flex-wrap items-center gap-1.5">
        <Chip>{originWords(f.origin)}</Chip>
        <span className="font-semibold text-fg">{f.source}</span>
        <span className="text-body">
          {humanize(f.verdict)}
          {f.status && f.status !== 'ok' ? ` (${humanize(f.status).toLowerCase()})` : ''}
        </span>
        {f.cached && <Chip title="Served from the provider cache: fetched before this analysis ran">cached</Chip>}
        {simulated && <Chip tone="danger">simulated</Chip>}
      </div>
      <p className="mt-1 break-all text-secondary">
        {kindWords(f.kind)} <code className="font-mono text-fg">{f.target}</code>
      </p>
      <p className="mt-0.5 text-muted">
        {f.checked_at ? (
          <>
            Checked <time dateTime={f.checked_at}>{formatDateTime(f.checked_at)}</time>
          </>
        ) : (
          'Check time not recorded'
        )}
      </p>
    </li>
  );
}

/** "What the AI verdict is based on": every provider result of the analysis, with origin, source, verdict and time. */
export function Findings({ alert }: { alert: AlertDetailOut }) {
  const findings = readFindings(alert);
  const id = useId();
  return (
    <div>
      <h4 id={id} className="mb-1.5 text-ctl font-semibold text-fg">
        What the AI verdict is based on
      </h4>
      {findings.length === 0 ? (
        <p className="text-ctl text-muted">No threat-intel or history lookup was recorded for this analysis.</p>
      ) : (
        <ul aria-labelledby={id} className="space-y-1.5">
          {findings.map((f, i) => (
            <FindingItem key={`${f.origin}-${f.source}-${f.target}-${i}`} f={f} />
          ))}
        </ul>
      )}
    </div>
  );
}

function ScoreDetails({ summary }: { summary: JsonObject }) {
  const triage = asObjectOrNull(summary.triage);
  const correlation = asObjectOrNull(summary.correlation);
  const analysis = asObjectOrNull(summary.analysis);
  const response = asObjectOrNull(summary.response);
  if (!triage && !correlation && !analysis && !response) return null;
  return (
    <details className="rounded-control border border-subtle p-2 text-sm">
      <summary className="cursor-pointer text-ctl font-semibold text-fg">Scores, rules and response plan</summary>
      <div className="mt-3 space-y-4">
        {analysis && (
          <section>
            <h4 className="mb-1 font-medium text-fg">Analysis</h4>
            <DefinitionList
              items={[
                ['Verdict', text(analysis.verdict) ?? '-'],
                ['Threat score', text(analysis.threat_score) ?? '-'],
                ['Certainty', text(analysis.certainty) ?? '-'],
                ['LLM used', analysis.llm_used ? 'yes' : 'no'],
                ['Stop reason', text(analysis.stop_reason) ?? '-'],
              ]}
            />
          </section>
        )}
        {triage && (
          <section>
            <h4 className="mb-1 font-medium text-fg">Triage</h4>
            <DefinitionList
              items={[
                ['Confidence', text(triage.confidence) ?? '-'],
                ['Priority', text(triage.priority) ?? '-'],
                ['False-positive indicators', [...list(triage.rule_fp), ...list(triage.llm_fp)].join(', ') || '-'],
                ['True-positive indicators', [...list(triage.rule_tp), ...list(triage.llm_tp)].join(', ') || '-'],
              ]}
            />
            {text(triage.reasoning) && <p className="mt-2 whitespace-pre-wrap text-body">{text(triage.reasoning)}</p>}
          </section>
        )}
        {correlation && (
          <section>
            <h4 className="mb-1 font-medium text-fg">Correlation</h4>
            <DefinitionList
              items={Object.entries(correlation)
                .filter(([, v]) => typeof v !== 'object' || v === null)
                .slice(0, 12)
                .map(([k, v]) => [humanize(k), text(v) ?? '-'])}
            />
          </section>
        )}
        {response && (
          <section>
            <h4 className="mb-1 font-medium text-fg">Response plan</h4>
            <DefinitionList
              items={Object.entries(response)
                .filter(([k, v]) => k !== 'evidence' && (typeof v !== 'object' || v === null))
                .map(([k, v]) => [humanize(k), text(v) ?? '-'])}
            />
          </section>
        )}
      </div>
    </details>
  );
}

/** The verdict, its basis, the model's conclusion and reasoning, and the findings behind it. */
export function AutomatedTriage({ alert }: { alert: AlertDetailOut }) {
  const id = useId();
  const summary = alert.summary ?? {};
  const analysis = asObjectOrNull(summary.analysis);
  const { verdict, confidence } = aiVerdict(alert);
  const flags = evidenceFlags(alert);
  const findings = readFindings(alert);
  const reasoning = list(analysis?.reasoning);
  const recommended = list(analysis?.recommended_actions);
  const budget = Boolean(summary.llm_budget_exceeded);
  const suppressedBy = text(summary.suppressed_by);
  const hasAny = Boolean(analysis || asObjectOrNull(summary.triage) || asObjectOrNull(summary.correlation) || asObjectOrNull(summary.response) || suppressedBy || budget);
  const basis: string[] = [];
  if (analysis) {
    if (analysis.llm_used === true) basis.push('Written by the model');
    else if (analysis.llm_used === false) basis.push('Rules only');
    basis.push(`Evidence: ${findings.length === 0 ? 'no lookups' : flags.simulated ? 'partly simulated' : 'live lookups'}`);
  }
  if (budget) basis.push('LLM budget exhausted');
  return (
    <section aria-labelledby={id} className="space-y-3">
      <h3 id={id} className="text-2xs font-semibold uppercase tracking-wider text-eyebrow">
        Automated triage
      </h3>
      {!hasAny ? (
        <p className="text-sm text-muted">The workflow has not produced a verdict yet.</p>
      ) : (
        <>
          {basis.length > 0 && (
            <ul aria-label="Basis of this verdict" className="flex flex-wrap gap-1.5">
              {basis.map((b) => (
                <li key={b}>
                  <Chip tone={b === 'Evidence: partly simulated' ? 'danger' : 'neutral'}>{b}</Chip>
                </li>
              ))}
            </ul>
          )}
          {(verdict || confidence !== null) && (
            <p className="text-ctl text-fg">
              {verdict && <strong className="font-semibold">{humanize(verdict)}.</strong>}
              {confidence !== null && ` Triage confidence ${confidence}%.`}
              {text(analysis?.threat_score) && ` Threat score ${text(analysis?.threat_score)}.`}
            </p>
          )}
          {budget && (
            <p className="text-ctl text-warn-fg">The tenant's daily LLM token budget was exhausted; this alert was assessed by rules only.</p>
          )}
          {suppressedBy && (
            <p className="text-ctl text-body">
              Closed by suppression rule <code>{suppressedBy}</code>.
            </p>
          )}
          {text(analysis?.conclusion) && <p className="whitespace-pre-wrap text-ctl text-body">{text(analysis?.conclusion)}</p>}
          {analysis?.llm_refusal ? <p className="text-ctl text-warn-fg">The model declined to assess this alert; rule results were used.</p> : null}
          {reasoning.length > 0 && (
            <ol aria-label="Reasoning steps" className="list-decimal space-y-1 pl-5 text-ctl text-body">
              {reasoning.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ol>
          )}
          {recommended.length > 0 && (
            <p className="text-xs text-secondary">
              Agent suggests: {recommended.join(', ')}.{alert.status === 'waiting_human' ? ' Nothing runs until an analyst decides.' : ''}
            </p>
          )}
          {analysis && <Findings alert={alert} />}
          <ScoreDetails summary={summary} />
        </>
      )}
    </section>
  );
}

// Entities ------------------------------------------------------------------------

const ENTITY_LABELS: Record<string, string> = {
  hosts: 'Hosts',
  users: 'Users',
  ips: 'IP addresses',
  domains: 'Domains',
  urls: 'URLs',
  hashes: 'File hashes',
  processes: 'Processes',
  command_lines: 'Command lines',
  emails: 'Email addresses',
};

function Entities({ normalized }: { normalized: JsonObject | null }) {
  const entities = asObjectOrNull(normalized?.entities);
  const kinds = entities ? Object.keys(entities).filter((k) => list(entities[k]).length > 0) : [];
  const mitre = asObjectOrNull(normalized?.mitre);
  const techniques = mitre ? [...list(mitre.tactics), ...list(mitre.techniques)] : [];
  return (
    <>
      {!entities || kinds.length === 0 ? (
        <p className="text-sm text-muted">No entities were extracted.</p>
      ) : (
        <dl className="space-y-3">
          {kinds.map((k) => (
            <div key={k}>
              <dt className="mb-1 text-xs font-medium text-muted">{ENTITY_LABELS[k] ?? humanize(k)}</dt>
              <dd className="flex flex-wrap gap-1.5">
                {list(entities[k]).map((v, i) => (
                  <code key={`${v}-${i}`} className="max-w-full break-all rounded bg-raised-2 px-1.5 py-0.5 text-xs text-fg">
                    {v}
                  </code>
                ))}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {techniques.length > 0 && (
        <p className="mt-3 text-sm text-body">
          <span className="text-muted">MITRE ATT&CK: </span>
          {techniques.join(', ')}
        </p>
      )}
    </>
  );
}

// Timeline, notes, actions, tickets -----------------------------------------------

function eventSummary(e: AlertEventOut): string {
  const d = e.data ?? {};
  if (e.event_type === 'note' && typeof d.text === 'string') return d.text;
  // Integration events (ticket opened, resolved outside LG-SOTF) carry a readable note.
  if (e.event_type.startsWith('ticket.') && typeof d.note === 'string') return d.note;
  const parts: string[] = [];
  for (const key of ['status', 'from', 'to', 'decision', 'reason', 'disposition', 'action_type', 'error']) {
    const v = d[key];
    if (typeof v === 'string' || typeof v === 'number') parts.push(`${humanize(key)}: ${v}`);
  }
  return parts.join(', ');
}

function Timeline({ alertId }: { alertId: string }) {
  const api = useApi();
  const q = useKeysetList({
    queryKey: qk.alert.events(alertId),
    fetchPage: (cursor, signal) => endpoints.alertEvents(api, alertId, cursor, signal),
    itemKey: (e: AlertEventOut) => e.id,
  });
  if (q.isPending) return <LoadingState label="Loading timeline" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />;
  if (q.items.length === 0) return <EmptyState title="No events yet" />;
  return (
    <div>
      <ol className="relative space-y-3 border-l border-strong pl-4">
        {q.items.map((e) => (
          <li key={e.id} className="text-sm">
            <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full bg-muted" aria-hidden="true" />
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-medium text-fg">{humanize(e.event_type)}</span>
              {e.node && <span className="text-xs text-muted">node {e.node}</span>}
              <time dateTime={e.ts} className="text-xs text-muted">
                {formatDateTime(e.ts)}
              </time>
            </div>
            <div className="text-xs text-muted">
              by {e.actor_type}
              {e.actor_id ? ` ${e.actor_id}` : ''}
            </div>
            {eventSummary(e) && <p className="mt-0.5 whitespace-pre-wrap break-words text-body">{eventSummary(e)}</p>}
          </li>
        ))}
      </ol>
      {q.hasNextPage && (
        <Button size="sm" className="mt-3" onClick={() => void q.fetchNextPage()} busy={q.isFetchingNextPage}>
          Load older events
        </Button>
      )}
    </div>
  );
}

function NoteForm({ alertId }: { alertId: string }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [value, setValue] = useState('');
  const m = useMutation({
    mutationFn: (textValue: string) => endpoints.addNote(api, alertId, textValue),
    onSuccess: () => {
      setValue('');
      toast.success('Note added.');
      void afterAlertTimelineChange(client, alertId);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (value.trim()) m.mutate(value.trim());
  };
  return (
    <form onSubmit={submit} className="space-y-2">
      <TextAreaField label="Add a note" rows={3} maxLength={4000} value={value} onChange={(e) => setValue(e.target.value)} className="font-sans" />
      {m.isError && <ErrorMessage error={m.error} compact />}
      <Button type="submit" size="sm" variant="primary" busy={m.isPending} disabled={!value.trim()}>
        Save note
      </Button>
    </form>
  );
}

/** The alert's response actions with their outcome, verification and rollback controls. */
export function ResponseActions({ alertId }: { alertId: string }) {
  const api = useApi();
  const [open, setOpen] = useState<string | null>(null);
  const q = useQuery({
    queryKey: qk.actions.list({ alert_id: alertId }),
    queryFn: ({ signal }) => endpoints.actions(api, { alert_id: alertId }, undefined, signal),
  });
  if (q.isPending) return <LoadingState label="Loading response actions" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />;
  const items: ActionOut[] = Array.isArray(q.data?.items) ? q.data.items : [];
  if (items.length === 0) return <p className="text-sm text-muted">No response action was planned for this alert.</p>;
  return (
    <ul className="space-y-2">
      {items.map((a) => (
        <li key={a.id} className="rounded-control border border-subtle p-2">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium text-fg">{humanize(a.action_type)}</span>
            <code className="break-all text-xs text-secondary">{a.target}</code>
            <RiskBadge value={a.risk_level} />
            <StatusBadge value={a.status} />
            <VerificationBadge value={a.verification} detail={a.verification_detail} />
            <Button
              size="sm"
              variant="quiet"
              aria-expanded={open === a.id}
              onClick={() => setOpen(open === a.id ? null : a.id)}
              aria-label={`${open === a.id ? 'Hide' : 'Show'} details of ${humanize(a.action_type)} on ${a.target}`}
            >
              {open === a.id ? 'Hide' : 'Details'}
            </Button>
            <div className="ml-auto">
              <ActionControls action={a} />
            </div>
          </div>
          {open === a.id && (
            <div className="mt-2">
              <ActionDetails action={a} onSelectAction={(id) => setOpen(id)} />
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

function Tickets({ alertId }: { alertId: string }) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.tickets.forAlert(alertId),
    queryFn: ({ signal }) => endpoints.tickets(api, { alert_id: alertId }, signal),
  });
  if (q.isPending) return <LoadingState label="Loading tickets" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />;
  const tickets = Array.isArray(q.data) ? q.data : [];
  if (tickets.length === 0) return <p className="text-sm text-muted">No ticket is linked to this alert.</p>;
  return <TicketLinks tickets={tickets} />;
}

// Reprocess ------------------------------------------------------------------------

/** Requeue the alert for the full workflow (admins), after a confirmation. */
export function ReprocessButton({ alertId }: { alertId: string }) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const reprocess = useMutation({
    mutationFn: () => endpoints.reprocess(api, alertId),
    onSuccess: () => {
      setConfirm(false);
      toast.success('Alert queued for reprocessing.');
      void afterAlertChange(client, alertId);
    },
    onError: (err) => {
      setConfirm(false);
      if (err instanceof ApiError && err.code === 'run_active') toast.info('The alert is still being processed; try again when its run finishes.');
      else toast.error(err, 'Reprocess failed');
    },
  });
  if (!can.reprocess(principal)) return null;
  return (
    <>
      <Button onClick={() => setConfirm(true)} icon={<RotateCcw className="h-4 w-4" aria-hidden="true" />}>
        Reprocess
      </Button>
      <ConfirmDialog
        open={confirm}
        title="Reprocess alert"
        confirmLabel="Reprocess"
        busy={reprocess.isPending}
        onConfirm={() => reprocess.mutate()}
        onCancel={() => setConfirm(false)}
      >
        The alert is queued for the full triage workflow again. Existing timeline entries are kept.
      </ConfirmDialog>
    </>
  );
}

// The whole body -------------------------------------------------------------------

/** Every section of one alert, in triage order (the header is the container's). */
export function AlertSections({ alert }: { alert: AlertDetailOut }) {
  const { principal } = useAuth();
  const [nis2, setNis2] = useState(false);
  const normalized = asObjectOrNull(alert.normalized);
  const email = emailSection(normalized);
  const escalationId = escalationIdOf(alert);
  const flags = list(normalized?.flags);
  return (
    <div className="space-y-4">
      {escalationId && <EscalationBox escalationId={escalationId} />}
      <EvidenceWarning alert={alert} />
      <AutomatedTriage alert={alert} />
      <Section title="Entities">
        <Entities normalized={normalized} />
      </Section>
      {email && (
        <Section title="Email">
          <EmailPanel section={email} phishing={asObjectOrNull(asObjectOrNull(alert.summary?.triage)?.phishing)} />
        </Section>
      )}
      <Section title="Timeline">
        <Timeline alertId={alert.id} />
      </Section>
      <Section title="Response actions">
        <ResponseActions alertId={alert.id} />
      </Section>
      <Section title="Tickets">
        <Tickets alertId={alert.id} />
      </Section>
      {can.addNote(principal) && (
        <Section title="Notes">
          <NoteForm alertId={alert.id} />
        </Section>
      )}
      <Section title="Evidence and reporting">
        <EvidenceActions alertId={alert.id} />
        {can.addNote(principal) && (
          <>
            <Button size="sm" className="mt-3" onClick={() => setNis2(true)}>
              Draft NIS2 report
            </Button>
            <IncidentReportDialog alertId={alert.id} open={nis2} onClose={() => setNis2(false)} />
          </>
        )}
      </Section>
      <Section title="Alert details">
        <DefinitionList
          items={[
            ['Alert ID', <code key="id" className="break-all text-xs">{alert.id}</code>],
            ['Source', `${alert.source_name ?? alert.source_id} / ${alert.source_alert_id}`],
            ['Category', alert.category ?? '-'],
            ['Rule', text(normalized?.rule_name) ?? '-'],
            ['Disposition', alert.disposition ? humanize(alert.disposition) : '-'],
            ['Occurred', formatDateTime(alert.occurred_at)],
            ['Ingested', formatDateTime(alert.ingested_at)],
            ['Updated', formatDateTime(alert.updated_at)],
            ['Closed', formatDateTime(alert.closed_at)],
            ['Priority', alert.priority ?? '-'],
            ['Confidence', alert.confidence ?? '-'],
            ['Threat score', alert.threat_score ?? '-'],
            ['Assigned to', alert.assigned_to ?? '-'],
            ['Case', alert.case_key ?? '-'],
          ]}
        />
        {text(normalized?.description) && <p className="mt-3 whitespace-pre-wrap text-sm text-body">{text(normalized?.description)}</p>}
        {flags.length > 0 && <p className="mt-2 text-xs text-warn-fg">Data quality flags: {flags.join(', ')}</p>}
      </Section>
      <details className="border-t border-subtle pt-4">
        <summary className="cursor-pointer text-sm font-semibold text-fg">Normalized record</summary>
        <div className="mt-2">
          <JsonBlock value={alert.normalized} label="Normalized alert JSON" />
        </div>
      </details>
    </div>
  );
}
