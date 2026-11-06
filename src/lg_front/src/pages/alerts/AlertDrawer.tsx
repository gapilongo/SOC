import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { RotateCcw } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { ApiError } from '../../api/client';
import { qk } from '../../api/queryKeys';
import { endpoints } from '../../api/endpoints';
import type { ActionOut, AlertDetailOut, AlertEventOut, JsonObject } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { ActionControls, ActionDetails } from '../../components/actions/ActionDetails';
import { VerificationBadge } from '../../components/actions/VerificationBadge';
import { DispositionBadge, RiskBadge, SeverityBadge, StatusBadge } from '../../components/Badge';
import { ConfirmDialog, Modal } from '../../components/Dialog';
import { TicketLinks } from '../../components/TicketLinks';
import { useToast } from '../../components/Toast';
import { Button, DefinitionList, EmptyState, ErrorMessage, JsonBlock, LoadingState, TextAreaField } from '../../components/ui';
import { formatDateTime, humanize } from '../../lib/format';
import { useKeysetList } from '../../lib/pagination';
import { EvidenceActions } from './EvidenceActions';
import { IncidentReportDialog } from './IncidentReportDialog';
import { EmailPanel, emailSection } from './EmailPanel';

function obj(value: unknown): JsonObject | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonObject) : null;
}

function text(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return null;
}

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).filter(Boolean) : [];
}

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
  const entities = obj(normalized?.entities);
  const kinds = entities ? Object.keys(entities).filter((k) => list(entities[k]).length > 0) : [];
  if (!entities || kinds.length === 0) return <p className="text-sm text-slate-400">No entities were extracted.</p>;
  return (
    <dl className="space-y-3">
      {kinds.map((k) => (
        <div key={k}>
          <dt className="mb-1 text-xs font-medium text-slate-400">{ENTITY_LABELS[k] ?? humanize(k)}</dt>
          <dd className="flex flex-wrap gap-1.5">
            {list(entities[k]).map((v, i) => (
              <code key={`${v}-${i}`} className="max-w-full break-all rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-100">
                {v}
              </code>
            ))}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Reasoning({ summary }: { summary: JsonObject }) {
  const triage = obj(summary.triage);
  const correlation = obj(summary.correlation);
  const analysis = obj(summary.analysis);
  const response = obj(summary.response);
  const reasoning = list(analysis?.reasoning);
  const recommended = list(analysis?.recommended_actions);
  const hasAny = triage || correlation || analysis || response || summary.suppressed_by || summary.llm_budget_exceeded;
  if (!hasAny) return <p className="text-sm text-slate-400">The workflow has not produced a verdict yet.</p>;
  return (
    <div className="space-y-4 text-sm">
      {Boolean(summary.llm_budget_exceeded) && (
        <p className="rounded border border-amber-700 bg-amber-950 px-3 py-2 text-amber-100">
          The tenant's daily LLM token budget was exhausted; this alert was assessed by rules only.
        </p>
      )}
      {text(summary.suppressed_by) && (
        <p className="rounded border border-slate-700 bg-slate-800 px-3 py-2 text-slate-200">
          Closed by suppression rule <code>{text(summary.suppressed_by)}</code>.
        </p>
      )}
      {analysis && (
        <section>
          <h4 className="mb-1 font-medium text-slate-100">Analysis</h4>
          <DefinitionList
            items={[
              ['Verdict', text(analysis.verdict) ?? '-'],
              ['Threat score', text(analysis.threat_score) ?? '-'],
              ['Certainty', text(analysis.certainty) ?? '-'],
              ['LLM used', analysis.llm_used ? 'yes' : 'no'],
              ['Stop reason', text(analysis.stop_reason) ?? '-'],
            ]}
          />
          {text(analysis.conclusion) && <p className="mt-2 whitespace-pre-wrap text-slate-200">{text(analysis.conclusion)}</p>}
          {analysis.llm_refusal ? <p className="mt-2 text-amber-200">The model declined to assess this alert; rule results were used.</p> : null}
          {reasoning.length > 0 && (
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-slate-200">
              {reasoning.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ol>
          )}
          {recommended.length > 0 && (
            <div className="mt-2">
              <span className="text-slate-400">Recommended actions: </span>
              {recommended.join(', ')}
            </div>
          )}
        </section>
      )}
      {triage && (
        <section>
          <h4 className="mb-1 font-medium text-slate-100">Triage</h4>
          <DefinitionList
            items={[
              ['Confidence', text(triage.confidence) ?? '-'],
              ['Priority', text(triage.priority) ?? '-'],
              ['False-positive indicators', [...list(triage.rule_fp), ...list(triage.llm_fp)].join(', ') || '-'],
              ['True-positive indicators', [...list(triage.rule_tp), ...list(triage.llm_tp)].join(', ') || '-'],
            ]}
          />
          {text(triage.reasoning) && <p className="mt-2 whitespace-pre-wrap text-slate-200">{text(triage.reasoning)}</p>}
        </section>
      )}
      {correlation && (
        <section>
          <h4 className="mb-1 font-medium text-slate-100">Correlation</h4>
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
          <h4 className="mb-1 font-medium text-slate-100">Response plan</h4>
          <DefinitionList
            items={Object.entries(response)
              .filter(([k, v]) => k !== 'evidence' && (typeof v !== 'object' || v === null))
              .map(([k, v]) => [humanize(k), text(v) ?? '-'])}
          />
        </section>
      )}
    </div>
  );
}

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
      <ol className="relative space-y-3 border-l border-slate-700 pl-4">
        {q.items.map((e) => (
          <li key={e.id} className="text-sm">
            <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full bg-slate-500" aria-hidden="true" />
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-medium text-slate-100">{humanize(e.event_type)}</span>
              {e.node && <span className="text-xs text-slate-400">node {e.node}</span>}
              <time dateTime={e.ts} className="text-xs text-slate-400">
                {formatDateTime(e.ts)}
              </time>
            </div>
            <div className="text-xs text-slate-400">
              by {e.actor_type}
              {e.actor_id ? ` ${e.actor_id}` : ''}
            </div>
            {eventSummary(e) && <p className="mt-0.5 whitespace-pre-wrap break-words text-slate-200">{eventSummary(e)}</p>}
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
      void client.invalidateQueries({ queryKey: qk.alert.events(alertId) });
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
  if (items.length === 0) return <p className="text-sm text-slate-400">No response action was planned for this alert.</p>;
  return (
    <ul className="space-y-2">
      {items.map((a) => (
        <li key={a.id} className="rounded-md border border-slate-800 p-2">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium text-slate-100">{humanize(a.action_type)}</span>
            <code className="break-all text-xs text-slate-300">{a.target}</code>
            <RiskBadge value={a.risk_level} />
            <StatusBadge value={a.status} />
            <VerificationBadge value={a.verification} detail={a.verification_detail} />
            <Button
              size="sm"
              variant="ghost"
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
  if (tickets.length === 0) return <p className="text-sm text-slate-400">No ticket is linked to this alert.</p>;
  return <TicketLinks tickets={tickets} />;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-slate-800 py-4 first:border-t-0 first:pt-0">
      <h3 className="mb-2 text-sm font-semibold text-white">{title}</h3>
      {children}
    </section>
  );
}

function AlertBody({ alert }: { alert: AlertDetailOut }) {
  const normalized = obj(alert.normalized);
  const mitre = obj(normalized?.mitre);
  const email = emailSection(normalized);
  return (
    <>
      <Section title="Overview">
        <DefinitionList
          items={[
            ['Alert ID', <code key="id" className="text-xs">{alert.id}</code>],
            ['Source', `${alert.source_id} / ${alert.source_alert_id}`],
            ['Category', alert.category ?? '-'],
            ['Rule', text(normalized?.rule_name) ?? '-'],
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
        {text(normalized?.description) && <p className="mt-3 whitespace-pre-wrap text-sm text-slate-200">{text(normalized?.description)}</p>}
        {list(normalized?.flags).length > 0 && (
          <p className="mt-2 text-xs text-amber-200">Data quality flags: {list(normalized?.flags).join(', ')}</p>
        )}
      </Section>
      {email && (
        <Section title="Email">
          <EmailPanel section={email} phishing={obj(obj(alert.summary?.triage)?.phishing)} />
        </Section>
      )}
      <Section title="Verdict and reasoning">
        <Reasoning summary={alert.summary ?? {}} />
      </Section>
      <Section title="Entities">
        <Entities normalized={normalized} />
        {mitre && (list(mitre.tactics).length > 0 || list(mitre.techniques).length > 0) && (
          <p className="mt-3 text-sm text-slate-200">
            <span className="text-slate-400">MITRE ATT&CK: </span>
            {[...list(mitre.tactics), ...list(mitre.techniques)].join(', ')}
          </p>
        )}
      </Section>
      <Section title="Response actions">
        <ResponseActions alertId={alert.id} />
      </Section>
      <Section title="Tickets">
        <Tickets alertId={alert.id} />
      </Section>
      <Section title="Timeline">
        <Timeline alertId={alert.id} />
      </Section>
      <details className="border-t border-slate-800 py-4">
        <summary className="cursor-pointer text-sm font-semibold text-white">Normalized record</summary>
        <div className="mt-2">
          <JsonBlock value={alert.normalized} label="Normalized alert JSON" />
        </div>
      </details>
    </>
  );
}

export function AlertDrawer({ alertId, onClose }: { alertId: string | null; onClose: () => void }) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const [nis2, setNis2] = useState(false);
  const q = useQuery({
    queryKey: qk.alert.detail(alertId),
    queryFn: ({ signal }) => endpoints.alert(api, alertId as string, signal),
    enabled: Boolean(alertId),
  });
  const reprocess = useMutation({
    mutationFn: () => endpoints.reprocess(api, alertId as string),
    onSuccess: () => {
      setConfirm(false);
      toast.success('Alert queued for reprocessing.');
      void client.invalidateQueries({ queryKey: qk.alert.detail(alertId) });
      void client.invalidateQueries({ queryKey: qk.alerts.all });
    },
    onError: (err) => {
      setConfirm(false);
      if (err instanceof ApiError && err.code === 'run_active') toast.info('The alert is still being processed; try again when its run finishes.');
      else toast.error(err, 'Reprocess failed');
    },
  });
  const a = q.data;
  return (
    <Modal
      open={Boolean(alertId)}
      onClose={onClose}
      variant="drawer"
      size="lg"
      title={a ? a.title : 'Alert'}
      description={
        a ? (
          <span className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge value={a.severity} />
            <StatusBadge value={a.status} />
            <DispositionBadge value={a.disposition} />
          </span>
        ) : undefined
      }
      footer={
        a && can.reprocess(principal) ? (
          <Button onClick={() => setConfirm(true)} icon={<RotateCcw className="h-4 w-4" aria-hidden="true" />}>
            Reprocess
          </Button>
        ) : undefined
      }
    >
      {q.isPending && alertId && <LoadingState label="Loading alert" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {a && (
        <>
          <AlertBody alert={a} />
          <Section title="Evidence and reporting">
            <EvidenceActions alertId={a.id} />
            {can.addNote(principal) && (
              <>
                <Button size="sm" className="mt-3" onClick={() => setNis2(true)}>
                  Draft NIS2 report
                </Button>
                <IncidentReportDialog alertId={a.id} open={nis2} onClose={() => setNis2(false)} />
              </>
            )}
          </Section>
          {can.addNote(principal) && (
            <Section title="Notes">
              <NoteForm alertId={a.id} />
            </Section>
          )}
        </>
      )}
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
    </Modal>
  );
}
