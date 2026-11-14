/** The investigation side of the decision page: ARIA tabs over what the alert and its analysis recorded. */

import { useMutation, useQuery } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { formatEntities, readAiReason, readFindings } from '../../api/fields';
import { qk } from '../../api/queryKeys';
import type { AlertDetailOut, AlertEventOut, EscalationOut, FindingOut } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { TicketLinks } from '../../components/TicketLinks';
import { useToast } from '../../../../components/Toast';
import { Banner, Button, EmptyState, ErrorMessage, JsonBlock, LoadingState, cx } from '../../../../components/ui';
import { downloadBlob } from '../../../../lib/download';
import { formatDateTime, humanize, shortId } from '../../../../lib/format';
import { alertsHref } from '../../lib/links';
import { useKeysetList } from '../../../../lib/pagination';
import { readEntities, readEvidence, type EvidenceDigest, type Indicator } from './evidence';
import { Tabs, type TabDef } from './Tabs';

export type InvestigationTab = 'summary' | 'evidence' | 'entities' | 'timeline' | 'raw';

export const INVESTIGATION_TABS: ReadonlyArray<TabDef<InvestigationTab>> = [
  { id: 'summary', label: 'Summary' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'entities', label: 'Entities' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'raw', label: 'Raw' },
];

const BY_LABEL: Record<Indicator['by'], string> = { rule: 'rule', model: 'model', analysis: 'analysis' };

function Panel({ title, eyebrow = false, actions, children, className }: { title: string; eyebrow?: boolean; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section aria-label={title} className={cx('flex flex-col gap-3 rounded-card border border-subtle bg-raised p-4 md:p-[18px]', className)}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className={eyebrow ? 'eyebrow text-link' : 'text-sm font-semibold text-fg'}>{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

const KIND_LABELS: Record<string, string> = { ip: 'IP', url: 'URL', hash: 'File hash', email: 'E-mail' };

function findingText(f: FindingOut): string {
  const target = f.target ? ` ${f.target}` : '';
  return `${KIND_LABELS[f.kind] ?? humanize(f.kind)}${target}: ${f.verdict || f.status}`;
}

function FindingMeta({ f }: { f: FindingOut }) {
  return (
    <span className="text-xs text-secondary">
      Source: {f.source}
      {f.checked_at ? <> · checked {formatDateTime(f.checked_at)}</> : null}
      {f.cached ? ' · from cache' : null}
      {f.origin === 'history' ? ' · tenant history' : null}
    </span>
  );
}

function Indicators({ title, items, dot }: { title: string; items: Indicator[]; dot: string }) {
  return (
    <section aria-label={title} className="rounded-card border border-subtle bg-raised p-4">
      <h2 className="mb-2.5 flex items-center gap-2 text-sm font-semibold text-fg">
        <span className={cx('h-2 w-2 rounded-full', dot)} aria-hidden="true" />
        {title}
      </h2>
      {items.length ? (
        <ul className="flex list-disc flex-col gap-1.5 pl-[18px] text-ctl text-body">
          {items.map((i) => (
            <li key={`${i.by}-${i.text}`}>
              {i.text} <span className="text-secondary">({BY_LABEL[i.by]})</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-ctl text-secondary">The analysis recorded none.</p>
      )}
    </section>
  );
}

function Summary({ escalation, alert, digest, findings, onShowEvidence }: { escalation: EscalationOut; alert: AlertDetailOut | undefined; digest: EvidenceDigest; findings: FindingOut[]; onShowEvidence: () => void }) {
  const reason = readAiReason(escalation);
  const basis = [
    digest.llmUsed === null ? null : digest.llmUsed ? 'Written by the model' : 'Written by the rules',
    findings.length ? `Evidence: ${findings.length} lookup${findings.length === 1 ? '' : 's'}` : 'Evidence: no lookups recorded',
    digest.verdict ? `Verdict: ${humanize(digest.verdict)}` : null,
    digest.threatScore !== null ? `Threat score ${Math.round(digest.threatScore)}` : null,
  ].filter((b): b is string => Boolean(b));
  const related = escalation.related_alert_ids ?? [];
  return (
    <div className="flex flex-col gap-3.5">
      <Panel
        title="What the agents found"
        eyebrow
        actions={
          <ul aria-label="Basis of this verdict" className="flex flex-wrap gap-1.5 text-xs">
            {basis.map((b) => (
              <li key={b} className="rounded-tag bg-raised-2 px-2 py-0.5 text-body">
                {b}
              </li>
            ))}
          </ul>
        }
      >
        {digest.conclusion ? (
          <p className="whitespace-pre-wrap text-sm text-fg">{digest.conclusion}</p>
        ) : reason ? (
          <p className="text-sm text-fg">{reason.text}</p>
        ) : (
          <p className="text-sm text-secondary">The analysis recorded no conclusion.</p>
        )}
        {digest.modelRefused && <p className="text-ctl text-warn-fg">The model declined to assess this alert; rule results were used.</p>}
        {digest.budgetExceeded && <p className="text-ctl text-warn-fg">The tenant’s daily LLM budget was exhausted; this alert was assessed by rules only.</p>}
        {findings.length > 0 && (
          <ol className="flex flex-col gap-2.5">
            {findings.slice(0, 4).map((f, i) => (
              <li key={`${f.source}-${f.target}-${i}`} className="flex flex-col gap-0.5 border-b border-subtle pb-2.5 last:border-b-0 last:pb-0">
                <span className="text-sm text-fg [overflow-wrap:anywhere]">{findingText(f)}</span>
                <FindingMeta f={f} />
              </li>
            ))}
          </ol>
        )}
        {findings.length > 4 && (
          <Button size="sm" variant="quiet" className="self-start" onClick={onShowEvidence}>
            All {findings.length} lookups in Evidence
          </Button>
        )}
      </Panel>
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(min(260px,100%),1fr))]">
        <Indicators title="Points to malicious" items={digest.malicious} dot="bg-state-bad" />
        <Indicators title="Points to benign" items={digest.benign} dot="bg-state-ok" />
      </div>
      {(digest.recommended.length > 0 || related.length > 0 || alert) && (
        <Panel title="Context">
          <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-ctl sm:grid-cols-[max-content_1fr]">
            {digest.recommended.length > 0 && (
              <>
                <dt className="text-secondary">Recommended by the analysis</dt>
                <dd className="text-fg">{digest.recommended.map(humanize).join(', ')}</dd>
              </>
            )}
            {alert && (
              <>
                <dt className="text-secondary">Source</dt>
                <dd className="break-words text-fg">{alert.source_name ?? escalation.source_name ?? alert.source_id}</dd>
                <dt className="text-secondary">Occurred</dt>
                <dd className="text-fg">{formatDateTime(alert.occurred_at)}</dd>
              </>
            )}
            {related.length > 0 && (
              <>
                <dt className="text-secondary">Attached alerts</dt>
                <dd>
                  <ul className="flex flex-wrap gap-x-3 gap-y-1">
                    {related.map((id) => (
                      <li key={id}>
                        <Link to={alertsHref({ alert: id })} className="font-mono text-xs text-link hover:text-link-hover hover:underline">
                          Alert {shortId(id)}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            <dt className="text-secondary">Tickets</dt>
            <dd>
              <Tickets escalationId={escalation.id} />
            </dd>
          </dl>
        </Panel>
      )}
    </div>
  );
}

function Tickets({ escalationId }: { escalationId: string }) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.tickets.forEscalations([escalationId]),
    queryFn: ({ signal }) => endpoints.tickets(api, { escalation_id: [escalationId] }, signal),
  });
  if (q.isPending) return <span className="text-xs text-secondary">Loading…</span>;
  const tickets = Array.isArray(q.data) ? q.data : [];
  if (!tickets.length) return <span className="text-secondary">None linked</span>;
  return <TicketLinks tickets={tickets} />;
}

function FindingRow({ f }: { f: FindingOut }) {
  const [open, setOpen] = useState(false);
  const hasData = Boolean(f.data && Object.keys(f.data).length);
  return (
    <li className="flex flex-col gap-1 border-b border-subtle pb-2.5 last:border-b-0 last:pb-0">
      <span className="text-ctl text-fg">{findingText(f)}</span>
      <span className="flex flex-wrap items-center gap-x-2">
        <FindingMeta f={f} />
        {hasData && (
          <Button size="sm" variant="quiet" className="min-h-0 px-1 py-0 text-xs" aria-expanded={open} onClick={() => setOpen(!open)}>
            {open ? 'Hide raw' : 'View raw'}
          </Button>
        )}
      </span>
      {open && <JsonBlock value={f.data} label={`Raw result of ${f.source} for ${f.target}`} />}
    </li>
  );
}

function EvidencePack({ alertId }: { alertId: string }) {
  const api = useApi();
  const toast = useToast();
  const m = useMutation({
    mutationFn: () => endpoints.evidencePack(api, alertId, 'json'),
    onSuccess: (blob) => downloadBlob(`evidence-${alertId}.json`, blob),
    onError: (err) => toast.error(err, 'Evidence export failed'),
  });
  return (
    <Button size="sm" className="self-start" busy={m.isPending} onClick={() => m.mutate()} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
      Download evidence pack (JSON)
    </Button>
  );
}

function Evidence({ alertId, digest, findings }: { alertId: string; digest: EvidenceDigest; findings: FindingOut[] }) {
  const intel = findings.filter((f) => f.origin === 'threat_intel');
  const history = findings.filter((f) => f.origin === 'history');
  return (
    <div className="flex flex-col gap-3.5">
      <Panel title="Provider lookups">
        {intel.length ? (
          <ul className="flex flex-col gap-2.5">
            {intel.map((f, i) => (
              <FindingRow key={`${f.source}-${f.target}-${i}`} f={f} />
            ))}
          </ul>
        ) : (
          <p className="text-ctl text-secondary">No threat-intelligence lookup was recorded for this alert.</p>
        )}
      </Panel>
      {history.length > 0 && (
        <Panel title="Tenant history">
          <ul className="flex flex-col gap-2.5">
            {history.map((f, i) => (
              <FindingRow key={`${f.source}-${f.target}-${i}`} f={f} />
            ))}
          </ul>
        </Panel>
      )}
      {(digest.ruleEvidence.length > 0 || digest.reasoning.length > 0) && (
        <Panel title="Analysis reasoning">
          {digest.ruleEvidence.length > 0 && (
            <div>
              <h3 className="mb-1 text-xs font-semibold text-secondary">Rule evidence</h3>
              <ul className="list-disc space-y-1 pl-5 text-ctl text-body">
                {digest.ruleEvidence.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </div>
          )}
          {digest.reasoning.length > 0 && (
            <div>
              <h3 className="mb-1 text-xs font-semibold text-secondary">Steps</h3>
              <ol className="list-decimal space-y-1 pl-5 text-ctl text-body">
                {digest.reasoning.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ol>
            </div>
          )}
        </Panel>
      )}
      <Panel title="Evidence pack">
        <p className="text-xs text-secondary">The alert, its timeline, the agents’ reasoning, decisions, response ledger and audit entries, hashed. Exports are audited.</p>
        <EvidencePack alertId={alertId} />
      </Panel>
    </div>
  );
}

function Entities({ alert, escalation }: { alert: AlertDetailOut | undefined; escalation: EscalationOut }) {
  const entities = readEntities(alert);
  const preview = formatEntities(escalation.entities_preview, 8);
  return (
    <Panel title="Entities">
      {entities.length ? (
        <dl className="grid grid-cols-1 gap-x-3 gap-y-2 text-ctl sm:grid-cols-[140px_1fr]">
          {entities.map(([kind, values]) => (
            <div key={kind} className="contents">
              <dt className="text-secondary">{humanize(kind)}</dt>
              <dd className="flex min-w-0 flex-wrap gap-1.5">
                {values.map((v, i) => (
                  <code key={`${v}-${i}`} className="max-w-full break-all rounded-tag bg-raised-2 px-1.5 py-0.5 font-mono text-xs text-fg">
                    {v}
                  </code>
                ))}
              </dd>
            </div>
          ))}
        </dl>
      ) : preview ? (
        <p className="break-words font-mono text-xs text-fg">{preview}</p>
      ) : (
        <p className="text-ctl text-secondary">No entities were extracted.</p>
      )}
    </Panel>
  );
}

function eventSummary(e: AlertEventOut): string {
  const d = e.data ?? {};
  if (e.event_type === 'note' && typeof d.text === 'string') return d.text;
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
  return (
    <Panel title="Timeline">
      {q.isPending && <LoadingState label="Loading timeline" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />}
      {q.isSuccess && q.items.length === 0 && <EmptyState title="No events yet" />}
      {q.items.length > 0 && (
        <ol className="flex flex-col gap-2 text-ctl">
          {q.items.map((e) => {
            const detail = eventSummary(e);
            return (
              <li key={e.id} className="flex flex-wrap justify-between gap-x-3 border-b border-subtle pb-2 last:border-b-0">
                <span className="min-w-0">
                  <span className="font-medium text-fg">{humanize(e.event_type)}</span>
                  <span className="text-secondary">
                    {' '}
                    by {e.actor_type}
                    {e.node ? ` · ${e.node}` : ''}
                  </span>
                  {detail && <span className="block whitespace-pre-wrap break-words text-body">{detail}</span>}
                </span>
                <time dateTime={e.ts} className="whitespace-nowrap text-xs text-secondary">
                  {formatDateTime(e.ts)}
                </time>
              </li>
            );
          })}
        </ol>
      )}
      {q.hasNextPage && (
        <Button size="sm" className="self-start" onClick={() => void q.fetchNextPage()} busy={q.isFetchingNextPage}>
          Load older events
        </Button>
      )}
    </Panel>
  );
}

function Raw({ alert, escalation }: { alert: AlertDetailOut | undefined; escalation: EscalationOut }) {
  return (
    <div className="flex flex-col gap-3.5">
      <Panel title="Raw alert">
        <JsonBlock value={alert?.raw ?? null} label="Raw alert JSON" />
      </Panel>
      <Panel title="Normalized alert">
        <JsonBlock value={alert?.normalized ?? null} label="Normalized alert JSON" />
      </Panel>
      <Panel title="Escalation summary">
        <JsonBlock value={escalation.summary ?? null} label="Escalation summary JSON" />
      </Panel>
    </div>
  );
}

/**
 * The tabs of the decision page. `alert` is the escalation's alert detail
 * (undefined while it loads or when it failed: the tabs then show what the
 * escalation itself carries).
 */
export function Investigation({
  escalation,
  alert,
  alertState,
}: {
  escalation: EscalationOut;
  alert: AlertDetailOut | undefined;
  alertState: { isPending: boolean; error: unknown; retry: () => void };
}) {
  const [tab, setTab] = useState<InvestigationTab>('summary');
  const digest = readEvidence(alert, escalation);
  const findings = alert ? readFindings(alert) : [];
  return (
    <section aria-label="Investigation" className="flex min-w-0 flex-col gap-3.5">
      {digest.simulated && (
        <Banner tone="warning" role="alert" title="Some evidence was simulated">
          At least one lookup behind this verdict did not come from a real provider. Verify the evidence before you decide.
        </Banner>
      )}
      {alertState.isPending && <LoadingState label="Loading the alert" />}
      {alertState.error !== null && <ErrorMessage error={alertState.error} onRetry={alertState.retry} compact />}
      <Tabs label="Investigation sections" tabs={INVESTIGATION_TABS} value={tab} onChange={setTab}>
        {tab === 'summary' && <Summary escalation={escalation} alert={alert} digest={digest} findings={findings} onShowEvidence={() => setTab('evidence')} />}
        {tab === 'evidence' && <Evidence alertId={escalation.alert_id} digest={digest} findings={findings} />}
        {tab === 'entities' && <Entities alert={alert} escalation={escalation} />}
        {tab === 'timeline' && <Timeline alertId={escalation.alert_id} />}
        {tab === 'raw' && <Raw alert={alert} escalation={escalation} />}
      </Tabs>
    </section>
  );
}
