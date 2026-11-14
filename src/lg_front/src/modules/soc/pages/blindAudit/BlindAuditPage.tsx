/**
 * Blind audit: analysts label a random sample of auto-closed alerts without
 * seeing the AI's verdict, confidence, routing or reasoning. The API sends
 * none of it before the label exists; once the label is saved the page shows
 * the AI's side and whether the two agree. Labels feed the production
 * false-negative estimate on the Reports page. Keyboard: M, B, U label the
 * sample; N (or Enter) moves to the next one.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../../../api/endpoints';
import { afterBlindAuditLabel } from '../../../../api/invalidate';
import { qk } from '../../../../api/queryKeys';
import type { AuditLabel, BlindAuditItemOut, BlindAuditLabelOut } from '../../../../api/types';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';
import { Badge, DispositionBadge, SeverityBadge } from '../../components/Badge';
import { useToast } from '../../../../components/Toast';
import { Banner, Button, Card, DefinitionList, EmptyState, ErrorMessage, JsonBlock, LoadingState, PageHeader, TextAreaField, cx } from '../../../../components/ui';
import { formatDateTime, formatInt, humanize } from '../../../../lib/format';
import { routingLabel } from '../escalations/labels';
import { SampleCard } from './SampleCard';
import { LABEL_CHOICES, NEXT_KEY, agreementText, isTypingTarget, labelForKey, labelText, normalizedFacts } from './labels';

function Evidence({ item }: { item: BlindAuditItemOut }) {
  const a = item.alert;
  const facts = normalizedFacts(a.normalized);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge value={a.severity} />
        {a.category && <Badge>{a.category}</Badge>}
        <span className="text-xs text-muted">Sample {formatInt(item.sample_rank)}</span>
      </div>
      <DefinitionList
        items={[
          ['Source', a.source_name ?? a.source_id],
          ['Occurred', formatDateTime(a.occurred_at)],
          ['Ingested', formatDateTime(a.ingested_at)],
          ...(a.entities_preview?.items ?? []).map((e): [string, string] => [humanize(e.kind), e.value]),
          ...facts,
        ]}
      />
      {a.raw && (
        <details>
          <summary className="cursor-pointer text-sm font-medium text-link">Source event</summary>
          <div className="mt-2">
            <JsonBlock value={a.raw} label="Source event" />
          </div>
        </details>
      )}
      {a.normalized && (
        <details>
          <summary className="cursor-pointer text-sm font-medium text-link">Normalized event</summary>
          <div className="mt-2">
            <JsonBlock value={a.normalized} label="Normalized event" />
          </div>
        </details>
      )}
    </div>
  );
}

function LabelForm({ busy, notes, onNotes, onLabel }: { busy: boolean; notes: string; onNotes: (v: string) => void; onLabel: (l: AuditLabel) => void }) {
  return (
    <form aria-label="Your label" onSubmit={(e) => e.preventDefault()} className="space-y-3">
      <fieldset>
        <legend className="mb-2 text-sm font-semibold text-fg">Your label</legend>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          {LABEL_CHOICES.map((c) => (
            <Button
              key={c.label}
              variant={c.label === 'malicious' ? 'destructive' : 'secondary'}
              size="lg"
              disabled={busy}
              aria-keyshortcuts={c.key.toUpperCase()}
              title={c.hint}
              onClick={() => onLabel(c.label)}
            >
              {c.text}
              <kbd className="rounded border border-control px-1.5 font-mono text-xs text-secondary">{c.key.toUpperCase()}</kbd>
            </Button>
          ))}
        </div>
      </fieldset>
      <TextAreaField label="Notes (optional)" rows={2} maxLength={4000} value={notes} onChange={(e) => onNotes(e.target.value)} />
      <p className="text-xs text-muted">The AI&apos;s verdict is hidden until you label. Malicious opens an escalation for the alert.</p>
    </form>
  );
}

function Reveal({ out, onNext, hasNext }: { out: BlindAuditLabelOut; onNext: () => void; hasNext: boolean }) {
  const r = out.item.reveal;
  return (
    <div className="space-y-4">
      <Banner tone={r?.agreement === false ? 'attention' : 'info'} role="status" title={`You labelled it ${labelText(out.item.label).toLowerCase()}.`}>
        {r ? agreementText(r) : 'The AI verdict is not available.'}
      </Banner>
      {r && (
        <DefinitionList
          items={[
            ['AI verdict when sampled', <DispositionBadge key="c" value={r.ai_class} />],
            ['Confidence', r.confidence === null ? '-' : `${Math.round(r.confidence)}%`],
            ['Threat score', r.threat_score === null ? '-' : formatInt(Math.round(r.threat_score))],
            ['Routing', r.routing_code ? routingLabel(r.routing_code) : '-'],
            ['Close reason', r.close_reason ? humanize(r.close_reason) : '-'],
            ['Reasoning', r.conclusion ?? '-'],
          ]}
        />
      )}
      {out.escalation_id && (
        <p className="text-sm text-body">
          {out.escalation_created ? 'An escalation was opened for this alert: ' : 'The alert already had an active escalation: '}
          <Link to={`/escalations/${encodeURIComponent(out.escalation_id)}`} className="text-link underline">
            open the escalation
          </Link>
          .
        </p>
      )}
      <Button variant="primary" onClick={onNext} aria-keyshortcuts="N">
        {hasNext ? 'Next sample' : 'Back to the queue'}
        <kbd className="rounded border border-on-accent/40 px-1.5 font-mono text-xs">N</kbd>
      </Button>
    </div>
  );
}

export default function BlindAuditPage() {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const { principal } = useAuth();
  const [selected, setSelected] = useState<string | null>(null);
  const [result, setResult] = useState<BlindAuditLabelOut | null>(null);
  const [notes, setNotes] = useState('');

  const queue = useQuery({
    queryKey: qk.blindAudit.queue('pending'),
    queryFn: ({ signal }) => endpoints.blindAuditItems(api, 'pending', undefined, signal),
  });
  const items = queue.data?.items ?? [];
  const currentId = result ? null : (selected ?? items[0]?.id ?? null);
  const item = useQuery({
    queryKey: qk.blindAudit.item(currentId ?? ''),
    queryFn: ({ signal }) => endpoints.blindAuditItem(api, currentId as string, signal),
    enabled: currentId !== null,
  });

  const label = useMutation({
    mutationFn: (l: AuditLabel) => endpoints.labelBlindAuditItem(api, currentId as string, { label: l, notes: notes.trim() || null }),
    onSuccess: (out) => {
      setResult(out);
      setNotes('');
      void afterBlindAuditLabel(qc, out.escalation_created);
    },
    onError: (err) => toast.error(err, 'The label was not saved'),
  });

  const next = () => {
    setResult(null);
    setSelected(null);
  };
  const ready = currentId !== null && item.isSuccess && !label.isPending;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || isTypingTarget(e.target)) return;
      if (result) {
        if (e.key.toLowerCase() === NEXT_KEY || (e.key === 'Enter' && e.target === document.body)) {
          e.preventDefault();
          next();
        }
        return;
      }
      const chosen = labelForKey(e.key);
      if (chosen && ready) {
        e.preventDefault();
        label.mutate(chosen);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [result, ready, label]);

  return (
    <>
      <PageHeader
        title="Blind audit"
        description="A random sample of the alerts automation closed. Label each one from the evidence alone: the AI's verdict is shown only after you label. Shortcuts: M malicious, B benign, U unsure, N next."
      />
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div>
          {result ? (
            <Card title={result.item.alert.title}>
              <Reveal out={result} onNext={next} hasNext={items.length > 0} />
            </Card>
          ) : queue.isPending ? (
            <LoadingState label="Loading the blind audit queue" />
          ) : queue.isError ? (
            <ErrorMessage error={queue.error} onRetry={() => void queue.refetch()} />
          ) : currentId === null ? (
            <EmptyState title="Nothing to label">
              No sample is waiting. Samples are drawn every week when the tenant setting is on, or on demand by an admin (below, or
              lg-sotf audit-sample).
            </EmptyState>
          ) : item.isError ? (
            <ErrorMessage error={item.error} onRetry={() => void item.refetch()} />
          ) : !item.isSuccess ? (
            <LoadingState label="Loading the sample" />
          ) : (
            <Card title={item.data.alert.title}>
              <div className="space-y-5">
                <Evidence item={item.data} />
                <LabelForm busy={label.isPending} notes={notes} onNotes={setNotes} onLabel={(l) => label.mutate(l)} />
              </div>
            </Card>
          )}
        </div>
        <div className="space-y-5">
          <Card title={`Waiting for a label (${formatInt(items.length)}${queue.data?.next_cursor ? '+' : ''})`}>
            {items.length === 0 ? (
              <p className="text-sm text-muted">The queue is empty.</p>
            ) : (
              <ul className="max-h-[28rem] space-y-1 overflow-auto" aria-label="Samples waiting for a label">
                {items.map((i) => (
                  <li key={i.id}>
                    <button
                      type="button"
                      aria-current={i.id === currentId ? 'true' : undefined}
                      onClick={() => {
                        setResult(null);
                        setSelected(i.id);
                      }}
                      className={cx(
                        'w-full rounded-control px-2 py-1.5 text-left text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus touch:min-h-11',
                        i.id === currentId ? 'bg-raised-2 text-fg' : 'text-body hover:bg-raised-2',
                      )}
                    >
                      <span className="block truncate">{i.alert.title}</span>
                      <span className="block text-xs text-muted">
                        {humanize(i.alert.severity)} · {formatDateTime(i.alert.occurred_at)}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          {can.admin(principal) && <SampleCard />}
        </div>
      </div>
    </>
  );
}
