import { useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterAlertTimelineChange } from '../../api/invalidate';
import type { IncidentReportField, IncidentReportOut, IncidentReportStage } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { Badge } from '../../components/Badge';
import { Modal } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Button, Checkbox, ErrorMessage } from '../../components/ui';
import { formatDateTime } from '../../lib/format';
import { downloadBlob } from '../../lib/download';

export const STAGES: ReadonlyArray<{ value: IncidentReportStage; label: string; hint: string }> = [
  { value: 'early_warning', label: 'Early warning (24 h)', hint: 'Suspected unlawful or malicious act, possible cross-border impact.' },
  { value: 'notification', label: 'Incident notification (72 h)', hint: 'Initial assessment, severity and impact, indicators of compromise.' },
  { value: 'final', label: 'Final report (1 month)', hint: 'Detailed description, root cause, mitigations, cross-border impact.' },
];

export const AI_LABEL = 'AI-drafted — review required';
const TO_COMPLETE = '— to be completed by you —';

function FieldRow({ field }: { field: IncidentReportField }) {
  return (
    <div className="border-b border-slate-800 py-2 last:border-b-0">
      <dt className="flex flex-wrap items-center gap-2 text-xs font-medium text-slate-300">
        <span>
          {field.label}
          {field.required && <span className="text-slate-500"> (required)</span>}
        </span>
        {field.source === 'requires_human' && <Badge tone="warn">Needs your input</Badge>}
        {field.source === 'ai_drafted' && <Badge tone="info">{AI_LABEL}</Badge>}
      </dt>
      <dd className="mt-0.5 whitespace-pre-wrap break-words text-sm text-slate-100">
        {field.value ?? <span className="italic text-slate-400">{TO_COMPLETE}</span>}
      </dd>
      {field.help && <p className="mt-0.5 text-xs text-slate-400">{field.help}</p>}
    </div>
  );
}

function Draft({ report }: { report: IncidentReportOut }) {
  const toast = useToast();
  const copy = async () => {
    const { html: _html, ...data } = report;
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
      toast.success('Draft copied as JSON.');
    } catch {
      toast.info('The clipboard is not available in this browser.');
    }
  };
  return (
    <div className="space-y-3">
      <p role="note" className="rounded border border-amber-600 bg-amber-950 px-3 py-2 text-sm font-medium text-amber-100">
        {report.disclaimer}
      </p>
      <p className="text-sm text-slate-300">
        <span className="text-slate-400">Deadline: </span>
        {report.deadline_hint}
        <span className="text-slate-500"> · generated {formatDateTime(report.generated_at)}</span>
      </p>
      <dl>{report.fields.map((f) => <FieldRow key={f.key} field={f} />)}</dl>
      {report.ai_narrative && (
        <section className="rounded border border-sky-800 bg-slate-950 p-3" aria-label="AI-drafted narrative">
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <Badge tone="info">{report.ai_narrative.label || AI_LABEL}</Badge>
            <span className="text-xs text-slate-400">
              {report.ai_narrative.provider} / {report.ai_narrative.model}
            </span>
          </div>
          <p className="whitespace-pre-wrap text-sm text-slate-100">{report.ai_narrative.text}</p>
        </section>
      )}
      {report.ai_narrative_error && <p className="text-xs text-slate-400">No AI narrative: {report.ai_narrative_error}</p>}
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          onClick={() => downloadBlob(`nis2-${report.stage}-${report.alert_id}.html`, new Blob([report.html], { type: 'text/html' }))}
        >
          Download HTML
        </Button>
        <Button size="sm" onClick={() => void copy()}>
          Copy as JSON
        </Button>
      </div>
    </div>
  );
}

/** "Draft NIS2 report": a prefilled Article 23 draft for a person to complete and submit. */
export function IncidentReportDialog({ alertId, open, onClose }: { alertId: string; open: boolean; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const [stage, setStage] = useState<IncidentReportStage>('early_warning');
  const [withAi, setWithAi] = useState(true);
  const m = useMutation({
    mutationFn: () => endpoints.incidentReport(api, alertId, stage, withAi),
    onSuccess: () => void afterAlertTimelineChange(client, alertId),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    m.mutate();
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title="Draft NIS2 incident report"
      description="Prefilled from the case data. LG-SOTF does not submit anything: a person completes, reviews and submits the report to the CSIRT or competent authority."
    >
      <form onSubmit={submit} className="space-y-4">
        <fieldset>
          <legend className="mb-1 text-xs font-medium text-slate-300">Stage</legend>
          <div className="space-y-1.5">
            {STAGES.map((s) => (
              <label key={s.value} className="flex items-start gap-2 text-sm text-slate-200">
                <input
                  type="radio"
                  name="nis2-stage"
                  value={s.value}
                  checked={stage === s.value}
                  onChange={() => setStage(s.value)}
                  className="mt-1"
                />
                <span>
                  {s.label}
                  <span className="block text-xs text-slate-400">{s.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <Checkbox
          label="Include AI-drafted narrative (if an LLM is configured)"
          hint="Alert content is passed to the model as untrusted data; the narrative is marked for review."
          checked={withAi}
          onChange={(e) => setWithAi(e.target.checked)}
        />
        {m.isError && <ErrorMessage error={m.error} compact />}
        <Button type="submit" variant="primary" busy={m.isPending} icon={<FileText className="h-4 w-4" aria-hidden="true" />}>
          Generate draft
        </Button>
      </form>
      {m.data && (
        <div className="mt-5 border-t border-slate-800 pt-4">
          <Draft report={m.data} />
        </div>
      )}
    </Modal>
  );
}
