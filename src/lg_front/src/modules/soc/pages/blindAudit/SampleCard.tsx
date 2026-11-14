/**
 * Admins: draw a blind-audit sample now (the proof-of-value random sample, or
 * a catch-up between weekly runs) and see the recent runs with their seed and
 * sampling frame. A run covers the alerts closed since the previous run ended.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../../../../api/endpoints';
import { afterBlindAuditSample } from '../../../../api/invalidate';
import { qk } from '../../../../api/queryKeys';
import { useApi } from '../../../../auth/AuthContext';
import { useToast } from '../../../../components/Toast';
import { Button, Card, ErrorMessage, TextField } from '../../../../components/ui';
import { formatDateTime, formatInt } from '../../../../lib/format';

/** The size field: empty (the tenant's rate) or a whole number from 1 to 2000. */
export function parseSize(value: string): number | null | 'invalid' {
  const v = value.trim();
  if (!v) return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 2000 ? n : 'invalid';
}

export function SampleCard() {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const [size, setSize] = useState('');
  const runs = useQuery({ queryKey: qk.blindAudit.runs, queryFn: ({ signal }) => endpoints.blindAuditRuns(api, signal) });
  const parsed = parseSize(size);
  const sample = useMutation({
    mutationFn: () => endpoints.sampleBlindAudit(api, parsed === null || parsed === 'invalid' ? {} : { size: parsed }),
    onSuccess: (run) => {
      toast.success(`Sampled ${formatInt(run.sample_size)} of ${formatInt(run.frame_size)} auto-closed alerts.`);
      setSize('');
      void afterBlindAuditSample(qc);
    },
    onError: (err) => toast.error(err, 'Sampling failed'),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (parsed !== 'invalid') sample.mutate();
  };
  return (
    <Card title="Sampling runs">
      <form onSubmit={submit} className="space-y-2" aria-label="Draw a sample">
        <TextField
          label="Sample size (optional)"
          inputMode="numeric"
          value={size}
          onChange={(e) => setSize(e.target.value)}
          hint="Empty: the tenant's rate. Covers alerts closed since the last run."
          error={parsed === 'invalid' ? 'A whole number from 1 to 2000.' : null}
        />
        <Button type="submit" busy={sample.isPending} disabled={parsed === 'invalid'}>
          Draw a sample now
        </Button>
      </form>
      <div className="mt-4">
        {runs.isError ? (
          <ErrorMessage error={runs.error} compact />
        ) : (
          <ul className="space-y-2 text-xs text-secondary" aria-label="Recent runs">
            {(runs.data?.items ?? []).slice(0, 5).map((r) => (
              <li key={r.id}>
                <span className="block text-body">
                  {formatDateTime(r.window_start)} to {formatDateTime(r.window_end)}
                </span>
                {formatInt(r.sample_size)} of {formatInt(r.frame_size)} sampled ({r.trigger}, seed {r.seed}); {formatInt(r.malicious + r.benign + r.unsure)}{' '}
                labelled, {formatInt(r.malicious)} malicious
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
