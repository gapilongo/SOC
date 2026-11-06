import { useMutation } from '@tanstack/react-query';

import { endpoints } from '../api/endpoints';
import type { LlmTierCheckOut } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { Badge } from './Badge';
import { Button, Card, ErrorMessage } from './ui';

/** "1.2 s" / "340 ms": latency as an admin reads it. */
export function formatLatency(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`;
}

function TierRow({ t }: { t: LlmTierCheckOut }) {
  return (
    <tr className="border-t border-subtle align-top">
      <th scope="row" className="px-3 py-2 font-medium capitalize text-body">
        {t.tier}
      </th>
      <td className="px-3 py-2 font-mono text-xs text-secondary break-all">{t.model}</td>
      <td className="px-3 py-2">
        <Badge tone={t.ok ? 'good' : 'bad'}>{t.ok ? 'ok' : (t.error_code ?? 'failed').replace(/_/g, ' ')}</Badge>
      </td>
      <td className="px-3 py-2 text-secondary">{t.ok || t.latency_ms > 0 ? formatLatency(t.latency_ms) : '-'}</td>
      <td className="px-3 py-2 text-secondary">{t.ok ? (t.structured_output ?? '') : t.error}</td>
    </tr>
  );
}

/** Settings card: send a tiny probe to the fast and deep model tiers and show what happened. */
export function LlmTestCard() {
  const api = useApi();
  const test = useMutation({ mutationFn: () => endpoints.testLlm(api) });
  const out = test.data;
  return (
    <Card
      title="Language model"
      actions={
        <Button onClick={() => test.mutate()} busy={test.isPending}>
          Test model
        </Button>
      }
    >
      <div className="space-y-3 text-sm">
        <p className="text-secondary">
          Sends a tiny request (no alert data) to the fast and deep tiers of the configured model and checks that each answers in the format triage needs. It counts toward this tenant's LLM usage.
        </p>
        {test.error ? <ErrorMessage error={test.error} compact /> : null}
        {out && (
          <div aria-live="polite" className="space-y-2">
            <p className="flex flex-wrap items-center gap-2 text-body">
              Provider <span className="font-mono text-xs">{out.provider}</span>
              <Badge tone={out.ok ? 'good' : 'bad'}>{out.ok ? 'both tiers answered' : 'check failed'}</Badge>
            </p>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[480px] text-left text-sm">
                <caption className="sr-only">Model test results</caption>
                <thead className="text-xs uppercase tracking-wide text-muted">
                  <tr>
                    <th scope="col" className="px-3 py-2">Tier</th>
                    <th scope="col" className="px-3 py-2">Model</th>
                    <th scope="col" className="px-3 py-2">Result</th>
                    <th scope="col" className="px-3 py-2">Latency</th>
                    <th scope="col" className="px-3 py-2">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {out.tiers.map((t) => (
                    <TierRow key={t.tier} t={t} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
