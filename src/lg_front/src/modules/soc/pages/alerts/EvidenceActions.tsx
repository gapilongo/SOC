import { useMutation } from '@tanstack/react-query';
import { Download, ExternalLink } from 'lucide-react';

import { endpoints } from '../../api/endpoints';
import { useApi } from '../../../../auth/AuthContext';
import { useToast } from '../../../../components/Toast';
import { Button } from '../../../../components/ui';
import { downloadBlob, openHtmlBlob } from '../../../../lib/download';

type Kind = 'json' | 'html' | 'open';

/**
 * "Export evidence": the alert's evidence pack (alert, timeline, agent
 * reasoning, decisions, response ledger, audit entries with hash-chain
 * verification, bundle hash and signature) as JSON or self-contained HTML.
 * Every export is recorded in the tenant's audit log by the API.
 */
export function EvidenceActions({ alertId }: { alertId: string }) {
  const api = useApi();
  const toast = useToast();
  const m = useMutation({
    mutationFn: async (kind: Kind) => ({ kind, blob: await endpoints.evidencePack(api, alertId, kind === 'json' ? 'json' : 'html') }),
    onSuccess: ({ kind, blob }) => {
      if (kind === 'open') openHtmlBlob(blob);
      else downloadBlob(`evidence-${alertId}.${kind}`, blob);
    },
    onError: (err) => toast.error(err, 'Evidence export failed'),
  });
  const busy = (kind: Kind) => m.isPending && m.variables === kind;
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted">
        A reconstructable record of this case with a SHA-256 bundle hash and the related audit-log entries. Exports are audited.
      </p>
      <div className="flex flex-wrap gap-2" role="group" aria-label="Export evidence">
        <Button size="sm" busy={busy('json')} disabled={m.isPending} onClick={() => m.mutate('json')} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
          Download JSON
        </Button>
        <Button size="sm" busy={busy('html')} disabled={m.isPending} onClick={() => m.mutate('html')} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
          Download HTML
        </Button>
        <Button size="sm" busy={busy('open')} disabled={m.isPending} onClick={() => m.mutate('open')} icon={<ExternalLink className="h-4 w-4" aria-hidden="true" />}>
          Open HTML
        </Button>
      </div>
    </div>
  );
}
