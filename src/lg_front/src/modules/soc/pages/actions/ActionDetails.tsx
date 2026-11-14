import { useQueryClient } from '@tanstack/react-query';
import { RefreshCcw, RotateCcw, Undo2 } from 'lucide-react';
import { useState, type ReactNode } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterActionChange } from '../../api/invalidate';
import type { ActionOut, JsonObject } from '../../api/types';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';
import { useToast } from '../../../../components/Toast';
import { Button, DefinitionList, JsonBlock } from '../../../../components/ui';
import { formatDateTime, humanize, shortId } from '../../../../lib/format';
import { asObjectOrNull } from '../../../../lib/json';
import { RetryDialog } from './RetryDialog';
import { RollbackDialog } from './RollbackDialog';
import { VerificationBadge } from './VerificationBadge';

const FINAL_VERIFICATION = new Set(['verified', 'failed', 'inconclusive']);

/** Readable reasons a rollback is not available (lg_sotf.services.rollback ROLLBACK_REASONS). */
export const ROLLBACK_REASONS: Record<string, string> = {
  not_executed: 'Only a succeeded (or partially failed) action can be rolled back.',
  is_rollback: 'A rollback cannot itself be rolled back.',
  irreversible: 'This action cannot be undone.',
  nothing_changed: 'The action changed nothing, so there is nothing to undo.',
  window_expired: 'The rollback window of this action has passed.',
  rollback_exists: 'A rollback of this action already exists.',
  connector_unsupported: 'The connector that executed this action cannot roll it back.',
  integration_gone: 'The Microsoft integration that executed this action was deleted: undo it in Microsoft.',
};

/** A failed Microsoft action whose failure is worth another attempt (and that no rollback undoes). */
export function canRetry(action: ActionOut): boolean {
  const result = action.result ?? {};
  return (
    action.status === 'failed' &&
    action.connector === 'microsoft' &&
    !action.rolled_back_by &&
    (result.retryable === true || result.error === 'partial')
  );
}

/** A succeeded Microsoft action whose verification finished (and can be re-checked). */
export function canRecheck(action: ActionOut): boolean {
  return action.connector === 'microsoft' && action.status === 'succeeded' && FINAL_VERIFICATION.has(action.verification ?? '');
}

function Steps({ steps }: { steps: JsonObject[] }) {
  const columns = Array.from(new Set(steps.flatMap((s) => Object.keys(s)))).slice(0, 6);
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full text-left text-xs">
        <caption className="sr-only">Steps</caption>
        <thead className="text-muted">
          <tr>
            {columns.map((c) => (
              <th key={c} scope="col" className="px-2 py-1 font-medium">
                {humanize(c)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {steps.slice(0, 200).map((step, i) => (
            <tr key={i} className="border-t border-subtle">
              {columns.map((c) => (
                <td key={c} className="break-all px-2 py-1 text-body">
                  {typeof step[c] === 'object' ? JSON.stringify(step[c]) : String(step[c] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Everything the ledger knows about one action: outcome, verification, connector state and rollback lineage. */
export function ActionDetails({
  action,
  onSelectAction,
  lead = [],
}: {
  action: ActionOut;
  onSelectAction?: (id: string) => void;
  /** Rows shown first in the same list (the ledger moves its long target and details here). */
  lead?: Array<[ReactNode, ReactNode]>;
}) {
  const result = action.result ?? null;
  const ref = action.external_ref ?? null;
  const steps = Array.isArray(ref?.steps) ? (ref?.steps as unknown[]).map(asObjectOrNull).filter((s): s is JsonObject => s !== null) : [];
  const summary = typeof result?.summary === 'string' ? result.summary : null;
  const hint = typeof result?.hint === 'string' ? result.hint : null;
  const link = (id: string | null | undefined, label: string) =>
    id ? (
      onSelectAction ? (
        <Button size="sm" variant="quiet" onClick={() => onSelectAction(id)} aria-label={`${label} ${id}`}>
          {shortId(id)}
        </Button>
      ) : (
        <code className="text-xs">{shortId(id)}</code>
      )
    ) : (
      '-'
    );
  return (
    <div className="space-y-3 text-sm">
      {summary && <p className="text-fg">{summary}</p>}
      {hint && <p className="text-warn-fg">{hint}</p>}
      <DefinitionList
        items={[
          ...lead,
          ['Connector', action.connector ?? '-'],
          ['Executed by', action.execution_owner === 'scheduler' ? 'scheduler (background)' : 'alert workflow'],
          ['Attempts', action.attempts ?? 0],
          ['Executed', formatDateTime(action.executed_at)],
          ['Verification', <VerificationBadge key="v" value={action.verification} detail={action.verification_detail} />],
          ['Verified', formatDateTime(action.verified_at)],
          ['Verify until', formatDateTime(action.verify_deadline)],
          ['Rolls back', link(action.rollback_of, 'Open original action')],
          ['Rolled back by', link(action.rolled_back_by, 'Open rollback action')],
          [
            'Rollback',
            action.rollback?.available
              ? `available (${humanize(action.rollback.action_type ?? '')}${action.rollback.until ? ` until ${formatDateTime(action.rollback.until)}` : ''})`
              : ROLLBACK_REASONS[action.rollback?.reason ?? ''] ?? '-',
          ],
        ]}
      />
      {steps.length > 0 && (
        <div>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Steps</h4>
          <Steps steps={steps} />
        </div>
      )}
      {result && <JsonBlock value={result} label="Connector result" />}
      {action.verification_detail && <JsonBlock value={action.verification_detail} label="Verification detail" />}
    </div>
  );
}

/** Roll back, Retry and Re-check, shown according to the caller's role and the action's eligibility. */
export function ActionControls({ action }: { action: ActionOut }) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const [dialog, setDialog] = useState<'rollback' | 'retry' | null>(null);
  const [checking, setChecking] = useState(false);
  const reviewer = can.reject(principal);
  const rollback = reviewer && Boolean(action.rollback?.available);
  const retry = can.approve(principal, action.risk_level) && canRetry(action);
  const recheck = reviewer && canRecheck(action);
  if (!rollback && !retry && !recheck) return null;

  const verify = async () => {
    setChecking(true);
    try {
      await endpoints.verifyAction(api, action.id);
      toast.success(`Re-checking ${humanize(action.action_type)} on ${action.target}.`);
      void afterActionChange(client);
    } catch (err) {
      toast.error(err, 'Re-check refused');
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="flex flex-wrap justify-end gap-1.5">
      {rollback && (
        <Button size="sm" variant="destructive" onClick={() => setDialog('rollback')} icon={<Undo2 className="h-3.5 w-3.5" aria-hidden="true" />}>
          Roll back
        </Button>
      )}
      {retry && (
        <Button size="sm" onClick={() => setDialog('retry')} icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />}>
          Retry
        </Button>
      )}
      {recheck && (
        <Button size="sm" onClick={() => void verify()} busy={checking} icon={<RefreshCcw className="h-3.5 w-3.5" aria-hidden="true" />}>
          Re-check
        </Button>
      )}
      {dialog === 'rollback' && <RollbackDialog action={action} onClose={() => setDialog(null)} />}
      {dialog === 'retry' && <RetryDialog action={action} onClose={() => setDialog(null)} />}
    </div>
  );
}
