import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { History, Pencil, PlugZap, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterIntegrationChange, afterIntegrationTest } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import type { IntegrationOut, MicrosoftTestReport as MicrosoftReport } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { Badge } from '../../components/Badge';
import { ConfirmDialog, Modal } from '../../../../components/Dialog';
import { useToast } from '../../../../components/Toast';
import { Button, EmptyState, ErrorMessage, LoadingState, PageHeader } from '../../../../components/ui';
import { DeliveryLog } from './DeliveryLog';
import { IntegrationForm } from './IntegrationForm';
import { MicrosoftTestReport } from './MicrosoftTestReport';
import { EVENT_LABELS, kindSpec, missingCredentials } from './specs';

export default function IntegrationsPage() {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<IntegrationOut | null | 'new'>(null);
  const [deleting, setDeleting] = useState<IntegrationOut | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [logFor, setLogFor] = useState<string | null>(null);
  const [report, setReport] = useState<{ name: string; report: MicrosoftReport } | null>(null);
  const q = useQuery({ queryKey: qk.integrations.all, queryFn: ({ signal }) => endpoints.integrations(api, signal) });

  const del = useMutation({
    mutationFn: (i: IntegrationOut) => endpoints.deleteIntegration(api, i.id),
    onSuccess: (_, i) => {
      toast.success('Integration deleted.');
      setDeleting(null);
      if (logFor === i.id) setLogFor(null);
      void afterIntegrationChange(client);
    },
    onError: (err) => toast.error(err, 'Delete failed'),
  });

  const test = async (i: IntegrationOut) => {
    setTesting(i.id);
    try {
      const out = await endpoints.testIntegration(api, i.id);
      if (out.microsoft) setReport({ name: i.name, report: out.microsoft });
      if (out.ok) toast.success(`${i.name}: ${out.detail}.`);
      else toast.error(new Error(`${i.name}: ${out.detail}`));
    } catch (err) {
      toast.error(err, `${i.name}: test failed`);
    } finally {
      setTesting(null);
      void afterIntegrationTest(client, i.id);
    }
  };

  const selected = q.data?.find((i) => i.id === logFor) ?? null;

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Send escalations, approvals and action outcomes to Slack, Teams, email or a signed webhook, open Jira or ServiceNow tickets for escalations, and execute approved actions directly in Microsoft 365. Notifications carry a summary and a link, never the raw alert."
        actions={
          <Button variant="primary" onClick={() => setEditing('new')} icon={<Plus className="h-4 w-4" aria-hidden="true" />}>
            Add integration
          </Button>
        }
      />
      {q.isPending && <LoadingState label="Loading integrations" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && q.data.length === 0 && (
        <EmptyState title="No integrations yet">Add a channel so analysts hear about escalations and approvals where they work.</EmptyState>
      )}
      {q.data && q.data.length > 0 && (
        <div className="relative overflow-x-auto rounded-card border border-subtle bg-raised">
          <table className="w-full min-w-[900px] text-left text-sm">
            <caption className="sr-only">Integrations</caption>
            <thead className="border-b border-subtle text-xs uppercase tracking-wide text-muted">
              <tr>
                <th scope="col" className="px-3 py-2">Name</th>
                <th scope="col" className="px-3 py-2">Kind</th>
                <th scope="col" className="px-3 py-2">Events</th>
                <th scope="col" className="px-3 py-2">Min severity</th>
                <th scope="col" className="px-3 py-2">Credentials</th>
                <th scope="col" className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((i) => {
                const missing = missingCredentials(i);
                return (
                  <tr key={i.id} className="border-b border-subtle align-top">
                    <td className="px-3 py-2">
                      <div className="min-w-[10rem] font-medium text-fg">{i.name}</div>
                      {!i.enabled && <Badge>disabled</Badge>}
                    </td>
                    <td className="px-3 py-2 text-body">{kindSpec(i.kind)?.label ?? i.kind}</td>
                    <td className="min-w-[12rem] px-3 py-2 text-xs text-secondary">
                      {i.events.length ? i.events.map((e) => EVENT_LABELS[e] ?? e).join(', ') : <span className="text-muted">none</span>}
                    </td>
                    <td className="px-3 py-2 capitalize text-body">{i.min_severity}</td>
                    <td className="px-3 py-2">
                      {missing.length ? <Badge tone="warn">missing {missing.map((m) => m.replace(/_/g, ' ')).join(', ')}</Badge> : <Badge tone="good">ok</Badge>}
                    </td>
                    <td className="px-3 py-2">
                      {/* Two buttons a row, so the table fits at 1280 px. */}
                      <div className="ml-auto flex w-[11rem] flex-wrap justify-end gap-1.5">
                        <Button size="sm" onClick={() => void test(i)} busy={testing === i.id} icon={<PlugZap className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Test ${i.name}`}>
                          Test
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => setLogFor(logFor === i.id ? null : i.id)}
                          aria-pressed={logFor === i.id}
                          icon={<History className="h-3.5 w-3.5" aria-hidden="true" />}
                          aria-label={`Delivery log of ${i.name}`}
                        >
                          Log
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => setEditing(i)}
                          // A kind this version of the app does not know has no form here.
                          disabled={!kindSpec(i.kind)}
                          icon={<Pencil className="h-3.5 w-3.5" aria-hidden="true" />}
                          aria-label={`Edit ${i.name}`}
                        >
                          Edit
                        </Button>
                        <Button size="sm" variant="destructive" onClick={() => setDeleting(i)} icon={<Trash2 className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Delete ${i.name}`}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {selected && <DeliveryLog integration={selected} />}
      {editing !== null && (
        <IntegrationForm
          integration={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          hasMicrosoft={Boolean(q.data?.some((i) => i.kind === 'microsoft'))}
        />
      )}
      {report && (
        <Modal open onClose={() => setReport(null)} size="xl" title={`Connection test: ${report.name}`}>
          <MicrosoftTestReport report={report.report} />
        </Modal>
      )}
      <ConfirmDialog
        open={deleting !== null}
        title="Delete integration"
        confirmLabel="Delete integration"
        danger
        busy={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting)}
        onCancel={() => setDeleting(null)}
      >
        Delete <strong>{deleting?.name}</strong>? Queued messages are dropped, its credentials are destroyed and its ticket links are removed
        (the tickets themselves stay in the external system).
      </ConfirmDialog>
    </>
  );
}
