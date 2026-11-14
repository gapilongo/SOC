import { useMutation } from '@tanstack/react-query';
import { Download, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../../api/endpoints';
import type { TenantErasedOut, TenantErasureStatusOut } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { Modal } from '../../../../components/Dialog';
import { useToast } from '../../../../components/Toast';
import { Button, Card, ErrorMessage, TextField } from '../../../../components/ui';
import { downloadBlob, fileStamp } from '../../../../lib/download';

/** Strong confirmation: the confirm button stays disabled until the tenant id is typed exactly. */
export function EraseTenantDialog({
  tenantId,
  open,
  busy,
  error,
  onConfirm,
  onCancel,
}: {
  tenantId: string;
  open: boolean;
  busy: boolean;
  error: unknown;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState('');
  const matches = typed === tenantId;
  const close = () => {
    setTyped('');
    onCancel();
  };
  return (
    <Modal
      open={open}
      onClose={close}
      size="md"
      title={`Erase tenant ${tenantId}`}
      footer={
        <>
          <Button onClick={close} data-autofocus>
            Cancel
          </Button>
          <Button
            variant="destructive"
            busy={busy}
            disabled={!matches}
            onClick={onConfirm}
            icon={<Trash2 className="h-4 w-4" aria-hidden="true" />}
          >
            Erase permanently
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-body">
        <p className="rounded border border-danger bg-tint-danger px-3 py-2 font-medium text-danger-fg">
          This permanently deletes all of the tenant&apos;s data and cannot be undone. Export the tenant&apos;s data first if it
          may be needed.
        </p>
        <p>
          Deleted: alerts and their timelines, users, sources, escalations, analyst feedback, response actions, suppression rules,
          indicator sightings, LLM usage, workflow runs and checkpoints, and the tenant&apos;s cached keys and queued work.
        </p>
        <p>
          Retained: the tenant&apos;s hash-chained audit log. It is immutable by design and kept on the basis of legal obligation
          and legitimate interest (proving who did what); it ages out with the audit retention period. The erasure itself is
          recorded in your home tenant&apos;s audit log.
        </p>
        <TextField
          label={
            <>
              Type <code className="text-danger-fg">{tenantId}</code> to confirm
            </>
          }
          autoComplete="off"
          spellCheck={false}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
        />
        {Boolean(error) && <ErrorMessage error={error} compact />}
      </div>
    </Modal>
  );
}

function totalRows(result: TenantErasedOut): number {
  return Object.values(result.deleted).reduce((sum, n) => sum + (Number.isFinite(n) ? n : 0), 0);
}

/** Platform admins: export a tenant's data (GDPR access/portability) and erase a suspended tenant. */
export function TenantDataCard() {
  const api = useApi();
  const toast = useToast();
  const [input, setInput] = useState('');
  const [status, setStatus] = useState<TenantErasureStatusOut | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [erased, setErased] = useState<TenantErasedOut | null>(null);

  const lookup = useMutation({
    mutationFn: (id: string) => endpoints.tenantErasureStatus(api, id),
    onMutate: () => {
      setStatus(null);
      setErased(null);
    },
    onSuccess: (s) => setStatus(s),
  });
  const exporter = useMutation({
    mutationFn: (id: string) => endpoints.exportTenant(api, id),
    onSuccess: (blob, id) => {
      downloadBlob(`lg-sotf-tenant-${id}-${fileStamp()}.zip`, blob);
      toast.success('Tenant export downloaded.');
    },
    onError: (err) => toast.error(err, 'Export failed'),
  });
  const eraser = useMutation({
    mutationFn: (id: string) => endpoints.eraseTenant(api, id),
    onSuccess: (result) => {
      setConfirming(false);
      setErased(result);
      setStatus((s) => (s ? { ...s, erasable: false, erased_at: result.erased_at } : s));
      toast.success(`Tenant ${result.tenant_id} erased.`);
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const id = input.trim();
    if (id) lookup.mutate(id);
  };

  const suspended = status?.status === 'suspended';
  const canErase = Boolean(status && suspended && status.erasable);

  return (
    <Card title="Tenant data export and erasure" className="max-w-2xl">
      <div className="space-y-4">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2" autoComplete="off">
          <TextField
            label="Tenant id"
            wrapperClassName="min-w-[14rem] flex-1"
            pattern="[a-z0-9][a-z0-9_-]{1,62}"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <Button type="submit" busy={lookup.isPending} disabled={!input.trim()}>
            Look up
          </Button>
        </form>
        {lookup.isError && <ErrorMessage error={lookup.error} compact />}
        {status && (
          <div className="space-y-4">
            <p className="text-sm text-body">
              <span className="font-medium">{status.name}</span> (<code>{status.tenant_id}</code>) is{' '}
              <span className={suspended ? 'text-warn-fg' : 'text-ok-fg'}>{status.status}</span>
              {status.erased_at ? `, erased ${status.erased_at}` : ''}.
            </p>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold text-fg">Export tenant data</h3>
              <p className="text-xs text-muted">
                A zip of JSON Lines files: settings, users, sources, alerts, events, escalations, feedback, actions, suppression rules
                and the audit log. Secrets, password hashes and key hashes are left out. The export contains personal data: store and
                transfer it accordingly. For very large tenants use <code>lg-sotf tenant-export</code> on the server instead. Every
                export is audited.
              </p>
              <Button
                size="sm"
                busy={exporter.isPending}
                onClick={() => exporter.mutate(status.tenant_id)}
                icon={<Download className="h-4 w-4" aria-hidden="true" />}
              >
                Export tenant data
              </Button>
            </section>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold text-fg">Erase tenant</h3>
              {!suspended && <p className="text-xs text-warn-fg">Suspend the tenant first: only a suspended tenant can be erased.</p>}
              {status.blockers.length > 0 && (
                <ul className="list-disc pl-5 text-xs text-warn-fg">
                  {status.blockers.map((b) => (
                    <li key={b}>{b}</li>
                  ))}
                </ul>
              )}
              <Button
                size="sm"
                variant="destructive"
                disabled={!canErase}
                onClick={() => {
                  eraser.reset();
                  setConfirming(true);
                }}
                icon={<Trash2 className="h-4 w-4" aria-hidden="true" />}
              >
                Erase tenant
              </Button>
            </section>
            <EraseTenantDialog
              tenantId={status.tenant_id}
              open={confirming}
              busy={eraser.isPending}
              error={eraser.error}
              onConfirm={() => eraser.mutate(status.tenant_id)}
              onCancel={() => setConfirming(false)}
            />
          </div>
        )}
        {erased && (
          <p role="status" className="rounded-control border border-state-ok/60 bg-tint-ok px-3 py-2 text-sm text-ok-fg">
            Tenant {erased.tenant_id} erased: {totalRows(erased)} rows, {erased.redis_keys} cached keys and {erased.queue_entries} queued
            entries deleted; {erased.audit_entries_retained} audit entries retained.
          </p>
        )}
      </div>
    </Card>
  );
}
