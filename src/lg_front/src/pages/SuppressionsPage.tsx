import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../api/endpoints';
import { afterSuppressionChange } from '../api/invalidate';
import { qk } from '../api/queryKeys';
import type { JsonObject, SuppressionOut } from '../api/types';
import { useApi, useAuth } from '../auth/AuthContext';
import { can } from '../auth/roles';
import { Badge } from '../components/Badge';
import { ConfirmDialog, Modal } from '../components/Dialog';
import { useToast } from '../components/Toast';
import { Button, Checkbox, EmptyState, ErrorMessage, LoadingState, PageHeader, SelectField, TextField, cx } from '../components/ui';
import { formatDateTime, formatInt, localInputToIso } from '../lib/format';

type Op = 'eq' | 'in' | 'regex' | 'cidr';
interface Predicate {
  path: string;
  op: Op;
  value: string;
}

const PATHS = ['severity', 'title', 'category', 'rule_name', 'source_id', 'entities.hosts', 'entities.users', 'entities.ips', 'entities.domains', 'entities.hashes', 'entities.processes'];

/** Build a rule's `match` object from the predicate rows. */
export function buildMatch(rows: Predicate[]): JsonObject {
  const match: JsonObject = {};
  for (const r of rows) {
    const path = r.path.trim();
    const value = r.value.trim();
    if (!path || !value) continue;
    const items = value.split(',').map((v) => v.trim()).filter(Boolean);
    if (r.op === 'eq') match[path] = { eq: value };
    else if (r.op === 'in') match[path] = { in: items };
    else if (r.op === 'regex') match[path] = { regex: value };
    else match[path] = { cidr: items };
  }
  return match;
}

function describeMatch(match: JsonObject): string {
  return Object.entries(match)
    .map(([path, pred]) => {
      if (pred && typeof pred === 'object' && !Array.isArray(pred)) {
        const [op, arg] = Object.entries(pred as JsonObject)[0] ?? ['?', ''];
        return `${path} ${op} ${Array.isArray(arg) ? arg.join(', ') : String(arg)}`;
      }
      return `${path} = ${Array.isArray(pred) ? pred.join(', ') : String(pred)}`;
    })
    .join('; ');
}

function CreateRule({ onClose }: { onClose: () => void }) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const admin = can.manageSuppressions(principal);
  const [name, setName] = useState('');
  const [expires, setExpires] = useState('');
  const [enabled, setEnabled] = useState(admin);
  const [rows, setRows] = useState<Predicate[]>([{ path: 'title', op: 'regex', value: '' }]);
  const [error, setError] = useState<unknown>(null);
  const m = useMutation({
    mutationFn: () => {
      const match = buildMatch(rows);
      if (Object.keys(match).length === 0) throw new Error('Add at least one condition with a value.');
      return endpoints.createSuppression(api, { name: name.trim(), match, expires_at: localInputToIso(expires) ?? null, enabled: admin ? enabled : false });
    },
    onSuccess: (rule) => {
      toast.success(rule.enabled ? 'Suppression rule created and active.' : 'Suppression rule created; an admin must enable it before it takes effect.');
      void afterSuppressionChange(client);
      onClose();
    },
    onError: (err) => setError(err),
  });
  const setRow = (i: number, patch: Partial<Predicate>) => setRows(rows.map((r, j) => (i === j ? { ...r, ...patch } : r)));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    m.mutate();
  };
  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title="New suppression rule"
      description="Alerts matching every condition are closed as benign without an LLM call. Rules that would match every alert are refused."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="rule-form" variant="primary" busy={m.isPending}>
            Create rule
          </Button>
        </>
      }
    >
      <form id="rule-form" onSubmit={submit} className="space-y-4">
        {error !== null && <ErrorMessage error={error} compact />}
        <div className="grid gap-3 sm:grid-cols-2">
          <TextField label="Name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <TextField label="Expires (optional)" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
        </div>
        <fieldset className="space-y-2">
          <legend className="mb-1 text-sm font-medium text-slate-200">Conditions (all must match)</legend>
          <datalist id="rule-paths">
            {PATHS.map((p) => (
              <option key={p} value={p} />
            ))}
          </datalist>
          {rows.map((r, i) => (
            <div key={i} className="grid items-end gap-2 sm:grid-cols-[1.2fr_0.8fr_2fr_auto]">
              <TextField label={`Field ${i + 1}`} list="rule-paths" value={r.path} onChange={(e) => setRow(i, { path: e.target.value })} />
              <SelectField label="Operator" value={r.op} onChange={(e) => setRow(i, { op: e.target.value as Op })}>
                <option value="eq">equals</option>
                <option value="in">is one of (comma separated)</option>
                <option value="regex">matches regex (full match)</option>
                <option value="cidr">in network (CIDR, comma separated)</option>
              </SelectField>
              <TextField label="Value" value={r.value} onChange={(e) => setRow(i, { value: e.target.value })} />
              <Button variant="ghost" aria-label={`Remove condition ${i + 1}`} disabled={rows.length === 1} onClick={() => setRows(rows.filter((_, j) => j !== i))} icon={<Trash2 className="h-4 w-4" aria-hidden="true" />} />
            </div>
          ))}
          <Button size="sm" onClick={() => setRows([...rows, { path: '', op: 'eq', value: '' }])} icon={<Plus className="h-3.5 w-3.5" aria-hidden="true" />}>
            Add condition
          </Button>
        </fieldset>
        {admin ? (
          <Checkbox label="Enable immediately" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        ) : (
          <p className="text-sm text-slate-300">Rules created by analysts start disabled until an admin enables them.</p>
        )}
      </form>
    </Modal>
  );
}

type Tab = 'active' | 'suggestions' | 'all';

export default function SuppressionsPage() {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const admin = can.manageSuppressions(principal);
  const [tab, setTab] = useState<Tab>('active');
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<SuppressionOut | null>(null);
  const q = useQuery({ queryKey: qk.suppressions.includingDisabled, queryFn: ({ signal }) => endpoints.suppressions(api, true, signal) });

  const toggle = useMutation({
    mutationFn: (r: SuppressionOut) => endpoints.updateSuppression(api, r.id, { enabled: !r.enabled }),
    onSuccess: (r) => {
      toast.success(`Rule ${r.name} ${r.enabled ? 'enabled' : 'disabled'}.`);
      void afterSuppressionChange(client);
    },
    onError: (err) => toast.error(err, 'Update failed'),
  });
  const del = useMutation({
    mutationFn: (r: SuppressionOut) => endpoints.deleteSuppression(api, r.id),
    onSuccess: () => {
      setDeleting(null);
      toast.success('Rule deleted.');
      void afterSuppressionChange(client);
    },
    onError: (err) => toast.error(err, 'Delete failed'),
  });

  const rules = q.data ?? [];
  const suggestions = rules.filter((r) => !r.enabled && r.source_feedback_id);
  const visible = tab === 'active' ? rules.filter((r) => r.enabled) : tab === 'suggestions' ? suggestions : rules;
  const tabs: Array<[Tab, string]> = [
    ['active', 'Active'],
    ['suggestions', `Suggestions (${suggestions.length})`],
    ['all', 'All rules'],
  ];

  return (
    <>
      <PageHeader
        title="Suppressions"
        description="Rules that close known-benign alerts automatically. Suggestions come from analysts' false-positive decisions and stay disabled until an admin enables them."
        actions={
          can.createSuppression(principal) && (
            <Button variant="primary" onClick={() => setCreating(true)} icon={<Plus className="h-4 w-4" aria-hidden="true" />}>
              New rule
            </Button>
          )
        }
      />
      <div role="group" aria-label="Rule views" className="mb-4 flex gap-1 border-b border-slate-800">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            type="button"
            aria-pressed={tab === key}
            onClick={() => setTab(key)}
            className={cx(
              '-mb-px border-b-2 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400',
              tab === key ? 'border-sky-400 text-white' : 'border-transparent text-slate-300 hover:text-white',
            )}
          >
            {label}
          </button>
        ))}
      </div>
      {q.isPending && <LoadingState label="Loading rules" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.isSuccess && visible.length === 0 && (
        <EmptyState title={tab === 'suggestions' ? 'No pending suggestions' : 'No rules'}>
          {tab === 'suggestions' ? 'Suggestions appear when analysts mark alerts as false positives and ask for a rule.' : undefined}
        </EmptyState>
      )}
      {visible.length > 0 && (
        <ul className="space-y-2" aria-label="Suppression rules">
          {visible.map((r) => (
            <li key={r.id} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-sm font-semibold text-white">{r.name}</h2>
                    <Badge tone={r.enabled ? 'good' : 'neutral'}>{r.enabled ? 'enabled' : 'disabled'}</Badge>
                    {r.source_feedback_id && <Badge tone="info">suggested</Badge>}
                  </div>
                  <p className="mt-1 break-words font-mono text-xs text-slate-300">{describeMatch(r.match)}</p>
                  <p className="mt-1 text-xs text-slate-400">
                    {formatInt(r.hit_count)} hits{r.last_hit_at ? `, last ${formatDateTime(r.last_hit_at)}` : ''}
                    {r.expires_at ? `; expires ${formatDateTime(r.expires_at)}` : ''}; created {formatDateTime(r.created_at)}
                  </p>
                </div>
                {admin && (
                  <div className="flex gap-1.5">
                    <Button size="sm" variant={r.enabled ? 'secondary' : 'primary'} onClick={() => toggle.mutate(r)} busy={toggle.isPending && toggle.variables?.id === r.id}>
                      {r.enabled ? 'Disable' : 'Enable'}
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => setDeleting(r)} aria-label={`Delete rule ${r.name}`} icon={<Trash2 className="h-3.5 w-3.5" aria-hidden="true" />}>
                      Delete
                    </Button>
                  </div>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      {creating && <CreateRule onClose={() => setCreating(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        title="Delete suppression rule"
        confirmLabel="Delete rule"
        danger
        busy={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting)}
        onCancel={() => setDeleting(null)}
      >
        Delete <strong>{deleting?.name}</strong>? Matching alerts will go through full triage again.
      </ConfirmDialog>
    </>
  );
}
