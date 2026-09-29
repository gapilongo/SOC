import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Pencil, PlugZap, Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../api/endpoints';
import { SOURCE_TYPES, type JsonObject, type SourceCreateIn, type SourceOut, type SourceType, type SourceUpdateIn } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { Badge, StatusBadge } from '../components/Badge';
import { ConfirmDialog, Modal } from '../components/Dialog';
import { useToast } from '../components/Toast';
import { Button, Checkbox, EmptyState, ErrorMessage, LoadingState, PageHeader, SelectField, TextAreaField, TextField } from '../components/ui';
import { formatDateTime, formatRelative } from '../lib/format';

interface FieldSpec {
  key: string;
  label: string;
  number?: boolean;
  placeholder?: string;
}

interface TypeSpec {
  label: string;
  push?: boolean;
  config: FieldSpec[];
  secrets: FieldSpec[];
  note?: string;
}

/** Connector settings per source type (lg_sotf.ingestion.sources). */
export const SOURCE_SPECS: Record<SourceType, TypeSpec> = {
  splunk: {
    label: 'Splunk',
    config: [
      { key: 'base_url', label: 'Management URL', placeholder: 'https://splunk.example.com:8089' },
      { key: 'search', label: 'Search', placeholder: 'search `notable`' },
      { key: 'max_event_lag_s', label: 'Max event lag (s)', number: true, placeholder: '86400' },
      { key: 'search_timeout_s', label: 'Search timeout (s)', number: true, placeholder: '300' },
    ],
    secrets: [
      { key: 'token', label: 'Authentication token' },
      { key: 'username', label: 'Username (instead of a token)' },
      { key: 'password', label: 'Password' },
    ],
  },
  qradar: {
    label: 'IBM QRadar',
    config: [
      { key: 'base_url', label: 'Console URL', placeholder: 'https://qradar.example.com' },
      { key: 'api_version', label: 'API version', placeholder: '20.0' },
    ],
    secrets: [{ key: 'token', label: 'Authorized service token' }],
  },
  sentinel: {
    label: 'Microsoft Sentinel',
    config: [
      { key: 'workspace_id', label: 'Workspace id' },
      { key: 'azure_tenant_id', label: 'Azure tenant id' },
      { key: 'table', label: 'Table', placeholder: 'SecurityAlert' },
      { key: 'authority_url', label: 'Authority URL', placeholder: 'https://login.microsoftonline.com' },
      { key: 'api_url', label: 'Log Analytics API URL', placeholder: 'https://api.loganalytics.io' },
    ],
    secrets: [
      { key: 'client_id', label: 'Client id' },
      { key: 'client_secret', label: 'Client secret' },
    ],
  },
  wazuh: {
    label: 'Wazuh indexer',
    config: [
      { key: 'base_url', label: 'Indexer URL', placeholder: 'https://wazuh-indexer:9200' },
      { key: 'index', label: 'Index pattern', placeholder: 'wazuh-alerts-*' },
      { key: 'min_level', label: 'Minimum rule level', number: true, placeholder: '0' },
      { key: 'time_field', label: 'Time field', placeholder: 'timestamp' },
      { key: 'max_event_lag_s', label: 'Max event lag (s)', number: true, placeholder: '900' },
    ],
    secrets: [
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password' },
    ],
  },
  crowdstrike: {
    label: 'CrowdStrike Falcon',
    config: [
      { key: 'base_url', label: 'API URL', placeholder: 'https://api.crowdstrike.com' },
      { key: 'filter', label: 'Extra FQL filter' },
      { key: 'member_cid', label: 'Member CID (MSSP)' },
    ],
    secrets: [
      { key: 'client_id', label: 'Client id' },
      { key: 'client_secret', label: 'Client secret' },
    ],
  },
  guardduty: {
    label: 'AWS GuardDuty (push)',
    push: true,
    config: [],
    secrets: [],
    note: 'Push source: deliver findings to POST /api/v1/ingest/webhook/<source id> with an API key that has the ingest scope.',
  },
  webhook: {
    label: 'Generic webhook (push)',
    push: true,
    config: [],
    secrets: [],
    note: 'Push source: send events to POST /api/v1/ingest/webhook/<source id> with an API key that has the ingest scope.',
  },
  file: {
    label: 'File (development only)',
    config: [{ key: 'path', label: 'JSON Lines file path' }],
    secrets: [],
    note: 'Refused in staging and production.',
  },
};

export function splitConfig(type: SourceType, config: JsonObject | undefined): { known: Record<string, string>; extra: string } {
  const spec = SOURCE_SPECS[type] ?? { config: [] };
  const known: Record<string, string> = {};
  const extra: JsonObject = {};
  for (const [k, v] of Object.entries(config ?? {})) {
    if (spec.config.some((f) => f.key === k) && (typeof v === 'string' || typeof v === 'number')) known[k] = String(v);
    else extra[k] = v;
  }
  return { known, extra: Object.keys(extra).length ? JSON.stringify(extra, null, 2) : '' };
}

export function buildConfig(type: SourceType, known: Record<string, string>, extra: string): JsonObject {
  let out: JsonObject = {};
  if (extra.trim()) {
    const parsed = JSON.parse(extra) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Additional configuration must be a JSON object.');
    out = { ...(parsed as JsonObject) };
  }
  for (const f of SOURCE_SPECS[type].config) {
    const raw = (known[f.key] ?? '').trim();
    if (!raw) continue;
    if (f.number) {
      const n = Number(raw);
      if (!Number.isFinite(n)) throw new Error(`${f.label} must be a number.`);
      out[f.key] = n;
    } else {
      out[f.key] = raw;
    }
  }
  return out;
}

function SourceForm({ source, onClose }: { source: SourceOut | null; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const editing = source !== null;
  const initialType = (source?.type as SourceType) ?? 'splunk';
  const initial = splitConfig(initialType, source?.config);
  const [type, setType] = useState<SourceType>(initialType);
  const [id, setId] = useState('');
  const [name, setName] = useState(source?.name ?? '');
  const [enabled, setEnabled] = useState(source?.enabled ?? true);
  const [poll, setPoll] = useState(String(source?.poll_interval_s ?? 60));
  const [known, setKnown] = useState<Record<string, string>>(initial.known);
  const [extra, setExtra] = useState(initial.extra);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [extraSecret, setExtraSecret] = useState('');
  const [removeSecret, setRemoveSecret] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const spec = SOURCE_SPECS[type];

  const m = useMutation({
    mutationFn: async () => {
      const config = buildConfig(type, known, extra);
      const secret: Record<string, string> = {};
      for (const [k, v] of Object.entries(secrets)) if (v) secret[k] = v;
      if (extraSecret.trim()) {
        const parsed = JSON.parse(extraSecret) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Additional credentials must be a JSON object.');
        for (const [k, v] of Object.entries(parsed as JsonObject)) secret[k] = String(v);
      }
      const pollInterval = Number(poll);
      if (!Number.isInteger(pollInterval) || pollInterval < 1) throw new Error('Poll interval must be a whole number of seconds.');
      if (editing) {
        const body: SourceUpdateIn = { name: name.trim(), enabled, config, poll_interval_s: pollInterval };
        if (removeSecret) body.secret = null;
        else if (Object.keys(secret).length) body.secret = secret;
        return endpoints.updateSource(api, source.id, body);
      }
      const body: SourceCreateIn = { type, name: name.trim(), enabled, config, poll_interval_s: pollInterval };
      if (id.trim()) body.id = id.trim();
      if (Object.keys(secret).length) body.secret = secret;
      return endpoints.createSource(api, body);
    },
    onSuccess: (s) => {
      // Clear credentials from component state as soon as they have been sent.
      setSecrets({});
      setExtraSecret('');
      toast.success(`Source ${s.name} saved.`);
      void client.invalidateQueries({ queryKey: ['sources'] });
      onClose();
    },
    onError: (err) => setError(err),
  });

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
      title={editing ? `Edit source ${source.name}` : 'Add source'}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="source-form" variant="primary" busy={m.isPending}>
            {editing ? 'Save changes' : 'Create source'}
          </Button>
        </>
      }
    >
      <form id="source-form" onSubmit={submit} className="space-y-4" autoComplete="off">
        {error !== null && <ErrorMessage error={error} compact />}
        <div className="grid gap-3 sm:grid-cols-2">
          <SelectField label="Type" value={type} disabled={editing} onChange={(e) => setType(e.target.value as SourceType)}>
            {SOURCE_TYPES.map((t) => (
              <option key={t} value={t}>
                {SOURCE_SPECS[t].label}
              </option>
            ))}
          </SelectField>
          {!editing && <TextField label="Source id (optional)" hint="Generated when empty." value={id} onChange={(e) => setId(e.target.value)} />}
          <TextField label="Name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          {!spec.push && (
            <TextField label="Poll interval (seconds)" type="number" min={1} required value={poll} onChange={(e) => setPoll(e.target.value)} />
          )}
        </div>
        <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        {spec.note && <p className="text-sm text-slate-300">{spec.note}</p>}
        {spec.config.length > 0 && (
          <fieldset className="grid gap-3 sm:grid-cols-2">
            <legend className="mb-2 text-sm font-medium text-slate-200">Configuration</legend>
            {spec.config.map((f) => (
              <TextField
                key={f.key}
                label={f.label}
                placeholder={f.placeholder}
                inputMode={f.number ? 'numeric' : undefined}
                value={known[f.key] ?? ''}
                onChange={(e) => setKnown({ ...known, [f.key]: e.target.value })}
              />
            ))}
          </fieldset>
        )}
        <TextAreaField
          label="Additional configuration (JSON object, optional)"
          hint="Keys that look like credentials are refused here; put credentials below."
          rows={3}
          value={extra}
          onChange={(e) => setExtra(e.target.value)}
        />
        <fieldset className="space-y-3 rounded-md border border-slate-800 p-3">
          <legend className="px-1 text-sm font-medium text-slate-200">Credentials (write-only)</legend>
          <p className="text-xs text-slate-400">
            {editing && source.has_secret
              ? 'Credentials are stored encrypted and are never shown. Leave these fields empty to keep them; entering any value replaces all stored credentials.'
              : 'Stored encrypted and never shown again.'}
          </p>
          {editing && source.has_secret && <Badge tone="good">credentials configured</Badge>}
          <div className="grid gap-3 sm:grid-cols-2">
            {spec.secrets.map((f) => (
              <TextField
                key={f.key}
                label={f.label}
                type="password"
                autoComplete="new-password"
                disabled={removeSecret}
                value={secrets[f.key] ?? ''}
                onChange={(e) => setSecrets({ ...secrets, [f.key]: e.target.value })}
              />
            ))}
          </div>
          <TextAreaField
            label="Other credentials (JSON object, optional)"
            rows={2}
            disabled={removeSecret}
            value={extraSecret}
            onChange={(e) => setExtraSecret(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          {editing && source.has_secret && (
            <Checkbox label="Remove stored credentials" checked={removeSecret} onChange={(e) => setRemoveSecret(e.target.checked)} />
          )}
        </fieldset>
      </form>
    </Modal>
  );
}

function healthTone(s: SourceOut): string {
  return s.health || (s.last_error ? 'failing' : 'unknown');
}

export default function SourcesPage() {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<SourceOut | null | 'new'>(null);
  const [deleting, setDeleting] = useState<SourceOut | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const q = useQuery({ queryKey: ['sources'], queryFn: ({ signal }) => endpoints.sources(api, signal) });

  const del = useMutation({
    mutationFn: (s: SourceOut) => endpoints.deleteSource(api, s.id),
    onSuccess: () => {
      toast.success('Source deleted.');
      setDeleting(null);
      void client.invalidateQueries({ queryKey: ['sources'] });
    },
    onError: (err) => toast.error(err, 'Delete failed'),
  });

  const test = async (s: SourceOut) => {
    setTesting(s.id);
    try {
      const out = await endpoints.testSource(api, s.id);
      if (out.ok) toast.success(`${s.name}: connection succeeded. ${out.detail}`);
      else toast.error(new Error(`${s.name}: connection failed. ${out.detail}`));
    } catch (err) {
      toast.error(err, `${s.name}: test failed`);
    } finally {
      setTesting(null);
    }
  };

  return (
    <>
      <PageHeader
        title="Sources"
        description="Where alerts come from. Pull sources are polled by the scheduler; push sources receive events on the ingest webhook."
        actions={
          <Button variant="primary" onClick={() => setEditing('new')} icon={<Plus className="h-4 w-4" aria-hidden="true" />}>
            Add source
          </Button>
        }
      />
      {q.isPending && <LoadingState label="Loading sources" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && q.data.length === 0 && <EmptyState title="No sources yet">Add a SIEM or EDR connection, or a webhook for push delivery.</EmptyState>}
      {q.data && q.data.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
          <table className="w-full min-w-[900px] text-left text-sm">
            <caption className="sr-only">Sources</caption>
            <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-3 py-2">Name</th>
                <th scope="col" className="px-3 py-2">Type</th>
                <th scope="col" className="px-3 py-2">Health</th>
                <th scope="col" className="px-3 py-2">Last polled</th>
                <th scope="col" className="px-3 py-2">Credentials</th>
                <th scope="col" className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((s) => (
                <tr key={s.id} className="border-b border-slate-800/70 align-top">
                  <td className="px-3 py-2">
                    <div className="font-medium text-slate-100">{s.name}</div>
                    <div className="font-mono text-xs text-slate-400">{s.id}</div>
                    {!s.enabled && <Badge>disabled</Badge>}
                  </td>
                  <td className="px-3 py-2 text-slate-200">{SOURCE_SPECS[s.type as SourceType]?.label ?? s.type}</td>
                  <td className="px-3 py-2">
                    <StatusBadge value={healthTone(s)} />
                    {s.consecutive_failures ? <div className="mt-1 text-xs text-orange-200">{s.consecutive_failures} consecutive failures</div> : null}
                    {s.last_error && <div className="mt-1 max-w-xs break-words text-xs text-orange-200">{s.last_error}</div>}
                  </td>
                  <td className="px-3 py-2 text-slate-300">
                    <span title={formatDateTime(s.last_polled_at)}>{s.last_polled_at ? formatRelative(s.last_polled_at) : 'never'}</span>
                    {s.next_poll_at && <div className="text-xs text-slate-400">next {formatRelative(s.next_poll_at)}</div>}
                  </td>
                  <td className="px-3 py-2">{s.has_secret ? <Badge tone="good">configured</Badge> : <Badge>none</Badge>}</td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-1.5">
                      <Button size="sm" onClick={() => void test(s)} busy={testing === s.id} icon={<PlugZap className="h-3.5 w-3.5" aria-hidden="true" />}>
                        Test
                      </Button>
                      <Button size="sm" onClick={() => setEditing(s)} icon={<Pencil className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Edit ${s.name}`}>
                        Edit
                      </Button>
                      <Button size="sm" variant="danger" onClick={() => setDeleting(s)} icon={<Trash2 className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Delete ${s.name}`}>
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing !== null && <SourceForm source={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        title="Delete source"
        confirmLabel="Delete source"
        danger
        busy={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting)}
        onCancel={() => setDeleting(null)}
      >
        Delete <strong>{deleting?.name}</strong>? Polling stops and its stored credentials are destroyed. Alerts already ingested are kept.
      </ConfirmDialog>
    </>
  );
}
