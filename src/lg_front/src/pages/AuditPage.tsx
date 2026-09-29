import { CheckCircle2, Download, ShieldCheck, XCircle } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { endpoints, type AuditFilters } from '../api/endpoints';
import type { AuditEntryOut, AuditVerifyOut } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { Button, EmptyState, ErrorMessage, JsonBlock, LoadingState, PageHeader, TextField } from '../components/ui';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../lib/csv';
import { formatDateTime, localInputToIso } from '../lib/format';
import { useKeysetList } from '../lib/pagination';

const CSV: CsvColumn<AuditEntryOut>[] = [
  { header: 'id', value: (e) => e.id },
  { header: 'ts', value: (e) => e.ts },
  { header: 'actor_type', value: (e) => e.actor_type },
  { header: 'actor_id', value: (e) => e.actor_id },
  { header: 'action', value: (e) => e.action },
  { header: 'resource_type', value: (e) => e.resource_type },
  { header: 'resource_id', value: (e) => e.resource_id },
  { header: 'details', value: (e) => e.details },
  { header: 'prev_hash', value: (e) => e.prev_hash },
  { header: 'hash', value: (e) => e.hash },
];

export default function AuditPage() {
  const api = useApi();
  const [draft, setDraft] = useState({ action: '', resource_type: '', resource_id: '', actor_id: '', from: '', to: '' });
  const [filters, setFilters] = useState<AuditFilters>({});
  const [expanded, setExpanded] = useState<number | null>(null);
  const [verify, setVerify] = useState<{ busy: boolean; result: AuditVerifyOut | null; error: unknown }>({ busy: false, result: null, error: null });

  const list = useKeysetList({
    queryKey: ['audit', filters],
    fetchPage: (cursor, signal) => endpoints.audit(api, filters, cursor, signal),
    itemKey: (e: AuditEntryOut) => e.id,
  });

  const apply = (e: FormEvent) => {
    e.preventDefault();
    const f: AuditFilters = {};
    for (const k of ['action', 'resource_type', 'resource_id', 'actor_id'] as const) if (draft[k].trim()) f[k] = draft[k].trim();
    const from = localInputToIso(draft.from);
    const to = localInputToIso(draft.to);
    if (from) f.from = from;
    if (to) f.to = to;
    setFilters(f);
  };

  const runVerify = async () => {
    setVerify({ busy: true, result: null, error: null });
    try {
      setVerify({ busy: false, result: await endpoints.verifyAudit(api, localInputToIso(draft.from)), error: null });
    } catch (err) {
      setVerify({ busy: false, result: null, error: err });
    }
  };

  const field = (key: keyof typeof draft, label: string, type = 'text') => (
    <TextField label={label} type={type} value={draft[key]} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })} />
  );

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Who did what in this tenant, newest first. Entries form a SHA-256 hash chain; verification recomputes it to detect tampering."
        actions={
          <>
            <Button onClick={() => void runVerify()} busy={verify.busy} icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />}>
              Verify chain
            </Button>
            <Button onClick={() => downloadCsv(csvFilename('audit'), toCsv(CSV, list.items))} disabled={list.items.length === 0} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
              Export loaded rows (CSV)
            </Button>
          </>
        }
      />
      <div aria-live="polite">
        {verify.result &&
          (verify.result.ok ? (
            <p className="mb-4 flex items-center gap-2 rounded-md border border-emerald-700 bg-emerald-950 px-3 py-2 text-sm text-emerald-100">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              The audit chain is intact{verify.result.since ? ` since ${formatDateTime(verify.result.since)}` : ''}.
            </p>
          ) : (
            <p className="mb-4 flex items-center gap-2 rounded-md border border-red-700 bg-red-950 px-3 py-2 text-sm text-red-100">
              <XCircle className="h-4 w-4" aria-hidden="true" />
              Verification failed: entry {verify.result.first_bad_id ?? 'unknown'} does not match the chain. Treat the log after it as untrusted and investigate.
            </p>
          ))}
        {verify.error !== null && (
          <div className="mb-4">
            <ErrorMessage error={verify.error} compact />
          </div>
        )}
      </div>
      <form onSubmit={apply} aria-label="Filters" className="mb-4 grid gap-3 rounded-lg border border-slate-800 bg-slate-900 p-4 sm:grid-cols-3 xl:grid-cols-7">
        {field('action', 'Action')}
        {field('resource_type', 'Resource type')}
        {field('resource_id', 'Resource id')}
        {field('actor_id', 'Actor id')}
        {field('from', 'From', 'datetime-local')}
        {field('to', 'To', 'datetime-local')}
        <div className="flex items-end">
          <Button type="submit" variant="primary">
            Apply
          </Button>
        </div>
      </form>
      {list.isPending && <LoadingState label="Loading audit log" />}
      {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
      {list.isSuccess && list.items.length === 0 && <EmptyState title="No audit entries match" />}
      {list.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
          <table className="w-full min-w-[900px] text-left text-sm">
            <caption className="sr-only">Audit entries</caption>
            <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-3 py-2">Time</th>
                <th scope="col" className="px-3 py-2">Actor</th>
                <th scope="col" className="px-3 py-2">Action</th>
                <th scope="col" className="px-3 py-2">Resource</th>
                <th scope="col" className="px-3 py-2">Hash</th>
                <th scope="col" className="px-3 py-2 text-right">Details</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((e) => (
                <FragmentRow key={e.id} e={e} open={expanded === e.id} onToggle={() => setExpanded(expanded === e.id ? null : e.id)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {list.hasNextPage && (
        <div className="mt-4 flex justify-center">
          <Button onClick={() => void list.fetchNextPage()} busy={list.isFetchingNextPage}>
            Load older entries
          </Button>
        </div>
      )}
      {list.capped && (
        <p role="status" className="mt-4 text-center text-sm text-slate-300">
          Showing the newest {list.items.length} entries. Narrow the time range or filters to read older ones.
        </p>
      )}
    </>
  );
}

function FragmentRow({ e, open, onToggle }: { e: AuditEntryOut; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className="border-b border-slate-800/70 align-top">
        <td className="whitespace-nowrap px-3 py-2 text-slate-300">{formatDateTime(e.ts)}</td>
        <td className="px-3 py-2 text-slate-200">
          {e.actor_type}
          {e.actor_id && <div className="font-mono text-xs text-slate-400">{e.actor_id}</div>}
        </td>
        <td className="px-3 py-2 font-mono text-xs text-slate-100">{e.action}</td>
        <td className="px-3 py-2 text-slate-200">
          {e.resource_type}
          {e.resource_id && <div className="break-all font-mono text-xs text-slate-400">{e.resource_id}</div>}
        </td>
        <td className="px-3 py-2 font-mono text-xs text-slate-400" title={e.hash}>
          {e.hash.slice(0, 12)}
        </td>
        <td className="px-3 py-2 text-right">
          <Button size="sm" variant="ghost" aria-expanded={open} onClick={onToggle}>
            {open ? 'Hide' : 'Show'}
          </Button>
        </td>
      </tr>
      {open && (
        <tr className="border-b border-slate-800/70">
          <td colSpan={6} className="px-3 py-2">
            <JsonBlock value={{ id: e.id, details: e.details, prev_hash: e.prev_hash, hash: e.hash }} label={`Audit entry ${e.id} details`} />
          </td>
        </tr>
      )}
    </>
  );
}
