import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent, type ReactNode } from 'react';

import { endpoints } from '../api/endpoints';
import { AUTONOMY_MODES, RISK_LEVELS, type JsonObject, type TenantSettingsOut } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { Badge } from '../components/Badge';
import { useToast } from '../components/Toast';
import { Button, Card, Checkbox, ErrorMessage, LoadingState, PageHeader, SelectField, TextAreaField, TextField } from '../components/ui';
import { formatDateTime } from '../lib/format';

function obj(value: unknown): JsonObject {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonObject) : {};
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter(Boolean);
}

/** Effective per-risk autonomy stored for the tenant (response.autonomy overrides the top-level map). */
export function storedAutonomy(settings: JsonObject): Record<string, string> {
  return { ...obj(settings.autonomy), ...obj(obj(settings.response).autonomy) } as Record<string, string>;
}

/** Merge patch for the autonomy section: one top-level map, the legacy response.autonomy removed. */
export function autonomyPatch(settings: JsonObject, choice: Record<string, string>): JsonObject {
  const map: Record<string, string> = {};
  for (const risk of RISK_LEVELS) if (choice[risk]) map[risk] = choice[risk];
  const patch: JsonObject = { autonomy: Object.keys(map).length ? map : null };
  if (obj(settings.response).autonomy !== undefined) patch.response = { autonomy: null };
  return patch;
}

function useSave(onDone?: () => void) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: (patch: JsonObject) => endpoints.patchTenantSettings(api, patch),
    onSuccess: (out) => {
      client.setQueryData(['tenant-settings'], out);
      toast.success('Settings saved.');
      onDone?.();
    },
  });
}

function Section({ title, description, children, onSubmit, busy, error, saveLabel }: { title: string; description: ReactNode; children: ReactNode; onSubmit: () => void; busy: boolean; error: unknown; saveLabel?: string }) {
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit();
  };
  return (
    <Card title={title}>
      <form onSubmit={submit} className="space-y-4">
        <p className="text-sm text-slate-300">{description}</p>
        {error ? <ErrorMessage error={error} compact /> : null}
        {children}
        <div className="flex justify-end">
          <Button type="submit" variant="primary" busy={busy}>
            {saveLabel ?? `Save ${title.toLowerCase()}`}
          </Button>
        </div>
      </form>
    </Card>
  );
}

const AUTONOMY_HELP: Record<string, string> = {
  auto: 'run without approval',
  approval: 'wait for an analyst or admin',
  disabled: 'never run',
};

function AutonomySection({ data }: { data: TenantSettingsOut }) {
  const [choice, setChoice] = useState<Record<string, string>>(storedAutonomy(data.settings));
  const save = useSave();
  return (
    <Section
      title="Autonomy"
      description="What happens to proposed response actions of each risk level. Unset levels use the installation default."
      onSubmit={() => save.mutate(autonomyPatch(data.settings, choice))}
      busy={save.isPending}
      error={save.error}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        {RISK_LEVELS.map((risk) => (
          <SelectField key={risk} label={`${risk[0].toUpperCase()}${risk.slice(1)} risk`} value={choice[risk] ?? ''} onChange={(e) => setChoice({ ...choice, [risk]: e.target.value })}>
            <option value="">Installation default</option>
            {AUTONOMY_MODES.map((m) => (
              <option key={m} value={m}>
                {m}: {AUTONOMY_HELP[m]}
              </option>
            ))}
          </SelectField>
        ))}
      </div>
    </Section>
  );
}

function ResponseSection({ data }: { data: TenantSettingsOut }) {
  const r = obj(data.settings.response);
  const [connector, setConnector] = useState(typeof r.connector === 'string' ? r.connector : '');
  const [dryRun, setDryRun] = useState(r.dry_run !== false);
  const [webhookUrl, setWebhookUrl] = useState(typeof r.webhook_url === 'string' ? r.webhook_url : '');
  const [secret, setSecret] = useState('');
  const [removeSecret, setRemoveSecret] = useState(false);
  const [cap, setCap] = useState(typeof r.max_actions_per_hour === 'number' ? String(r.max_actions_per_hour) : '');
  const [internal, setInternal] = useState(r.allow_internal_ip_blocks === true);
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave(() => {
    setSecret('');
    setRemoveSecret(false);
  });
  const configured = r.webhook_secret_configured === true;
  const submit = () => {
    setLocalError(null);
    const patch: JsonObject = {
      connector: connector || null,
      dry_run: dryRun,
      webhook_url: webhookUrl.trim() || null,
      allow_internal_ip_blocks: internal,
    };
    if (cap.trim()) {
      const n = Number(cap);
      if (!Number.isInteger(n) || n < 0) {
        setLocalError(new Error('Maximum actions per hour must be a whole number.'));
        return;
      }
      patch.max_actions_per_hour = n;
    } else {
      patch.max_actions_per_hour = null;
    }
    if (removeSecret) patch.webhook_secret = null;
    else if (secret) patch.webhook_secret = secret;
    save.mutate({ response: patch });
  };
  return (
    <Section
      title="Response"
      description="How approved actions are carried out. In dry-run mode actions are recorded but never executed."
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      <Checkbox label="Dry run (record actions without executing them)" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
      <div className="grid gap-3 sm:grid-cols-2">
        <SelectField label="Connector" value={connector} onChange={(e) => setConnector(e.target.value)}>
          <option value="">Installation default</option>
          <option value="dry_run">dry_run</option>
          <option value="webhook">webhook (SOAR)</option>
        </SelectField>
        <TextField label="Webhook URL" type="url" placeholder="https://soar.example.com/hooks/lg-sotf" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
        <TextField
          label="Webhook signing secret (write-only)"
          type="password"
          autoComplete="new-password"
          disabled={removeSecret}
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          hint={configured ? 'A secret is configured. Leave empty to keep it.' : 'No secret configured.'}
        />
        <TextField label="Maximum actions per hour" type="number" min={0} value={cap} onChange={(e) => setCap(e.target.value)} hint="Empty uses the installation default." />
      </div>
      {configured && <Checkbox label="Remove the stored webhook secret" checked={removeSecret} onChange={(e) => setRemoveSecret(e.target.checked)} />}
      <Checkbox
        label="Allow blocking internal (private) IP addresses"
        checked={internal}
        onChange={(e) => setInternal(e.target.checked)}
        hint="Off by default so an automated action cannot cut off internal infrastructure."
      />
    </Section>
  );
}

function ProtectedSection({ data }: { data: TenantSettingsOut }) {
  const raw = data.settings.protected_assets;
  const pa = Array.isArray(raw) ? { hosts: raw } : obj(raw);
  const legacyCidrs = strings(data.settings.protected_cidrs);
  const [hosts, setHosts] = useState(strings(pa.hosts).join('\n'));
  const [users, setUsers] = useState(strings(pa.users).join('\n'));
  const [domains, setDomains] = useState(strings(pa.domains).join('\n'));
  const [cidrs, setCidrs] = useState([...strings(pa.cidrs), ...legacyCidrs].join('\n'));
  const [processes, setProcesses] = useState(strings(pa.processes).join('\n'));
  const [hashes, setHashes] = useState(strings(pa.hashes).join('\n'));
  const save = useSave();
  const submit = () => {
    const patch: JsonObject = {
      protected_assets: {
        hosts: lines(hosts),
        users: lines(users),
        domains: lines(domains),
        cidrs: lines(cidrs),
        processes: lines(processes),
        hashes: lines(hashes),
      },
    };
    if (data.settings.protected_cidrs !== undefined) patch.protected_cidrs = null;
    save.mutate(patch);
  };
  return (
    <Section
      title="Protected assets"
      description="No automated or approved action may target these. Host, user and process entries accept * and ? wildcards. Critical operating-system and security-agent processes (lsass.exe, explorer.exe, ...) are always protected. One entry per line."
      onSubmit={submit}
      busy={save.isPending}
      error={save.error}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <TextAreaField label="Hosts" rows={4} value={hosts} onChange={(e) => setHosts(e.target.value)} placeholder={'dc01.corp.example\n*-prod-db-*'} />
        <TextAreaField label="Users" rows={4} value={users} onChange={(e) => setUsers(e.target.value)} placeholder="administrator" />
        <TextAreaField label="Domains" rows={4} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="corp.example" />
        <TextAreaField label="Networks (CIDR)" rows={4} value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="10.0.0.0/8" />
        <TextAreaField label="Processes" rows={4} value={processes} onChange={(e) => setProcesses(e.target.value)} placeholder="corp-agent.exe" />
        <TextAreaField label="File hashes" rows={4} value={hashes} onChange={(e) => setHashes(e.target.value)} placeholder="SHA-256, SHA-1 or MD5" />
      </div>
    </Section>
  );
}

function BudgetSection({ data }: { data: TenantSettingsOut }) {
  const current = data.settings.llm_daily_token_budget;
  const [budget, setBudget] = useState(typeof current === 'number' ? String(current) : '');
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    if (!budget.trim()) {
      save.mutate({ llm_daily_token_budget: null });
      return;
    }
    const n = Number(budget);
    if (!Number.isInteger(n) || n < 0) {
      setLocalError(new Error('The budget must be a whole number of tokens.'));
      return;
    }
    save.mutate({ llm_daily_token_budget: n });
  };
  return (
    <Section
      title="LLM budget"
      saveLabel="Save LLM budget"
      description="Daily token budget for this tenant. When it is used up, alerts are assessed by rules only until the next day (UTC)."
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      <TextField label="Daily token budget" type="number" min={0} value={budget} onChange={(e) => setBudget(e.target.value)} hint="Empty uses the installation default; 0 disables LLM calls." wrapperClassName="max-w-xs" />
    </Section>
  );
}

function ReviewSection({ data }: { data: TenantSettingsOut }) {
  const review = obj(data.settings.review);
  const sla = obj(review.sla_minutes);
  const [l1, setL1] = useState(typeof sla.L1 === 'number' ? String(sla.L1) : '');
  const [l2, setL2] = useState(typeof sla.L2 === 'number' ? String(sla.L2) : '');
  const [l3, setL3] = useState(typeof sla.L3 === 'number' ? String(sla.L3) : '');
  const [suggest, setSuggest] = useState(review.suggest_suppressions !== false);
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    const minutes: Record<string, number> = {};
    for (const [level, v] of [['L1', l1], ['L2', l2], ['L3', l3]] as const) {
      if (!v.trim()) continue;
      const n = Number(v);
      if (!Number.isInteger(n) || n < 1 || n > 43_200) {
        setLocalError(new Error(`${level} SLA must be 1 to 43200 minutes.`));
        return;
      }
      minutes[level] = n;
    }
    const next: JsonObject = { ...review, suggest_suppressions: suggest };
    if (Object.keys(minutes).length) next.sla_minutes = minutes;
    else delete next.sla_minutes;
    save.mutate({ review: next });
  };
  return (
    <Section title="Review policy" description="Escalation SLAs per level (minutes); empty fields use the defaults." onSubmit={submit} busy={save.isPending} error={localError ?? save.error}>
      <div className="grid gap-3 sm:grid-cols-3">
        <TextField label="L1 SLA (minutes)" type="number" min={1} value={l1} onChange={(e) => setL1(e.target.value)} />
        <TextField label="L2 SLA (minutes)" type="number" min={1} value={l2} onChange={(e) => setL2(e.target.value)} />
        <TextField label="L3 SLA (minutes)" type="number" min={1} value={l3} onChange={(e) => setL3(e.target.value)} />
      </div>
      <Checkbox label="Offer suppression suggestions from false-positive decisions" checked={suggest} onChange={(e) => setSuggest(e.target.checked)} />
    </Section>
  );
}

export default function TenantSettingsPage() {
  const api = useApi();
  const q = useQuery({ queryKey: ['tenant-settings'], queryFn: ({ signal }) => endpoints.tenantSettings(api, signal) });
  const d = q.data;
  return (
    <>
      <PageHeader
        title="Tenant settings"
        description={
          d ? (
            <span className="inline-flex flex-wrap items-center gap-2">
              {d.name} ({d.tenant_id}) <Badge tone={d.status === 'active' ? 'good' : 'bad'}>{d.status}</Badge> last changed {formatDateTime(d.updated_at)}
            </span>
          ) : undefined
        }
      />
      {q.isPending && <LoadingState label="Loading settings" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {d && (
        // Re-mount the sections when the stored settings change so the forms show saved values.
        <div key={d.updated_at} className="grid gap-5 xl:grid-cols-2">
          <AutonomySection data={d} />
          <ResponseSection data={d} />
          <ProtectedSection data={d} />
          <div className="space-y-5">
            <BudgetSection data={d} />
            <ReviewSection data={d} />
          </div>
        </div>
      )}
    </>
  );
}
