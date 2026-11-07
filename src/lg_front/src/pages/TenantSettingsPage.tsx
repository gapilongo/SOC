import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent, type ReactNode } from 'react';

import { endpoints } from '../api/endpoints';
import { afterTenantSettingsChange } from '../api/invalidate';
import { qk } from '../api/queryKeys';
import { AUTONOMY_MODES, RISK_LEVELS, ROUTE_NAMES, type JsonObject, type RouteOut, type TenantSettingsOut } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { Badge } from '../components/Badge';
import { LlmTestCard } from './settings/LlmTestCard';
import { useToast } from '../components/Toast';
import { Button, Card, Checkbox, ErrorMessage, LoadingState, PageHeader, SelectField, TextAreaField, TextField } from '../components/ui';
import { formatDateTime, humanize } from '../lib/format';
import { asObject } from '../lib/json';

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
  return { ...asObject(settings.autonomy), ...asObject(asObject(settings.response).autonomy) } as Record<string, string>;
}

/** Merge patch for the autonomy section: one top-level map, the legacy response.autonomy removed. */
export function autonomyPatch(settings: JsonObject, choice: Record<string, string>): JsonObject {
  const map: Record<string, string> = {};
  for (const risk of RISK_LEVELS) if (choice[risk]) map[risk] = choice[risk];
  const patch: JsonObject = { autonomy: Object.keys(map).length ? map : null };
  if (asObject(settings.response).autonomy !== undefined) patch.response = { autonomy: null };
  return patch;
}

function useSave(onDone?: () => void) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: (patch: JsonObject) => endpoints.patchTenantSettings(api, patch),
    onSuccess: (out) => {
      client.setQueryData(qk.tenantSettings.all, out);
      // Saving autonomy or response settings completes the checklist's "autonomy reviewed" step.
      void afterTenantSettingsChange(client);
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
        <p className="text-sm text-secondary">{description}</p>
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
  const r = asObject(data.settings.response);
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
  const pa = Array.isArray(raw) ? { hosts: raw } : asObject(raw);
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

function ReportingSection({ data }: { data: TenantSettingsOut }) {
  const current = asObject(data.settings.reporting).minutes_per_alert;
  const [minutes, setMinutes] = useState(typeof current === 'number' ? String(current) : '');
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    if (!minutes.trim()) {
      save.mutate({ reporting: { minutes_per_alert: null } });
      return;
    }
    const n = Number(minutes);
    if (!Number.isInteger(n) || n < 1 || n > 480) {
      setLocalError(new Error('Minutes per alert must be a whole number from 1 to 480.'));
      return;
    }
    save.mutate({ reporting: { minutes_per_alert: n } });
  };
  return (
    <Section
      title="Reporting"
      saveLabel="Save reporting"
      description="Analyst hours saved = alerts handled without a human x minutes per alert / 60. Set the minutes an analyst typically spends triaging one alert; it is an estimate and is labelled as one in every report."
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      <TextField label="Minutes per alert" type="number" min={1} max={480} value={minutes} onChange={(e) => setMinutes(e.target.value)} hint="Empty uses the default (15)." wrapperClassName="max-w-xs" />
    </Section>
  );
}

function ReviewSection({ data }: { data: TenantSettingsOut }) {
  const review = asObject(data.settings.review);
  const sla = asObject(review.sla_minutes);
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

/** Merge patch for the retention section; an empty field removes that override. */
export function retentionPatch(alerts: string, indicators: string, limits: { min_days: number; max_days: number }): JsonObject | Error {
  const out: JsonObject = {};
  for (const [key, label, value] of [
    ['alerts_days', 'Alert retention', alerts],
    ['indicators_days', 'Indicator retention', indicators],
  ] as const) {
    if (!value.trim()) {
      out[key] = null;
      continue;
    }
    const n = Number(value);
    if (!Number.isInteger(n) || n < limits.min_days || n > limits.max_days) {
      return new Error(`${label} must be a whole number of days from ${limits.min_days} to ${limits.max_days}.`);
    }
    out[key] = n;
  }
  return { retention: out };
}

function RetentionSection({ data }: { data: TenantSettingsOut }) {
  const retention = asObject(data.settings.retention);
  const limits = data.retention_limits ?? { min_days: 1, max_days: 99_999, alerts_days: 90, indicators_days: 30 };
  const [alerts, setAlerts] = useState(typeof retention.alerts_days === 'number' ? String(retention.alerts_days) : '');
  const [indicators, setIndicators] = useState(typeof retention.indicators_days === 'number' ? String(retention.indicators_days) : '');
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    const patch = retentionPatch(alerts, indicators, limits);
    if (patch instanceof Error) {
      setLocalError(patch);
      return;
    }
    save.mutate(patch);
  };
  return (
    <Section
      title="Data retention"
      description={`How long this tenant's finished alerts and indicator sightings are kept before the nightly purge removes them. Allowed: ${limits.min_days} to ${limits.max_days} days; empty fields use the installation default.`}
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Closed alerts (days)"
          type="number"
          min={limits.min_days}
          max={limits.max_days}
          value={alerts}
          onChange={(e) => setAlerts(e.target.value)}
          hint={`Installation default: ${limits.alerts_days} days. Alert timelines and the audit log follow installation settings.`}
        />
        <TextField
          label="Indicator sightings (days)"
          type="number"
          min={limits.min_days}
          max={limits.max_days}
          value={indicators}
          onChange={(e) => setIndicators(e.target.value)}
          hint={`Installation default: ${limits.indicators_days} days. Correlation looks back this far.`}
        />
      </div>
    </Section>
  );
}

/** Limits of the backend's PhishingSettings (lg_sotf.domain.phishing). */
export const PHISHING_FIELDS = [
  { key: 'protected_brands', label: 'Protected brands', max: 200, maxChars: 253 },
  { key: 'executives', label: 'Executives', max: 500, maxChars: 128 },
  { key: 'trusted_authserv_ids', label: 'Trusted mail servers (authserv-id)', max: 20, maxChars: 255 },
] as const;

export type PhishingKey = (typeof PHISHING_FIELDS)[number]['key'];

/** Replacement for the phishing section from one-entry-per-line text (commas are kept: "Smith, Jane"). */
export function phishingPatch(text: Record<PhishingKey, string>): JsonObject | Error {
  const section: Record<string, string[]> = {};
  for (const { key, label, max, maxChars } of PHISHING_FIELDS) {
    const entries = [...new Set(text[key].split('\n').map((l) => l.trim()).filter(Boolean))];
    if (entries.length > max) return new Error(`${label}: at most ${max} entries.`);
    const long = entries.find((e) => e.length > maxChars);
    if (long) return new Error(`${label}: "${long.slice(0, 40)}..." is longer than ${maxChars} characters.`);
    section[key] = entries;
  }
  return { phishing: Object.values(section).some((v) => v.length) ? section : null };
}

const PHISHING_HINTS: Record<PhishingKey, string> = {
  protected_brands: 'Brand names or domains that the look-alike and display-name checks protect.',
  executives: 'Display names attackers impersonate (CEO, CFO, ...).',
  trusted_authserv_ids: 'Your own receiving mail servers; only their Authentication-Results header is trusted.',
};

const PHISHING_PLACEHOLDERS: Record<PhishingKey, string> = {
  protected_brands: 'Example Bank\nexamplebank.example',
  executives: 'Jane Smith',
  trusted_authserv_ids: 'mx.corp.example',
};

function PhishingSection({ data }: { data: TenantSettingsOut }) {
  const stored = asObject(data.settings.phishing);
  const [text, setText] = useState<Record<PhishingKey, string>>({
    protected_brands: strings(stored.protected_brands).join('\n'),
    executives: strings(stored.executives).join('\n'),
    trusted_authserv_ids: strings(stored.trusted_authserv_ids).join('\n'),
  });
  const [localError, setLocalError] = useState<Error | null>(null);
  const save = useSave();
  const submit = () => {
    setLocalError(null);
    const patch = phishingPatch(text);
    if (patch instanceof Error) {
      setLocalError(patch);
      return;
    }
    save.mutate(patch);
  };
  return (
    <Section
      title="Phishing context"
      saveLabel="Save phishing context"
      description="Used by the phishing signals on email alerts. One entry per line."
      onSubmit={submit}
      busy={save.isPending}
      error={localError ?? save.error}
    >
      {PHISHING_FIELDS.map(({ key, label }) => (
        <TextAreaField
          key={key}
          label={label}
          rows={4}
          value={text[key]}
          onChange={(e) => setText({ ...text, [key]: e.target.value })}
          placeholder={PHISHING_PLACEHOLDERS[key]}
          hint={PHISHING_HINTS[key]}
        />
      ))}
    </Section>
  );
}

const ROUTE_SOURCE_LABELS: Record<string, string> = {
  kill_switch: 'install dry run',
  tenant_dry_run: 'tenant dry run',
  sample: 'onboarding sample',
  pinned: 'pinned',
  explicit: 'your override',
  ticketing: 'ticketing integration',
  capability: 'Microsoft capability',
  default: 'tenant default',
};

/** Merge patch of response.routes from the override choices ("" = automatic); null clears them all. */
export function routesPatch(choice: Record<string, string>): JsonObject {
  const routes: Record<string, string> = {};
  for (const [type, route] of Object.entries(choice)) if (route) routes[type] = route;
  return { response: { routes: Object.keys(routes).length ? routes : null } };
}

export function describeRoute(route: RouteOut): string {
  const why = [ROUTE_SOURCE_LABELS[route.source] ?? route.source];
  if (route.capability) why.push(route.capability);
  if (route.live === false) why.push('rehearsal');
  else if (route.live) why.push('live');
  return `${humanize(route.connector)} (${why.join(', ')})`;
}

function RoutingSection({ data }: { data: TenantSettingsOut }) {
  const api = useApi();
  const q = useQuery({ queryKey: qk.responseRoutes.forSettings(data.updated_at), queryFn: ({ signal }) => endpoints.responseRoutes(api, signal) });
  const stored = asObject(asObject(data.settings.response).routes) as Record<string, string>;
  const [choice, setChoice] = useState<Record<string, string>>(stored);
  const save = useSave();
  const routes = Object.entries(asObject(q.data?.routes)) as Array<[string, RouteOut]>;
  return (
    <Section
      title="Response routing"
      saveLabel="Save response routing"
      description="Which connector executes each action type: the kill switches first, then your overrides, a ticketing integration for create_ticket, an enabled Microsoft capability, and finally the tenant default connector."
      onSubmit={() => save.mutate(routesPatch(choice))}
      busy={save.isPending}
      error={save.error}
    >
      {q.data?.dry_run_forced && (
        <p role="status" className="rounded-control border border-warn/60 bg-tint-warn px-3 py-2 text-sm text-warn-fg">
          Dry run is on: nothing executes. Actions are recorded as dry runs until the install and tenant dry run switches are off.
        </p>
      )}
      {q.isPending && <LoadingState label="Loading routes" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} compact />}
      {routes.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Response routes</caption>
            <thead className="border-b border-subtle text-xs uppercase tracking-wide text-muted">
              <tr>
                <th scope="col" className="px-2 py-1">Action</th>
                <th scope="col" className="px-2 py-1">Executes through</th>
                <th scope="col" className="px-2 py-1">Override</th>
              </tr>
            </thead>
            <tbody>
              {routes.map(([type, route]) => (
                <tr key={type} className="border-b border-subtle align-top">
                  <th scope="row" className="px-2 py-1 text-left font-normal text-fg">
                    {humanize(type)}
                  </th>
                  <td className="px-2 py-1 text-xs text-secondary">
                    {describeRoute(route)}
                    {route.problem && <span className="block text-danger-fg">{route.problem}</span>}
                  </td>
                  <td className="px-2 py-1">
                    <SelectField
                      label={<span className="sr-only">Route for {humanize(type)}</span>}
                      value={choice[type] ?? ''}
                      onChange={(e) => setChoice({ ...choice, [type]: e.target.value })}
                    >
                      <option value="">auto</option>
                      {ROUTE_NAMES.map((name) => (
                        <option key={name} value={name} disabled={name === 'ticketing' && type !== 'create_ticket'}>
                          {humanize(name)}
                        </option>
                      ))}
                    </SelectField>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

function SecuritySection({ data }: { data: TenantSettingsOut }) {
  const current = asObject(data.settings.security).require_mfa === true;
  const [requireMfa, setRequireMfa] = useState(current);
  const save = useSave();
  return (
    <Section
      title="Sign-in security"
      saveLabel="Save sign-in security"
      description="Local accounts (email and password). Single sign-on users get MFA from your identity provider."
      onSubmit={() => save.mutate({ security: { require_mfa: requireMfa } })}
      busy={save.isPending}
      error={save.error}
    >
      <Checkbox
        label="Require MFA for local accounts"
        hint="Users without an authenticator app must set one up right after their password at the next sign-in; existing sessions of those users end at their next refresh."
        checked={requireMfa}
        onChange={(e) => setRequireMfa(e.target.checked)}
      />
    </Section>
  );
}

export default function TenantSettingsPage() {
  const api = useApi();
  const q = useQuery({ queryKey: qk.tenantSettings.all, queryFn: ({ signal }) => endpoints.tenantSettings(api, signal) });
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
          <RoutingSection data={d} />
          <ProtectedSection data={d} />
          <PhishingSection data={d} />
          <div className="space-y-5">
            <SecuritySection data={d} />
            <BudgetSection data={d} />
            <LlmTestCard />
            <ReviewSection data={d} />
            <RetentionSection data={d} />
            <ReportingSection data={d} />
          </div>
        </div>
      )}
    </>
  );
}
