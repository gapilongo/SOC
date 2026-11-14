/** Tenant settings: autonomy per risk level, response options, protected assets and the LLM budget. */

import { useState } from 'react';

import { AUTONOMY_MODES, RISK_LEVELS, type JsonObject, type TenantSettingsOut } from '../../api/types';
import { Checkbox, SelectField, TextAreaField, TextField } from '../../../../components/ui';
import { asObject } from '../../../../lib/json';
import { lines, Section, strings, useSave } from './shared';

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

const AUTONOMY_HELP: Record<string, string> = {
  auto: 'run without approval',
  approval: 'wait for an analyst or admin',
  disabled: 'never run',
};

export function AutonomySection({ data }: { data: TenantSettingsOut }) {
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

export function ResponseSection({ data }: { data: TenantSettingsOut }) {
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

export function ProtectedSection({ data }: { data: TenantSettingsOut }) {
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

export function BudgetSection({ data }: { data: TenantSettingsOut }) {
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
