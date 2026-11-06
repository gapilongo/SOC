import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterIntegrationChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import { MICROSOFT_CLOUDS, type IntegrationOut, type JsonObject } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { Badge } from '../../components/Badge';
import { Modal } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Button, Checkbox, ErrorMessage, LoadingState, SelectField, TextAreaField, TextField } from '../../components/ui';
import { formatDateTime } from '../../lib/format';
import { capabilitiesConfig, initialStates, MicrosoftCapabilities, type CapabilityStates } from './MicrosoftCapabilities';

export const CLOUD_LABELS: Record<string, string> = {
  global: 'Global (commercial and GCC)',
  usgov_gcc_high: 'US Government GCC High',
  usgov_dod: 'US Government DoD',
};
const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
/** Config fields the stored credential is bound to: changing one needs the credential again. */
export const BOUND_FIELDS = ['cloud', 'directory_tenant_id', 'client_id', 'credential', 'certificate_pem'] as const;

export type Credential = 'certificate' | 'client_secret';

export interface MicrosoftFormValues {
  cloud: string;
  directory_tenant_id: string;
  client_id: string;
  credential: Credential;
  certificate_pem: string;
  defender_geo: string;
}

function obj(value: unknown): JsonObject {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonObject) : {};
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

export function secretField(credential: Credential): 'private_key_pem' | 'client_secret' {
  return credential === 'certificate' ? 'private_key_pem' : 'client_secret';
}

/** The integration config to send (no URL anywhere; the derived certificate details are not sent back). */
export function buildMicrosoftConfig(values: MicrosoftFormValues, states: CapabilityStates): JsonObject {
  for (const key of ['directory_tenant_id', 'client_id'] as const) {
    if (!GUID.test(values[key].trim())) {
      throw new Error(`${key === 'client_id' ? 'Application (client) ID' : 'Directory (tenant) ID'} must be a GUID.`);
    }
  }
  const config: JsonObject = {
    cloud: values.cloud,
    directory_tenant_id: values.directory_tenant_id.trim(),
    client_id: values.client_id.trim(),
    credential: values.credential,
    capabilities: capabilitiesConfig(states),
  };
  if (values.credential === 'certificate') {
    if (!values.certificate_pem.trim()) throw new Error('Paste the public certificate (PEM) uploaded to the app registration.');
    config.certificate_pem = values.certificate_pem.trim();
  }
  if (values.cloud === 'global' && values.defender_geo) config.defender_geo = values.defender_geo;
  return config;
}

/** Whether a field the stored credential is bound to changed (then the credential must be entered again). */
export function bindingChanged(stored: JsonObject | undefined, values: MicrosoftFormValues): boolean {
  if (!stored) return false;
  return BOUND_FIELDS.some((f) => str(stored[f]).trim() !== str(values[f]).trim());
}

/** Create or edit the tenant's Microsoft integration (one per tenant). */
export function MicrosoftIntegrationForm({ integration, onClose }: { integration: IntegrationOut | null; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const editing = integration !== null;
  const stored = integration?.config;
  const catalog = useQuery({ queryKey: qk.microsoftCatalog.all, queryFn: ({ signal }) => endpoints.microsoftCatalog(api, signal) });
  const [name, setName] = useState(integration?.name ?? 'Microsoft 365');
  const [enabled, setEnabled] = useState(integration?.enabled ?? true);
  const [values, setValues] = useState<MicrosoftFormValues>({
    cloud: str(stored?.cloud) || 'global',
    directory_tenant_id: str(stored?.directory_tenant_id),
    client_id: str(stored?.client_id),
    credential: stored?.credential === 'client_secret' ? 'client_secret' : 'certificate',
    certificate_pem: str(stored?.certificate_pem),
    defender_geo: str(stored?.defender_geo),
  });
  const [secret, setSecret] = useState('');
  const [states, setStates] = useState<CapabilityStates | null>(null);
  const [error, setError] = useState<unknown>(null);
  const capabilities = catalog.data?.capabilities ?? [];
  const current = states ?? initialStates(capabilities, obj(stored?.capabilities));
  const field = secretField(values.credential);
  const configured = Boolean(integration?.secrets?.[field]);
  const rebind = bindingChanged(stored, values);
  const needSecret = !configured || rebind;
  const certificate = obj(stored?.certificate);
  const set = (patch: Partial<MicrosoftFormValues>) => setValues({ ...values, ...patch });

  const m = useMutation({
    mutationFn: async () => {
      const config = buildMicrosoftConfig(values, current);
      const patch: Record<string, string | null> = {};
      if (secret.trim()) patch[field] = secret.trim();
      const other = secretField(values.credential === 'certificate' ? 'client_secret' : 'certificate');
      if (integration?.secrets?.[other]) patch[other] = null;
      if (editing) {
        return endpoints.updateIntegration(api, integration.id, {
          name: name.trim(),
          enabled,
          config,
          ...(Object.keys(patch).length ? { secret: patch } : {}),
        });
      }
      return endpoints.createIntegration(api, { kind: 'microsoft', name: name.trim(), enabled, events: [], config, secret: patch });
    },
    onSuccess: (saved) => {
      setSecret('');
      toast.success(`Integration ${saved.name} saved.`);
      void afterIntegrationChange(client);
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
      size="xl"
      title={editing ? `Edit ${integration.name}` : 'Add Microsoft 365 direct response'}
      description="LG-SOTF acts in your Microsoft tenant (mail, Entra ID, Defender for Endpoint) with its own app registration. Nothing is changed until a capability is live and dry run is off."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="microsoft-form" variant="primary" busy={m.isPending}>
            {editing ? 'Save changes' : 'Create integration'}
          </Button>
        </>
      }
    >
      <form id="microsoft-form" onSubmit={submit} className="space-y-4" autoComplete="off">
        {error !== null && <ErrorMessage error={error} compact />}
        <div className="grid gap-3 sm:grid-cols-2">
          <TextField label="Name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="self-end" />
          <SelectField label="Cloud" value={values.cloud} onChange={(e) => set({ cloud: e.target.value, defender_geo: e.target.value === 'global' ? values.defender_geo : '' })}>
            {MICROSOFT_CLOUDS.map((c) => (
              <option key={c} value={c}>
                {CLOUD_LABELS[c]}
              </option>
            ))}
          </SelectField>
          <SelectField
            label="Defender API region"
            value={values.defender_geo}
            disabled={values.cloud !== 'global'}
            hint="Global cloud only; the regional host is closer to your data."
            onChange={(e) => set({ defender_geo: e.target.value })}
          >
            <option value="">Default (api.security.microsoft.com)</option>
            {(catalog.data?.defender_geos ?? []).map((g) => (
              <option key={g} value={g}>
                {g}.api.security.microsoft.com
              </option>
            ))}
          </SelectField>
          <TextField
            label="Directory (tenant) ID"
            required
            spellCheck={false}
            value={values.directory_tenant_id}
            onChange={(e) => set({ directory_tenant_id: e.target.value })}
            hint="The customer directory's GUID (not common, organizations or a domain)."
          />
          <TextField
            label="Application (client) ID"
            required
            spellCheck={false}
            value={values.client_id}
            onChange={(e) => set({ client_id: e.target.value })}
          />
        </div>
        <fieldset className="space-y-3 rounded-control border border-subtle p-3">
          <legend className="px-1 text-sm font-medium text-body">Credential (write-only)</legend>
          <div className="flex flex-wrap gap-4" role="radiogroup" aria-label="Credential type">
            {(['certificate', 'client_secret'] as const).map((c) => (
              <label key={c} className="inline-flex items-center gap-2 text-sm text-body">
                <input
                  type="radio"
                  name="credential"
                  value={c}
                  checked={values.credential === c}
                  onChange={() => {
                    set({ credential: c });
                    setSecret('');
                  }}
                />
                {c === 'certificate' ? 'Certificate (recommended by Microsoft)' : 'Client secret'}
              </label>
            ))}
          </div>
          {values.credential === 'certificate' && (
            <>
              <TextAreaField
                label="Public certificate (PEM)"
                rows={4}
                spellCheck={false}
                value={values.certificate_pem}
                onChange={(e) => set({ certificate_pem: e.target.value })}
                hint="The certificate uploaded to the app registration (Certificates & secrets); RSA, 2048 bits or more."
              />
              {Object.keys(certificate).length > 0 && (
                <p className="text-xs text-secondary">
                  Stored certificate: SHA-1 thumbprint <code className="select-all">{str(certificate.thumbprint_sha1)}</code>, expires{' '}
                  {formatDateTime(str(certificate.not_after))}.
                </p>
              )}
            </>
          )}
          {values.credential === 'certificate' ? (
            <TextAreaField
              label={
                <span className="inline-flex items-center gap-1.5">
                  Private key (PEM, unencrypted)
                  {configured && <Badge tone="good">configured</Badge>}
                </span>
              }
              rows={3}
              spellCheck={false}
              autoComplete="off"
              required={needSecret}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              hint={rebind && configured ? 'The cloud, app or certificate changed: enter the private key again.' : 'Stored encrypted and never shown again.'}
            />
          ) : (
            <TextField
              label={
                <span className="inline-flex items-center gap-1.5">
                  Client secret
                  {configured && <Badge tone="good">configured</Badge>}
                </span>
              }
              type="password"
              autoComplete="new-password"
              required={needSecret}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              hint={rebind && configured ? 'The cloud or app changed: enter the secret again.' : 'The secret value (not its id); stored encrypted, never shown again.'}
            />
          )}
        </fieldset>
        <section aria-label="Capabilities" className="space-y-2">
          <h3 className="text-sm font-semibold text-fg">Capabilities</h3>
          <p className="text-xs text-muted">
            Enabled capabilities rehearse (read-only, recorded as dry run) until you make them live. Kill switches (install and tenant dry run)
            always win.
          </p>
          {catalog.isPending && <LoadingState label="Loading capabilities" />}
          {catalog.isError && <ErrorMessage error={catalog.error} onRetry={() => void catalog.refetch()} compact />}
          {catalog.data && <MicrosoftCapabilities catalog={capabilities} states={current} cloud={values.cloud} onChange={setStates} />}
        </section>
      </form>
    </Modal>
  );
}
