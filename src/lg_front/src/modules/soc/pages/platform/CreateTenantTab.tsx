/** MSSP console, Create tenant tab: provisioning from a profile or a copy of a tenant's settings. */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterTenantChange } from '../../api/invalidate';
import { TENANT_PROFILES, type TenantCreatedOut, type TenantCreateIn } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { Button, Card, ErrorMessage, SelectField, TextField } from '../../../../components/ui';
import { usePlatformTenants } from './TenantSwitcher';

const PROFILE_HELP: Record<string, string> = {
  conservative: 'every action needs approval; high and critical risk never run; MFA required',
  balanced: 'low-risk actions run on their own, the rest need approval',
  autonomous: 'low and medium risk run on their own; high and critical need approval',
};

/** The template select value ('' | 'profile:<name>' | 'copy:<tenant id>') as request fields. */
export function templateFields(template: string): Pick<TenantCreateIn, 'profile' | 'copy_settings_from'> {
  if (template.startsWith('profile:')) return { profile: template.slice(8) as TenantCreateIn['profile'] };
  if (template.startsWith('copy:')) return { copy_settings_from: template.slice(5) };
  return {};
}

export function CreateTenantTab() {
  const api = useApi();
  const client = useQueryClient();
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [template, setTemplate] = useState('profile:balanced');
  const [created, setCreated] = useState<TenantCreatedOut | null>(null);
  const tenants = usePlatformTenants({ staleTime: 60_000 });
  const m = useMutation({
    mutationFn: () =>
      endpoints.createTenant(api, {
        id: id.trim(),
        name: name.trim(),
        admin_email: adminEmail.trim() || null,
        admin_password: adminPassword || null,
        ...templateFields(template),
      }),
    onSuccess: (t) => {
      setCreated(t);
      setId('');
      setName('');
      setAdminEmail('');
      setAdminPassword('');
      void afterTenantChange(client);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setCreated(null);
    m.mutate();
  };
  return (
    <Card title="Create tenant" className="max-w-3xl">
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        {m.isError && <ErrorMessage error={m.error} compact />}
        {created && (
          <p role="status" className="rounded-control border border-state-ok/60 bg-tint-ok px-3 py-2 text-sm text-ok-fg">
            Tenant {created.name} ({created.id}) created{created.admin ? ` with admin ${created.admin.email}` : ''}
            {created.settings_keys && created.settings_keys.length > 0 ? `; seeded settings: ${created.settings_keys.join(', ')}` : ''}.
          </p>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <TextField label="Tenant id" required pattern="[a-z0-9][a-z0-9_-]{1,62}" hint="Lowercase letters, digits, - and _" value={id} onChange={(e) => setId(e.target.value)} />
          <TextField label="Display name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <TextField label="First admin email (optional)" type="email" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} />
          <TextField
            label="First admin password (optional)"
            type="password"
            autoComplete="new-password"
            value={adminPassword}
            onChange={(e) => setAdminPassword(e.target.value)}
            hint="Leave empty for a single sign-on admin."
          />
          <SelectField
            label="Initial settings"
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            wrapperClassName="sm:col-span-2"
            hint="Profiles seed autonomy, response and review settings; actions stay in dry run until a connector is configured. Copying takes another tenant's policy, never its secrets, destinations or protected assets."
          >
            <option value="">Installation defaults</option>
            {TENANT_PROFILES.map((p) => (
              <option key={p} value={`profile:${p}`}>
                Profile: {p} ({PROFILE_HELP[p]})
              </option>
            ))}
            {(tenants.data ?? []).map((t) => (
              <option key={t.id} value={`copy:${t.id}`}>
                Copy policy from {t.name} ({t.id})
              </option>
            ))}
          </SelectField>
        </div>
        <Button type="submit" variant="primary" busy={m.isPending}>
          Create tenant
        </Button>
      </form>
    </Card>
  );
}
