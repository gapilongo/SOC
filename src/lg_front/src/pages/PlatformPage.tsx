import { useMutation } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../api/endpoints';
import type { TenantCreatedOut } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { Button, Card, ErrorMessage, PageHeader, TextField } from '../components/ui';
import { TenantDataCard } from './platform/TenantDataCard';

export default function PlatformPage() {
  const api = useApi();
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [created, setCreated] = useState<TenantCreatedOut | null>(null);
  const m = useMutation({
    mutationFn: () =>
      endpoints.createTenant(api, {
        id: id.trim(),
        name: name.trim(),
        admin_email: adminEmail.trim() || null,
        admin_password: adminPassword || null,
      }),
    onSuccess: (t) => {
      setCreated(t);
      setId('');
      setName('');
      setAdminEmail('');
      setAdminPassword('');
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setCreated(null);
    m.mutate();
  };
  return (
    <>
      <PageHeader
        title="Platform"
        description="Provision tenants. To work inside a tenant, enter its id in the header's tenant switcher; every request is recorded in that tenant's audit log."
      />
      <Card title="Create tenant" className="max-w-2xl">
        <form onSubmit={submit} className="space-y-4" autoComplete="off">
          {m.isError && <ErrorMessage error={m.error} compact />}
          {created && (
            <p role="status" className="rounded-md border border-emerald-700 bg-emerald-950 px-3 py-2 text-sm text-emerald-100">
              Tenant {created.name} ({created.id}) created{created.admin ? ` with admin ${created.admin.email}` : ''}.
            </p>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            <TextField label="Tenant id" required pattern="[a-z0-9][a-z0-9_-]{1,62}" hint="Lowercase letters, digits, - and _" value={id} onChange={(e) => setId(e.target.value)} />
            <TextField label="Display name" required value={name} onChange={(e) => setName(e.target.value)} />
            <TextField label="First admin email (optional)" type="email" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} />
            <TextField
              label="First admin password (optional)"
              type="password"
              autoComplete="new-password"
              value={adminPassword}
              onChange={(e) => setAdminPassword(e.target.value)}
              hint="Leave empty for a single sign-on admin."
            />
          </div>
          <Button type="submit" variant="primary" busy={m.isPending}>
            Create tenant
          </Button>
        </form>
      </Card>
      <div className="mt-5">
        <TenantDataCard />
      </div>
    </>
  );
}
