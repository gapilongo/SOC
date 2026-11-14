import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, KeyRound, Pencil, Plus, ShieldOff, Trash2, UserPlus } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { endpoints } from '../../../api/endpoints';
import { afterApiKeyChange, afterUserChange } from '../../../api/invalidate';
import { qk } from '../../../api/queryKeys';
import { API_KEY_SCOPES, type ApiKeyCreatedOut, type ApiKeyOut, type ApiKeyScope, type Role, type UserOut, type UserUpdateIn } from '../../../api/types';
import { useApi, useAuth } from '../../../auth/AuthContext';
import { can } from '../../../auth/roles';
import { AiClientHelp } from '../../../components/AiClientHelp';
import { Badge } from '../components/Badge';
import { ConfirmDialog, Modal } from '../../../components/Dialog';
import { useToast } from '../../../components/Toast';
import { Button, Card, Checkbox, EmptyState, ErrorMessage, LoadingState, PageHeader, SelectField, TextField } from '../../../components/ui';
import { formatDateTime, formatRelative } from '../../../lib/format';

const ROLES: Role[] = ['viewer', 'analyst', 'admin'];

function UserDialog({ user, onClose }: { user: UserOut | null; onClose: () => void }) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const editing = user !== null;
  const self = editing && principal?.userId === user.id;
  const [email, setEmail] = useState(user?.email ?? '');
  const [role, setRole] = useState<Role>((user?.role as Role) ?? 'analyst');
  const [active, setActive] = useState(user?.is_active ?? true);
  const [platformAdmin, setPlatformAdmin] = useState(user?.is_platform_admin ?? false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const m = useMutation({
    mutationFn: () => {
      if (editing) {
        const body: UserUpdateIn = {};
        if (role !== user.role) body.role = role;
        if (active !== user.is_active) body.is_active = active;
        if (password) body.password = password;
        if (can.grantPlatformAdmin(principal) && platformAdmin !== user.is_platform_admin) body.is_platform_admin = platformAdmin;
        return endpoints.updateUser(api, user.id, body);
      }
      return endpoints.createUser(api, {
        email: email.trim(),
        role,
        password: password || null,
        is_active: active,
        ...(can.grantPlatformAdmin(principal) && platformAdmin ? { is_platform_admin: true } : {}),
      });
    },
    onSuccess: (u) => {
      setPassword('');
      toast.success(editing ? `User ${u.email} updated.` : `User ${u.email} created.`);
      void afterUserChange(client);
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
      title={editing ? `Edit ${user.email}` : 'Add user'}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="user-form" variant="primary" busy={m.isPending}>
            {editing ? 'Save' : 'Create user'}
          </Button>
        </>
      }
    >
      <form id="user-form" onSubmit={submit} className="space-y-4" autoComplete="off">
        {error !== null && <ErrorMessage error={error} compact />}
        {!editing && <TextField label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />}
        <SelectField label="Role" value={role} disabled={self} onChange={(e) => setRole(e.target.value as Role)} hint={self ? 'You cannot change your own role.' : undefined}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </SelectField>
        <TextField
          label={editing ? 'New password (optional)' : 'Password (optional)'}
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint={editing ? 'Changing the password signs the user out everywhere.' : 'Leave empty for a single sign-on only account.'}
        />
        <Checkbox label="Active" checked={active} disabled={self} onChange={(e) => setActive(e.target.checked)} hint={editing ? 'Deactivating signs the user out everywhere.' : undefined} />
        {can.grantPlatformAdmin(principal) && (
          <Checkbox
            label="Platform admin"
            hint="May act on every tenant. Grant sparingly."
            checked={platformAdmin}
            onChange={(e) => setPlatformAdmin(e.target.checked)}
          />
        )}
      </form>
    </Modal>
  );
}

function KeyCreated({ created, onClose }: { created: ApiKeyCreatedOut; onClose: () => void }) {
  const toast = useToast();
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created.key);
      setCopied(true);
      toast.success('API key copied to the clipboard.');
    } catch {
      toast.info('Copy failed; select the key and copy it manually.');
    }
  };
  return (
    <Modal
      open
      onClose={onClose}
      title={`API key ${created.name} created`}
      description="This is the only time the key is shown. Store it in your secret manager now."
      footer={
        <Button variant="primary" onClick={onClose}>
          I have stored the key
        </Button>
      }
    >
      <div className="space-y-3">
        <label htmlFor="new-api-key" className="block text-xs font-medium text-secondary">
          API key
        </label>
        <div className="flex gap-2">
          <input
            id="new-api-key"
            readOnly
            value={created.key}
            onFocus={(e) => e.currentTarget.select()}
            className="min-w-0 flex-1 rounded-control border border-control bg-canvas px-3 py-2 font-mono text-xs text-fg"
          />
          <Button onClick={() => void copy()} icon={<Copy className="h-4 w-4" aria-hidden="true" />} data-autofocus>
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </div>
        <p className="text-sm text-secondary">Scopes: {created.scopes.join(', ')}</p>
      </div>
    </Modal>
  );
}

function KeyDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (k: ApiKeyCreatedOut) => void }) {
  const api = useApi();
  const client = useQueryClient();
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<ApiKeyScope[]>(['ingest']);
  const [error, setError] = useState<unknown>(null);
  const m = useMutation({
    mutationFn: () => endpoints.createApiKey(api, name.trim(), scopes),
    onSuccess: (k) => {
      void afterApiKeyChange(client);
      onCreated(k);
    },
    onError: (err) => setError(err),
  });
  return (
    <Modal
      open
      onClose={onClose}
      title="Create API key"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="key-form" variant="primary" busy={m.isPending} disabled={!scopes.length}>
            Create key
          </Button>
        </>
      }
    >
      <form
        id="key-form"
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          m.mutate();
        }}
      >
        {error !== null && <ErrorMessage error={error} compact />}
        <TextField label="Name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} hint="Where the key is used, e.g. the SIEM forwarder." />
        <fieldset>
          <legend className="mb-2 text-sm font-medium text-body">Scopes</legend>
          <div className="space-y-2">
            {API_KEY_SCOPES.map((s) => (
              <Checkbox
                key={s}
                label={s}
                hint={s === 'ingest' ? 'Send alerts to the ingest endpoints.' : s === 'read' ? 'Read alerts, escalations, actions and the dashboard.' : 'Add notes and create (disabled) suppression rules.'}
                checked={scopes.includes(s)}
                onChange={(e) => setScopes(e.target.checked ? [...scopes, s] : scopes.filter((x) => x !== s))}
              />
            ))}
          </div>
        </fieldset>
      </form>
    </Modal>
  );
}

export default function UsersPage() {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const [showInactive, setShowInactive] = useState(false);
  const [showRevoked, setShowRevoked] = useState(false);
  const [editing, setEditing] = useState<UserOut | null | 'new'>(null);
  const [deleting, setDeleting] = useState<UserOut | null>(null);
  const [resetting, setResetting] = useState<UserOut | null>(null);
  const [newKey, setNewKey] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreatedOut | null>(null);
  const [revoking, setRevoking] = useState<ApiKeyOut | null>(null);

  const users = useQuery({ queryKey: qk.users.list(showInactive), queryFn: ({ signal }) => endpoints.users(api, showInactive, signal) });
  const keys = useQuery({ queryKey: qk.apiKeys.list(showRevoked), queryFn: ({ signal }) => endpoints.apiKeys(api, showRevoked, signal) });

  const delUser = useMutation({
    mutationFn: (u: UserOut) => endpoints.deleteUser(api, u.id),
    onSuccess: () => {
      setDeleting(null);
      toast.success('User deleted.');
      void afterUserChange(client);
    },
    onError: (err) => {
      setDeleting(null);
      toast.error(err, 'Delete failed');
    },
  });
  const resetMfa = useMutation({
    mutationFn: (u: UserOut) => endpoints.resetUserMfa(api, u.id),
    onSuccess: (_, u) => {
      setResetting(null);
      toast.success(`MFA reset for ${u.email}. They set it up again at their next sign-in if required.`);
      void afterUserChange(client);
    },
    onError: (err) => {
      setResetting(null);
      toast.error(err, 'Reset failed');
    },
  });
  const revoke = useMutation({
    mutationFn: (k: ApiKeyOut) => endpoints.revokeApiKey(api, k.id),
    onSuccess: () => {
      setRevoking(null);
      toast.success('API key revoked.');
      void afterApiKeyChange(client);
    },
    onError: (err) => {
      setRevoking(null);
      toast.error(err, 'Revoke failed');
    },
  });

  return (
    <>
      <PageHeader title="Users and API keys" description="People who can sign in to this tenant, and keys for machine access." />
      <div className="space-y-6">
        <Card
          title="Users"
          actions={
            <>
              <Checkbox label="Show inactive" checked={showInactive} onChange={(e) => setShowInactive(e.target.checked)} />
              <Button size="sm" variant="primary" onClick={() => setEditing('new')} icon={<UserPlus className="h-3.5 w-3.5" aria-hidden="true" />}>
                Add user
              </Button>
            </>
          }
        >
          {users.isPending && <LoadingState label="Loading users" />}
          {users.isError && <ErrorMessage error={users.error} onRetry={() => void users.refetch()} />}
          {users.data && users.data.length === 0 && <EmptyState title="No users" />}
          {users.data && users.data.length > 0 && (
            <div className="relative overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-sm">
                <caption className="sr-only">Users</caption>
                <thead className="text-xs uppercase tracking-wide text-muted">
                  <tr>
                    <th scope="col" className="py-2 pr-3">Email</th>
                    <th scope="col" className="py-2 pr-3">Role</th>
                    <th scope="col" className="py-2 pr-3">Status</th>
                    <th scope="col" className="py-2 pr-3">MFA</th>
                    <th scope="col" className="py-2 pr-3">Last sign-in</th>
                    <th scope="col" className="py-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.data.map((u) => (
                    <tr key={u.id} className="border-t border-subtle">
                      <td className="py-2 pr-3 text-fg">
                        {u.email}
                        {principal?.userId === u.id && <span className="ml-2 text-xs text-muted">(you)</span>}
                      </td>
                      <td className="py-2 pr-3">
                        <div className="flex flex-wrap gap-1">
                          <Badge tone={u.role === 'admin' ? 'warn' : 'neutral'}>{u.role}</Badge>
                          {u.is_platform_admin && <Badge tone="critical">platform admin</Badge>}
                        </div>
                      </td>
                      <td className="py-2 pr-3">
                        <div className="flex flex-wrap gap-1">
                          {u.is_active ? <Badge tone="good">active</Badge> : <Badge>inactive</Badge>}
                          {u.locked_until && new Date(u.locked_until).getTime() > Date.now() && <Badge tone="bad">locked</Badge>}
                        </div>
                      </td>
                      <td className="py-2 pr-3" data-testid={`mfa-${u.id}`}>
                        {u.mfa_enabled ? (
                          <Badge tone="good">on</Badge>
                        ) : u.oidc_provisioned ? (
                          <Badge tone="info" title="Provisioned by single sign-on; the identity provider handles MFA.">SSO</Badge>
                        ) : (
                          <Badge>off</Badge>
                        )}
                      </td>
                      <td className="whitespace-nowrap py-2 pr-3 text-secondary" title={formatDateTime(u.last_login_at)}>
                        {u.last_login_at ? formatRelative(u.last_login_at) : 'never'}
                      </td>
                      <td className="py-2">
                        <div className="flex justify-end gap-1.5">
                          <Button size="sm" onClick={() => setEditing(u)} aria-label={`Edit ${u.email}`} icon={<Pencil className="h-3.5 w-3.5" aria-hidden="true" />}>
                            Edit
                          </Button>
                          {u.mfa_enabled && principal?.userId !== u.id && (
                            <Button
                              size="sm"
                              disabled={u.is_platform_admin && !principal?.isPlatformAdmin}
                              title={u.is_platform_admin && !principal?.isPlatformAdmin ? 'Only a platform admin can reset a platform admin' : undefined}
                              onClick={() => setResetting(u)}
                              aria-label={`Reset MFA of ${u.email}`}
                              icon={<ShieldOff className="h-3.5 w-3.5" aria-hidden="true" />}
                            >
                              Reset MFA
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="destructive"
                            disabled={principal?.userId === u.id}
                            onClick={() => setDeleting(u)}
                            aria-label={`Delete ${u.email}`}
                            icon={<Trash2 className="h-3.5 w-3.5" aria-hidden="true" />}
                          >
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
        </Card>

        <Card
          title="API keys"
          actions={
            <>
              <Checkbox label="Show revoked" checked={showRevoked} onChange={(e) => setShowRevoked(e.target.checked)} />
              <Button size="sm" variant="primary" onClick={() => setNewKey(true)} icon={<Plus className="h-3.5 w-3.5" aria-hidden="true" />}>
                Create key
              </Button>
            </>
          }
        >
          <AiClientHelp />
          {keys.isPending && <LoadingState label="Loading API keys" />}
          {keys.isError && <ErrorMessage error={keys.error} onRetry={() => void keys.refetch()} />}
          {keys.data && keys.data.length === 0 && <EmptyState title="No API keys" />}
          {keys.data && keys.data.length > 0 && (
            <div className="relative overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-sm">
                <caption className="sr-only">API keys</caption>
                <thead className="text-xs uppercase tracking-wide text-muted">
                  <tr>
                    <th scope="col" className="py-2 pr-3">Name</th>
                    <th scope="col" className="py-2 pr-3">Prefix</th>
                    <th scope="col" className="py-2 pr-3">Scopes</th>
                    <th scope="col" className="py-2 pr-3">Last used</th>
                    <th scope="col" className="py-2 pr-3">Created</th>
                    <th scope="col" className="py-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {keys.data.map((k) => (
                    <tr key={k.id} className="border-t border-subtle">
                      <td className="py-2 pr-3 text-fg">
                        <KeyRound className="mr-1.5 inline h-3.5 w-3.5 text-muted" aria-hidden="true" />
                        {k.name}
                        {k.revoked_at && (
                          <span className="ml-2">
                            <Badge>revoked</Badge>
                          </span>
                        )}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs text-secondary">{k.prefix}</td>
                      <td className="py-2 pr-3 text-body">{k.scopes.join(', ')}</td>
                      <td className="whitespace-nowrap py-2 pr-3 text-secondary">{k.last_used_at ? formatRelative(k.last_used_at) : 'never'}</td>
                      <td className="whitespace-nowrap py-2 pr-3 text-secondary">{formatDateTime(k.created_at)}</td>
                      <td className="py-2 text-right">
                        {!k.revoked_at && (
                          <Button size="sm" variant="destructive" onClick={() => setRevoking(k)} aria-label={`Revoke ${k.name}`}>
                            Revoke
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
      {editing !== null && <UserDialog user={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      {newKey && (
        <KeyDialog
          onClose={() => setNewKey(false)}
          onCreated={(k) => {
            setNewKey(false);
            setCreated(k);
          }}
        />
      )}
      {created && <KeyCreated created={created} onClose={() => setCreated(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        title="Delete user"
        confirmLabel="Delete user"
        danger
        busy={delUser.isPending}
        onConfirm={() => deleting && delUser.mutate(deleting)}
        onCancel={() => setDeleting(null)}
      >
        Delete <strong>{deleting?.email}</strong>? Their sessions end immediately. Consider deactivating instead to keep the account for audit context.
      </ConfirmDialog>
      <ConfirmDialog
        open={resetting !== null}
        title="Reset MFA"
        confirmLabel="Reset MFA"
        danger
        busy={resetMfa.isPending}
        onConfirm={() => resetting && resetMfa.mutate(resetting)}
        onCancel={() => setResetting(null)}
      >
        Remove two-step verification from <strong>{resetting?.email}</strong> (for a lost device)? Their sessions end now, their recovery codes stop
        working, and they sign in with their password only until they set it up again. Confirm their identity out of band first. The reset is
        recorded in the audit log.
      </ConfirmDialog>
      <ConfirmDialog
        open={revoking !== null}
        title="Revoke API key"
        confirmLabel="Revoke key"
        danger
        busy={revoke.isPending}
        onConfirm={() => revoking && revoke.mutate(revoking)}
        onCancel={() => setRevoking(null)}
      >
        Revoke <strong>{revoking?.name}</strong>? Anything using it stops working immediately.
      </ConfirmDialog>
    </>
  );
}
