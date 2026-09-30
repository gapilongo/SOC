import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, ShieldCheck, ShieldOff } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { ApiError } from '../api/client';
import { endpoints } from '../api/endpoints';
import type { MfaEnrollOut, MfaStatusOut } from '../api/types';
import { useApi, useAuth } from '../auth/AuthContext';
import { Badge } from '../components/Badge';
import { Modal } from '../components/Dialog';
import { CodeField, EnrollmentDetails, RecoveryCodes } from '../components/Mfa';
import { useToast } from '../components/Toast';
import { Button, Card, DefinitionList, ErrorMessage, LoadingState, PageHeader, TextField } from '../components/ui';
import { formatDateTime } from '../lib/format';

const STATUS_KEY = ['mfa-status'];

function friendly(err: unknown): unknown {
  if (err instanceof ApiError && err.code === 'invalid_mfa_code') {
    return new ApiError({
      status: err.status,
      code: err.code,
      message: 'That code is not valid. Each code works once; wait for the next one. Repeated failures lock the account.',
      requestId: err.requestId,
    });
  }
  return err;
}

function CodesDialog({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  const { principal } = useAuth();
  return (
    <Modal
      open
      onClose={onClose}
      title="Your recovery codes"
      description="Shown once. Store them before you close this window."
      footer={
        <Button variant="primary" onClick={onClose}>
          I have saved them
        </Button>
      }
    >
      <RecoveryCodes codes={codes} account={principal?.email} />
    </Modal>
  );
}

function EnrollCard({ onEnrolled }: { onEnrolled: (codes: string[]) => void }) {
  const api = useApi();
  const client = useQueryClient();
  const [enrollment, setEnrollment] = useState<MfaEnrollOut | null>(null);
  const [code, setCode] = useState('');
  const start = useMutation({ mutationFn: () => endpoints.mfaEnroll(api), onSuccess: setEnrollment });
  const confirm = useMutation({
    mutationFn: () => endpoints.mfaConfirm(api, code.trim()),
    onSuccess: (out) => {
      setEnrollment(null);
      setCode('');
      void client.invalidateQueries({ queryKey: STATUS_KEY });
      void client.invalidateQueries({ queryKey: ['users'] });
      onEnrolled(out.recovery_codes);
    },
    onError: () => setCode(''),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    confirm.mutate();
  };
  if (!enrollment) {
    return (
      <div className="space-y-3">
        {start.error ? <ErrorMessage error={start.error} compact /> : null}
        <Button variant="primary" busy={start.isPending} onClick={() => start.mutate()} icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />}>
          Set up authenticator app
        </Button>
      </div>
    );
  }
  return (
    <form onSubmit={submit} className="space-y-5">
      <EnrollmentDetails enrollment={enrollment} />
      {confirm.error ? <ErrorMessage error={friendly(confirm.error)} compact /> : null}
      <div className="max-w-xs">
        <CodeField value={code} onChange={setCode} />
      </div>
      <div className="flex gap-2">
        <Button type="submit" variant="primary" busy={confirm.isPending}>
          Turn on two-step verification
        </Button>
        <Button onClick={() => setEnrollment(null)}>Cancel</Button>
      </div>
    </form>
  );
}

function RegenerateDialog({ onClose, onCodes }: { onClose: () => void; onCodes: (codes: string[]) => void }) {
  const api = useApi();
  const client = useQueryClient();
  const [code, setCode] = useState('');
  const m = useMutation({
    mutationFn: () => endpoints.mfaRegenerate(api, code.trim()),
    onSuccess: (out) => {
      void client.invalidateQueries({ queryKey: STATUS_KEY });
      onCodes(out.recovery_codes);
    },
    onError: () => setCode(''),
  });
  return (
    <Modal
      open
      onClose={onClose}
      title="New recovery codes"
      description="Your current recovery codes stop working."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="regen-form" variant="primary" busy={m.isPending}>
            Generate new codes
          </Button>
        </>
      }
    >
      <form
        id="regen-form"
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        {m.error ? <ErrorMessage error={friendly(m.error)} compact /> : null}
        <CodeField value={code} onChange={setCode} />
      </form>
    </Modal>
  );
}

function DisableDialog({ status, onClose }: { status: MfaStatusOut; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const m = useMutation({
    mutationFn: () => endpoints.mfaDisable(api, password, code.trim()),
    onSuccess: () => {
      toast.success('Two-step verification is off.');
      void client.invalidateQueries({ queryKey: STATUS_KEY });
      void client.invalidateQueries({ queryKey: ['users'] });
      onClose();
    },
    onError: () => {
      setPassword('');
      setCode('');
    },
  });
  return (
    <Modal
      open
      onClose={onClose}
      title="Turn off two-step verification"
      description={
        status.required
          ? 'Your organisation requires two-step verification: you will have to set it up again at your next sign-in.'
          : 'Your account will be protected by your password only.'
      }
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="disable-form" variant="danger" busy={m.isPending}>
            Turn off
          </Button>
        </>
      }
    >
      <form
        id="disable-form"
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
        autoComplete="off"
      >
        {m.error ? <ErrorMessage error={friendly(m.error)} compact /> : null}
        <TextField label="Password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        <CodeField value={code} onChange={setCode} label="Authentication or recovery code" />
      </form>
    </Modal>
  );
}

export default function AccountSecurityPage() {
  const api = useApi();
  const { principal } = useAuth();
  const sso = principal?.method === 'oidc';
  const status = useQuery({ queryKey: STATUS_KEY, queryFn: ({ signal }) => endpoints.mfaStatus(api, signal), enabled: !sso });
  const [codes, setCodes] = useState<string[] | null>(null);
  const [regenerating, setRegenerating] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const s = status.data;

  return (
    <>
      <PageHeader title="Account security" description={principal?.email ?? undefined} />
      <div className="max-w-3xl space-y-6">
        {sso && (
          <Card title="Two-step verification">
            <p className="text-sm text-slate-300">
              You signed in through single sign-on. Two-step verification for this sign-in is managed by your identity provider.
            </p>
          </Card>
        )}
        {!sso && status.isPending && <LoadingState label="Loading account security" />}
        {!sso && status.isError && <ErrorMessage error={status.error} onRetry={() => void status.refetch()} />}
        {s && !s.available && (
          <Card title="Two-step verification">
            <p className="text-sm text-slate-300">This account has no local password; it signs in through single sign-on.</p>
          </Card>
        )}
        {s && s.available && (
          <Card
            title="Two-step verification (authenticator app)"
            actions={s.enabled ? <Badge tone="good">on</Badge> : <Badge tone={s.required ? 'bad' : 'neutral'}>off</Badge>}
          >
            <div className="space-y-4">
              {s.required && !s.enabled && (
                <p className="rounded-md border border-amber-700 bg-amber-950 px-3 py-2 text-sm text-amber-100">
                  Your organisation requires two-step verification. Set it up now; otherwise you will be asked to at your next sign-in.
                </p>
              )}
              {s.enabled ? (
                <>
                  <DefinitionList
                    items={[
                      ['Turned on', formatDateTime(s.enabled_at)],
                      ['Recovery codes left', String(s.recovery_codes_remaining ?? 0)],
                      ['Required by policy', s.required ? 'yes' : 'no'],
                    ]}
                  />
                  {(s.recovery_codes_remaining ?? 0) <= 2 && (
                    <p className="text-sm text-amber-200">You are running out of recovery codes. Generate new ones.</p>
                  )}
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => setRegenerating(true)} icon={<KeyRound className="h-4 w-4" aria-hidden="true" />}>
                      New recovery codes
                    </Button>
                    <Button variant="danger" onClick={() => setDisabling(true)} icon={<ShieldOff className="h-4 w-4" aria-hidden="true" />}>
                      Turn off
                    </Button>
                  </div>
                  <p className="text-xs text-slate-400">
                    New phone? Turn two-step verification off with a current or recovery code, then set it up again. Lost every factor? Ask an administrator to reset it.
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm text-slate-300">
                    Protect your account with a 6-digit code from an authenticator app in addition to your password.
                  </p>
                  <EnrollCard onEnrolled={setCodes} />
                </>
              )}
            </div>
          </Card>
        )}
      </div>
      {codes && <CodesDialog codes={codes} onClose={() => setCodes(null)} />}
      {regenerating && (
        <RegenerateDialog
          onClose={() => setRegenerating(false)}
          onCodes={(c) => {
            setRegenerating(false);
            setCodes(c);
          }}
        />
      )}
      {disabling && s && <DisableDialog status={s} onClose={() => setDisabling(false)} />}
    </>
  );
}
