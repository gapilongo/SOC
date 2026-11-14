/**
 * Guided Wazuh setup (tenant admins): enter where the Wazuh indexer is and a
 * read-only user, run the checks, fix what the failed check names, and save
 * the source once every check passes. The second way in, the Wazuh manager
 * pushing alerts to the ingest webhook, is checked the same way
 * (WazuhPushSetup). Credentials stay in this form until the source is saved
 * and are cleared from it afterwards.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type ChangeEvent, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { afterOnboardingChange, afterSourceChange } from '../../api/invalidate';
import type { GuidedCheckOut, JsonObject, SourceCreateIn } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { useToast } from '../../components/Toast';
import { Button, Card, ErrorMessage, PageHeader, Segmented, TextAreaField, TextField, buttonClass } from '../../components/ui';
import { SetupChecks } from './SetupChecks';
import { WazuhPushSetup } from './WazuhPushSetup';

export const DEFAULT_INDEX = 'wazuh-alerts-*';

type Mode = 'pull' | 'push';

const MODES = [
  { value: 'pull', label: 'Read the indexer' },
  { value: 'push', label: 'Push from the manager' },
] as const;

export interface PullForm {
  baseUrl: string;
  index: string;
  username: string;
  password: string;
  caPem: string;
}

/** The source config the form describes; defaults are left out, as a source saved by hand would. */
export function pullConfig(form: PullForm): JsonObject {
  const config: JsonObject = { base_url: form.baseUrl.trim() };
  const index = form.index.trim();
  if (index && index !== DEFAULT_INDEX) config.index = index;
  if (form.caPem.trim()) config.ca_cert_pem = form.caPem.trim();
  return config;
}

function PullSetup() {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [form, setForm] = useState<PullForm>({ baseUrl: '', index: DEFAULT_INDEX, username: '', password: '', caPem: '' });
  const [name, setName] = useState('Wazuh');
  const [result, setResult] = useState<GuidedCheckOut | null>(null);

  const secret = () => ({ username: form.username.trim(), password: form.password });
  const check = useMutation({
    mutationFn: () => endpoints.checkWazuh(api, { pull: { config: pullConfig(form), secret: secret() } }),
    onSuccess: setResult,
  });
  const save = useMutation({
    mutationFn: () => {
      const body: SourceCreateIn = { type: 'wazuh', name: name.trim(), enabled: true, config: pullConfig(form), secret: secret(), poll_interval_s: 60 };
      return endpoints.createSource(api, body);
    },
    onSuccess: (source) => {
      // Clear the credentials from component state as soon as they have been sent.
      setForm((f) => ({ ...f, password: '' }));
      toast.success(`Source ${source.name} saved; the first poll starts within a minute.`);
      void afterSourceChange(client);
      void afterOnboardingChange(client);
      navigate('/sources');
    },
  });

  // A result describes the values it was run with: any edit makes it stale, so it is dropped.
  const edit = (key: keyof PullForm) => (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setForm({ ...form, [key]: e.target.value });
    setResult(null);
    check.reset();
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    check.mutate();
  };

  return (
    <div className="space-y-5">
      <Card title="1. Indexer and read-only user">
        <form onSubmit={submit} autoComplete="off">
          <p className="mb-4 max-w-3xl text-sm text-secondary">
            Alerts are read from the Wazuh indexer, never from the manager. Use an indexer user that can only read: a role
            with the index permission <span className="font-mono text-xs">read</span> on{' '}
            <span className="font-mono text-xs">{DEFAULT_INDEX}</span>.
          </p>
          <div className="grid max-w-3xl gap-4 sm:grid-cols-2">
            <TextField
              label="Indexer URL"
              hint="The indexer's REST API, port 9200 by default."
              placeholder="https://wazuh-indexer.example.com:9200"
              type="url"
              required
              value={form.baseUrl}
              onChange={edit('baseUrl')}
            />
            <TextField label="Index pattern" hint="Where Wazuh stores alerts." required value={form.index} onChange={edit('index')} />
            <TextField label="User name" required autoComplete="off" value={form.username} onChange={edit('username')} />
            <TextField label="Password" type="password" required autoComplete="new-password" value={form.password} onChange={edit('password')} />
            <TextAreaField
              wrapperClassName="sm:col-span-2"
              label="CA certificate (optional)"
              hint="PEM text of the root CA that signed the indexer certificate (root-ca.pem). Leave empty when a public CA signed it."
              rows={4}
              spellCheck={false}
              value={form.caPem}
              onChange={edit('caPem')}
            />
          </div>
          <div className="mt-5">
            <Button type="submit" variant={result?.ok ? 'secondary' : 'primary'} busy={check.isPending}>
              {result ? 'Run checks again' : 'Run checks'}
            </Button>
          </div>
        </form>
      </Card>

      <Card title="2. Checks">
        {check.error ? <ErrorMessage error={check.error} compact /> : null}
        {result ? (
          <SetupChecks result={result} label="Wazuh indexer checks" />
        ) : (
          !check.error && (
            <p className="text-sm text-secondary">
              {check.isPending
                ? 'Running the checks...'
                : 'Not run yet. The checks send one read-only search to the indexer; nothing is saved.'}
            </p>
          )
        )}
      </Card>

      <Card title="3. Save the source">
        {result?.ok ? (
          <div className="max-w-xl space-y-4">
            <TextField label="Source name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
            {save.error ? <ErrorMessage error={save.error} compact /> : null}
            <Button variant="primary" busy={save.isPending} disabled={!name.trim()} onClick={() => save.mutate()}>
              Save source
            </Button>
          </div>
        ) : (
          <p className="text-sm text-secondary">Available once every check passes.</p>
        )}
      </Card>
    </div>
  );
}

export default function WazuhSetupPage() {
  const [mode, setMode] = useState<Mode>('pull');
  return (
    <>
      <PageHeader
        title="Connect Wazuh"
        description="Check the connection step by step before anything is saved. A failed check names what to change: the certificate, the permission, the index."
        actions={
          <Link to="/sources" className={buttonClass('secondary', 'sm')}>
            All sources
          </Link>
        }
      />
      <Segmented label="How alerts arrive" options={MODES} value={mode} onChange={setMode} className="mb-5" />
      {mode === 'pull' ? <PullSetup /> : <WazuhPushSetup />}
    </>
  );
}
