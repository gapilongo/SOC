/**
 * Guided Wazuh setup, push: the Wazuh manager posts its alerts to the ingest
 * webhook of a push source, with an API key that has the ingest scope. The
 * checks cover both halves: the source, and the key the manager sends.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { afterOnboardingChange, afterSourceChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import type { GuidedCheckOut, WazuhPushIn } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { useToast } from '../../../../components/Toast';
import { Banner, Button, Card, ErrorMessage, TextField } from '../../../../components/ui';
import { SetupChecks } from './SetupChecks';

export const DEFAULT_PUSH_SOURCE_ID = 'wazuh-push';

export function WazuhPushSetup() {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [sourceId, setSourceId] = useState(DEFAULT_PUSH_SOURCE_ID);
  const [apiKey, setApiKey] = useState('');
  const [result, setResult] = useState<GuidedCheckOut | null>(null);
  const id = sourceId.trim();

  const sources = useQuery({ queryKey: qk.sources.all, queryFn: ({ signal }) => endpoints.sources(api, signal) });
  const missing = Boolean(id) && sources.data !== undefined && !sources.data.some((s) => s.id === id);

  const check = useMutation({
    mutationFn: () => {
      const push: WazuhPushIn = { source_id: id };
      if (apiKey.trim()) push.api_key = apiKey.trim();
      return endpoints.checkWazuh(api, { push });
    },
    onSuccess: setResult,
  });
  const create = useMutation({
    mutationFn: () =>
      endpoints.createSource(api, { id, type: 'webhook', name: 'Wazuh (push)', enabled: true, config: { format: 'wazuh' }, poll_interval_s: 60 }),
    onSuccess: (source) => {
      toast.success(`Push source ${source.id} created.`);
      setResult(null);
      void afterSourceChange(client);
      void afterOnboardingChange(client);
    },
  });

  const stale = () => {
    setResult(null);
    check.reset();
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    check.mutate();
  };

  return (
    <div className="space-y-5">
      <Card title="1. Push source and API key">
        <form onSubmit={submit} autoComplete="off">
          <p className="mb-4 max-w-3xl text-sm text-secondary">
            The Wazuh manager sends each alert to <span className="break-words font-mono text-xs">POST /api/v1/ingest/webhook/{id || '<source id>'}</span>{' '}
            with the key in the <span className="font-mono text-xs">X-API-Key</span> header. Create the key under{' '}
            <Link to="/users" className="text-link underline">
              Users and API keys
            </Link>{' '}
            with the <span className="font-mono text-xs">ingest</span> scope.
          </p>
          <div className="grid max-w-3xl gap-4 sm:grid-cols-2">
            <TextField
              label="Source ID"
              hint="The push source the manager posts to."
              required
              pattern="[A-Za-z0-9][A-Za-z0-9._\-]{0,127}"
              value={sourceId}
              onChange={(e) => {
                setSourceId(e.target.value);
                stale();
              }}
            />
            <TextField
              label="API key the manager sends (optional)"
              hint="Checked against this tenant's keys; never stored or shown."
              type="password"
              autoComplete="new-password"
              value={apiKey}
              onChange={(e) => {
                setApiKey(e.target.value);
                stale();
              }}
            />
          </div>
          {missing && (
            <Banner
              tone="info"
              title={`No source ${id} yet`}
              className="mt-4 max-w-3xl"
              actions={
                <Button size="sm" busy={create.isPending} onClick={() => create.mutate()}>
                  Create push source
                </Button>
              }
            >
              A webhook source that reads the Wazuh alert format.
            </Banner>
          )}
          {create.error ? (
            <div className="mt-3">
              <ErrorMessage error={create.error} compact />
            </div>
          ) : null}
          <div className="mt-5">
            <Button type="submit" variant="primary" busy={check.isPending}>
              {result ? 'Run checks again' : 'Run checks'}
            </Button>
          </div>
        </form>
      </Card>

      <Card title="2. Checks">
        {check.error ? <ErrorMessage error={check.error} compact /> : null}
        {result ? (
          <SetupChecks result={result} label="Wazuh push checks" />
        ) : (
          !check.error && (
            <p className="text-sm text-secondary">
              {check.isPending ? 'Running the checks...' : 'Not run yet. The checks read this tenant only; nothing is sent to Wazuh.'}
            </p>
          )
        )}
      </Card>
    </div>
  );
}
