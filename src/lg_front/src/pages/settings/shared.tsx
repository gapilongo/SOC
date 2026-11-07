/** Building blocks shared by the tenant settings sections: the save mutation and the section form. */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { FormEvent, ReactNode } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterTenantSettingsChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import type { JsonObject } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { useToast } from '../../components/Toast';
import { Button, Card, ErrorMessage } from '../../components/ui';

export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

export function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter(Boolean);
}

export function useSave(onDone?: () => void) {
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

export function Section({ title, description, children, onSubmit, busy, error, saveLabel }: { title: string; description: ReactNode; children: ReactNode; onSubmit: () => void; busy: boolean; error: unknown; saveLabel?: string }) {
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
