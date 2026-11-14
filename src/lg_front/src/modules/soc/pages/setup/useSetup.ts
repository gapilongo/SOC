/**
 * First-run setup state (`/onboarding/setup`): the install's platform admin,
 * in their home tenant. Everyone else never asks (the API would refuse).
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { endpoints } from '../../api/endpoints';
import { afterSetupSaved } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import type { LlmResidency, SetupIn, SetupOut } from '../../api/types';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';

export function useSetup(enabled = true) {
  const api = useApi();
  const { principal } = useAuth();
  return useQuery({
    queryKey: qk.setup.all,
    queryFn: ({ signal }) => endpoints.setup(api, signal),
    enabled: enabled && can.setup(principal),
    staleTime: 30_000,
  });
}

export function useSaveSetup() {
  const api = useApi();
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: SetupIn) => endpoints.saveSetup(api, body),
    onSuccess: (out: SetupOut) => {
      client.setQueryData(qk.setup.all, out);
      void afterSetupSaved(client);
    },
  });
}

export function useCompleteSetup() {
  const api = useApi();
  const client = useQueryClient();
  return useMutation({
    mutationFn: (skipped: boolean) => endpoints.completeSetup(api, skipped),
    onSuccess: (out: SetupOut) => client.setQueryData(qk.setup.all, out),
  });
}

/** Where the model runs, as an admin reads it; `flag` marks what should not run in an EU SOC by default. */
export const RESIDENCY_TEXT: Record<LlmResidency, { label: string; flag: boolean }> = {
  eu: { label: 'Hosted in the EU', flag: false },
  local: { label: 'Runs on your own servers', flag: false },
  us: { label: 'Hosted outside the EU', flag: true },
  cn: { label: 'Hosted in China', flag: true },
  offline: { label: 'Offline demo model, no real analysis', flag: true },
  unknown: { label: 'Hosting region unknown', flag: true },
};

export function residencyText(residency: string): { label: string; flag: boolean } {
  return RESIDENCY_TEXT[residency as LlmResidency] ?? RESIDENCY_TEXT.unknown;
}
