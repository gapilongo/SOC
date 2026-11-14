import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';

import { SessionProvider } from '../../../auth/AuthContext';
import type { Session } from '../../../auth/session';
import { fakeApi, signedInSession } from '../../../test/helpers';
import {
  useAlertCounts,
  useBulkClaim,
  useBulkClose,
  useBulkProposeSuppression,
  useDashboardSummary,
  useEscalation,
  useEscalationGroups,
  useEscalationList,
  useEscalationsTop,
  useLivePollInterval,
  useMe,
  useResponsePreview,
} from './hooks';
import { qk } from './queryKeys';

const NOW = '2026-11-06T12:00:00Z';

function escalation(id: string) {
  return { id, tenant_id: 'acme', alert_id: `a-${id}`, level: 'L1', status: 'open', reason: 'r', priority: 1, version: 1, created_at: NOW, updated_at: NOW };
}

async function setup(handler: (method: string, path: string, body?: unknown) => unknown) {
  const { api, calls } = fakeApi(handler);
  const session: Session = await signedInSession(api, { role: 'analyst' });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <SessionProvider session={session}>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </SessionProvider>
  );
  return { calls, client, wrapper };
}

describe('read hooks', () => {
  it('fetch the caller, the dashboard and the alert counts with their parameters', async () => {
    const { calls, wrapper } = await setup((_m, path) => {
      if (path === '/auth/me') return { kind: 'user', tenant_id: 'acme', home_tenant_id: 'acme', auth_method: 'password', tenant_name: 'Acme Corp' };
      if (path === '/dashboard/summary') return { window_hours: 168 };
      if (path === '/alerts/counts') return { by_status: { new: 2 }, closed_from: NOW, generated_at: NOW };
      throw new Error(path);
    });
    const { result } = renderHook(
      () => ({ me: useMe(), dash: useDashboardSummary(168), counts: useAlertCounts({ closed_from: NOW }), poll: useLivePollInterval(5, 7) }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.counts.data?.by_status.new).toBe(2));
    await waitFor(() => expect(result.current.me.data?.tenant_name).toBe('Acme Corp'));
    expect(result.current.dash.data?.window_hours).toBe(168);
    // Outside a LiveProvider the stream is idle: the fallback interval applies.
    expect(result.current.poll).toBe(7);
    expect(calls.find((c) => c.path === '/dashboard/summary')?.query).toEqual({ window_hours: 168 });
    expect(calls.find((c) => c.path === '/alerts/counts')?.query).toEqual({ closed_from: NOW });
  });

  it('list escalations: a keyset list, a short list and the groups', async () => {
    const { calls, wrapper } = await setup((_m, path) => {
      if (path === '/escalations') return { items: [escalation('e-1'), escalation('e-2')], next_cursor: 'c-2' };
      if (path === '/escalations/groups') return { items: [], truncated: false, generated_at: NOW };
      throw new Error(path);
    });
    const { result } = renderHook(
      () => ({
        list: useEscalationList({ assigned_to: 'none', order: 'sla_deadline' }),
        top: useEscalationsTop({ assigned_to: 'me', order: 'sla_deadline' }, 2),
        groups: useEscalationGroups({ min_size: 3 }),
      }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.list.items).toHaveLength(2));
    await waitFor(() => expect(result.current.top.items.map((e) => e.id)).toEqual(['e-1', 'e-2']));
    expect(result.current.top.hasMore).toBe(true);
    await waitFor(() => expect(result.current.groups.data?.truncated).toBe(false));
    const queries = calls.filter((c) => c.path === '/escalations').map((c) => c.query);
    expect(queries).toContainEqual({ assigned_to: 'none', order: 'sla_deadline', cursor: undefined, limit: 100 });
    expect(queries).toContainEqual({ assigned_to: 'me', order: 'sla_deadline', cursor: undefined, limit: 2 });
    expect(calls.find((c) => c.path === '/escalations/groups')?.query).toEqual({ min_size: 3 });
  });

  it('read one escalation and its response preview, and wait for an id', async () => {
    const { calls, wrapper } = await setup((_m, path) => {
      if (path === '/escalations/e-1') return escalation('e-1');
      if (path === '/escalations/e-1/response-preview') return { escalation_id: 'e-1', actions: [] };
      throw new Error(path);
    });
    const { result, rerender } = renderHook(({ id }: { id: string | null }) => ({ e: useEscalation(id), p: useResponsePreview(id) }), {
      wrapper,
      initialProps: { id: null as string | null },
    });
    expect(result.current.e.fetchStatus).toBe('idle');
    expect(calls).toHaveLength(0);
    rerender({ id: 'e-1' });
    await waitFor(() => expect(result.current.p.data?.escalation_id).toBe('e-1'));
    expect(result.current.e.data?.id).toBe('e-1');
  });
});

describe('bulk mutations', () => {
  it('claim and close post per-item bodies and refresh the queue, alerts and the overview', async () => {
    const { calls, client, wrapper } = await setup((method, path) => {
      if (method === 'POST' && path === '/escalations/bulk/claim') return { results: [], succeeded: 1, failed: 0 };
      if (method === 'POST' && path === '/escalations/bulk/close') return { results: [], succeeded: 1, failed: 0, suppression_created: true };
      throw new Error(path);
    });
    const spy = vi.spyOn(client, 'invalidateQueries');
    const { result } = renderHook(() => ({ claim: useBulkClaim(), close: useBulkClose() }), { wrapper });
    await act(() => result.current.claim.mutateAsync([{ escalation_id: 'e-1', version: 2 }]));
    expect(calls.at(-1)?.body).toEqual({ items: [{ escalation_id: 'e-1', version: 2 }] });
    // The group each invalidated key names (after the module id).
    const invalidated = () => spy.mock.calls.map(([f]) => (f as { queryKey: unknown[] }).queryKey[1]);
    expect(invalidated()).toEqual(['escalations', 'escalation', 'alerts', 'dashboard']);

    spy.mockClear();
    await act(() =>
      result.current.close.mutateAsync({ items: [{ escalation_id: 'e-1', version: 3 }], notes: 'Known scanner', decision: 'benign_positive', propose_suppression: true }),
    );
    expect(calls.at(-1)?.path).toBe('/escalations/bulk/close');
    expect(invalidated()).toEqual(['escalations', 'escalation', 'alerts', 'alert', 'dashboard', 'suppressions']);
  });

  it('refreshes after a failed bulk request too (items commit one by one)', async () => {
    const { client, wrapper } = await setup(() => {
      throw new Error('network');
    });
    const spy = vi.spyOn(client, 'invalidateQueries');
    const { result } = renderHook(() => useBulkClose(), { wrapper });
    await act(async () => {
      await expect(result.current.mutateAsync({ items: [{ escalation_id: 'e-1', version: 1 }], notes: 'n' })).rejects.toThrow('network');
    });
    expect(spy.mock.calls.map(([f]) => (f as { queryKey: unknown[] }).queryKey)).toContainEqual(qk.dashboard.all);
  });

  it('proposes a suppression and refreshes the rules', async () => {
    const { calls, client, wrapper } = await setup(() => ({ created: true, escalation_ids: ['e-1'], suppression: { id: 's-1' } }));
    const spy = vi.spyOn(client, 'invalidateQueries');
    const { result } = renderHook(() => useBulkProposeSuppression(), { wrapper });
    const out = await act(() => result.current.mutateAsync({ escalation_ids: ['e-1'], name: 'Scanner' }));
    expect(out.created).toBe(true);
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/escalations/bulk/propose-suppression', body: { escalation_ids: ['e-1'], name: 'Scanner' } });
    expect(spy.mock.calls.map(([f]) => (f as { queryKey: unknown[] }).queryKey)).toEqual([qk.suppressions.all]);
  });
});
