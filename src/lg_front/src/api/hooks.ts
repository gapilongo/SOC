/**
 * React Query hooks for the console's read models and triage mutations, so
 * pages share one query key, one fetcher and one invalidation policy per
 * resource. Lists that page use `useKeysetList` (lib/pagination.ts); the
 * overview's short lists use `useEscalationsTop` (one request, no paging).
 *
 * Polling is a fallback to the live stream: pass `refetchInterval` from
 * `useLivePollInterval`, which slows down while live events flow and stops
 * while the tab is hidden.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { useApi, useAuth } from '../auth/AuthContext';
import { useKeysetList } from '../lib/pagination';
import { usePollInterval } from '../lib/visibility';
import { useLive } from '../live/LiveProvider';
import {
  endpoints,
  type AlertCountsWindow,
  type EscalationFilters,
  type EscalationGroupFilters,
} from './endpoints';
import { afterBulkClaim, afterBulkClose, afterBulkSuppressionProposal } from './invalidate';
import { qk } from './queryKeys';
import type {
  BulkCloseIn,
  BulkItemIn,
  BulkOut,
  BulkProposeSuppressionIn,
  EscalationOut,
  SuppressionProposalOut,
} from './types';

interface PollOptions {
  /** Poll interval in ms, or false (default) for none. */
  refetchInterval?: number | false;
  enabled?: boolean;
}

/** Poll every `liveMs` while the live stream is open, every `fallbackMs` otherwise; paused while the tab is hidden. */
export function useLivePollInterval(liveMs = 60_000, fallbackMs = 20_000): number | false {
  const { status } = useLive();
  return usePollInterval(status === 'open' ? liveMs : fallbackMs);
}

/** GET /auth/me for the tenant the caller acts on (cached five minutes). */
export function useMe() {
  const api = useApi();
  const { principal } = useAuth();
  const tenantId = principal?.tenantId ?? '';
  return useQuery({
    queryKey: qk.me.forTenant(tenantId),
    queryFn: ({ signal }) => endpoints.me(api, signal),
    enabled: Boolean(tenantId),
    staleTime: 5 * 60_000,
  });
}

/** GET /dashboard/summary over the last `windowHours` (the queue figures are always "now"). */
export function useDashboardSummary(windowHours: number, opts: PollOptions = {}) {
  const api = useApi();
  return useQuery({
    queryKey: qk.dashboard.summary(windowHours),
    queryFn: ({ signal }) => endpoints.dashboard(api, windowHours, signal),
    refetchInterval: opts.refetchInterval ?? false,
    refetchIntervalInBackground: false,
    enabled: opts.enabled ?? true,
  });
}

/** GET /alerts/counts: alerts per status (all-time, `closed` within the window). */
export function useAlertCounts(window: AlertCountsWindow = {}, opts: PollOptions = {}) {
  const api = useApi();
  return useQuery({
    queryKey: qk.alerts.counts(window),
    queryFn: ({ signal }) => endpoints.alertCounts(api, window, signal),
    refetchInterval: opts.refetchInterval ?? false,
    refetchIntervalInBackground: false,
    enabled: opts.enabled ?? true,
  });
}

/** The escalation queue, keyset-paged ("Load more", bounded refetch). */
export function useEscalationList(filters: EscalationFilters, opts: PollOptions = {}) {
  const api = useApi();
  return useKeysetList<EscalationOut>({
    queryKey: qk.escalations.list(filters),
    fetchPage: (cursor, signal) => endpoints.escalations(api, filters, cursor, signal),
    itemKey: (e) => e.id,
    enabled: opts.enabled,
    refetchInterval: opts.refetchInterval,
  });
}

/**
 * The first `limit` escalations matching `filters` (one request). `hasMore`
 * says more rows matched than were returned.
 */
export function useEscalationsTop(filters: EscalationFilters, limit: number, opts: PollOptions = {}) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.escalations.top(filters, limit),
    queryFn: ({ signal }) => endpoints.escalations(api, filters, undefined, signal, limit),
    refetchInterval: opts.refetchInterval ?? false,
    refetchIntervalInBackground: false,
    enabled: opts.enabled ?? true,
  });
  return { ...q, items: q.data?.items ?? [], hasMore: Boolean(q.data?.next_cursor) };
}

/** One escalation (the decision page); disabled without an id. */
export function useEscalation(id: string | null | undefined, opts: PollOptions = {}) {
  const api = useApi();
  return useQuery({
    queryKey: qk.escalation.detail(id ?? ''),
    queryFn: ({ signal }) => endpoints.escalation(api, id as string, signal),
    enabled: Boolean(id) && (opts.enabled ?? true),
    refetchInterval: opts.refetchInterval ?? false,
    refetchIntervalInBackground: false,
  });
}

/** GET /escalations/groups: active escalations grouped by source and rule, largest first. */
export function useEscalationGroups(filters: EscalationGroupFilters = {}, opts: PollOptions = {}) {
  const api = useApi();
  return useQuery({
    queryKey: qk.escalations.groups(filters),
    queryFn: ({ signal }) => endpoints.escalationGroups(api, filters, signal),
    refetchInterval: opts.refetchInterval ?? false,
    refetchIntervalInBackground: false,
    enabled: opts.enabled ?? true,
  });
}

/**
 * The response plan a true-positive decision would produce for this
 * escalation (a dry run: it writes nothing and calls no connector).
 */
export function useResponsePreview(escalationId: string | null | undefined, opts: { enabled?: boolean } = {}) {
  const api = useApi();
  return useQuery({
    queryKey: qk.escalation.responsePreview(escalationId ?? ''),
    queryFn: ({ signal }) => endpoints.responsePreview(api, escalationId as string, signal),
    enabled: Boolean(escalationId) && (opts.enabled ?? true),
    // The plan follows the tenant's policy and connectors; keep it briefly, re-read on return.
    staleTime: 30_000,
  });
}

/**
 * Claim several escalations (at most BULK_MAX_ITEMS). The request answers 200
 * with per-item results (`ok`, `error`), so check `failed`; the lists and the
 * overview are refreshed whatever the outcome, because items commit one by one.
 */
export function useBulkClaim() {
  const api = useApi();
  const client = useQueryClient();
  return useMutation<BulkOut, unknown, BulkItemIn[]>({
    mutationFn: (items) => endpoints.bulkClaim(api, { items }),
    onSettled: () => afterBulkClaim(client),
  });
}

/** Close several escalations as false or benign positive (notes required); per-item results as for a claim. */
export function useBulkClose() {
  const api = useApi();
  const client = useQueryClient();
  return useMutation<BulkOut, unknown, BulkCloseIn>({
    mutationFn: (body) => endpoints.bulkClose(api, body),
    onSettled: (_out, _err, body) => afterBulkClose(client, Boolean(body.propose_suppression)),
  });
}

/**
 * Propose one disabled suppression rule from escalations decided false or
 * benign positive (all or nothing: 422 `not_confirmed_benign` lists the others).
 */
export function useBulkProposeSuppression() {
  const api = useApi();
  const client = useQueryClient();
  return useMutation<SuppressionProposalOut, unknown, BulkProposeSuppressionIn>({
    mutationFn: (body) => endpoints.bulkProposeSuppression(api, body),
    onSuccess: () => afterBulkSuppressionProposal(client),
  });
}
