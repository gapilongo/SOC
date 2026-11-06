import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { qk } from '../api/queryKeys';
import type { LiveEvent } from '../api/types';
import { useAuth, useAuthStore } from '../auth/AuthContext';
import { wsEndpoint } from '../config';
import { invalidateBounded } from '../lib/pagination';
import { LiveSocket, type LiveStatus } from './socket';

interface LiveContextValue {
  status: LiveStatus;
}

const LiveContext = createContext<LiveContextValue>({ status: 'idle' });

/** Query key prefixes (first key elements, see api/queryKeys.ts) each event type makes stale. */
export function keysForEvent(type: LiveEvent['type']): string[] {
  switch (type) {
    case 'alert.created':
    case 'alert.updated':
      return [qk.alerts.all[0], qk.alert.all[0], qk.dashboard.all[0]];
    case 'escalation.created':
    case 'escalation.updated':
      return [qk.escalations.all[0], qk.escalation.all[0], qk.dashboard.all[0]];
    case 'action.updated':
      return [qk.actions.all[0], qk.dashboard.all[0]];
    default:
      return [];
  }
}

/**
 * Coalesces invalidations: each query prefix is refreshed at most once per
 * `windowMs`, so an alert storm does not turn into a request storm. Lists
 * holding several pages are only marked stale (one request per list at most;
 * see `invalidateBounded`).
 */
export function createInvalidator(client: QueryClient, windowMs = 2_000) {
  const pending = new Set<string>();
  let timer: ReturnType<typeof setTimeout> | null = null;
  const flush = () => {
    timer = null;
    const keys = [...pending];
    pending.clear();
    for (const key of keys) void invalidateBounded(client, [key]);
  };
  return {
    add(keys: string[]) {
      for (const k of keys) pending.add(k);
      if (!timer && pending.size) timer = setTimeout(flush, windowMs);
    },
    cancel() {
      if (timer) clearTimeout(timer);
      timer = null;
      pending.clear();
    },
  };
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const { status: authStatus, actingTenant } = useAuth();
  const store = useAuthStore();
  const client = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>('idle');

  useEffect(() => {
    // The socket is tenant-scoped by the token; a platform admin acting on
    // another tenant gets no live stream for it (REST polling still works).
    if (authStatus !== 'authenticated' || actingTenant) {
      setStatus('idle');
      return;
    }
    const inv = createInvalidator(client);
    const socket = new LiveSocket({
      url: wsEndpoint(),
      getToken: store.getToken,
      refreshToken: store.refresh,
      onStatus: setStatus,
      onEvent: (event) => inv.add(keysForEvent(event.type)),
      onResync: () => {
        // Events may have been missed while disconnected: re-read everything visible.
        void invalidateBounded(client);
      },
    });
    socket.start();
    const onOnline = () => socket.reconnectNow();
    window.addEventListener('online', onOnline);
    return () => {
      window.removeEventListener('online', onOnline);
      socket.stop();
      inv.cancel();
    };
  }, [authStatus, actingTenant, client, store]);

  // Stable while the status holds, so consumers do not re-render per event.
  const value = useMemo(() => ({ status }), [status]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveContextValue {
  return useContext(LiveContext);
}
