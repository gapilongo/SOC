import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';

import type { LiveEvent } from '../api/types';
import { useAuth, useAuthStore } from '../auth/AuthContext';
import { wsEndpoint } from '../config';
import { invalidateBounded } from '../lib/pagination';
import { LiveSocket, type LiveStatus } from './socket';

interface LiveContextValue {
  status: LiveStatus;
  lastEventAt: number | null;
}

const LiveContext = createContext<LiveContextValue>({ status: 'idle', lastEventAt: null });

/** Query key prefixes each event type makes stale. */
export function keysForEvent(type: LiveEvent['type']): string[] {
  switch (type) {
    case 'alert.created':
    case 'alert.updated':
      return ['alerts', 'alert', 'dashboard'];
    case 'escalation.created':
    case 'escalation.updated':
      return ['escalations', 'dashboard'];
    case 'action.updated':
      return ['actions', 'dashboard'];
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
  const [lastEventAt, setLastEventAt] = useState<number | null>(null);
  const invalidator = useRef<ReturnType<typeof createInvalidator> | null>(null);

  useEffect(() => {
    // The socket is tenant-scoped by the token; a platform admin acting on
    // another tenant gets no live stream for it (REST polling still works).
    if (authStatus !== 'authenticated' || actingTenant) {
      setStatus('idle');
      return;
    }
    const inv = createInvalidator(client);
    invalidator.current = inv;
    const socket = new LiveSocket({
      url: wsEndpoint(),
      getToken: store.getToken,
      refreshToken: store.refresh,
      onStatus: setStatus,
      onEvent: (event) => {
        setLastEventAt(Date.now());
        inv.add(keysForEvent(event.type));
      },
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
      invalidator.current = null;
    };
  }, [authStatus, actingTenant, client, store]);

  return <LiveContext.Provider value={{ status, lastEventAt }}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveContextValue {
  return useContext(LiveContext);
}
