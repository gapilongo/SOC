import { hashKey, useQueryClient, type QueryClient, type QueryKey } from '@tanstack/react-query';
import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';

import type { LiveEvent } from '../api/types';
import { useAuth, useAuthStore } from '../auth/AuthContext';
import { wsEndpoint } from '../config';
import { invalidateBounded } from '../lib/pagination';
import { LiveSocket, type LiveStatus } from './socket';

export type LiveListener = (event: LiveEvent) => void;

export interface LiveContextValue {
  status: LiveStatus;
  /** Hear every live event (after its invalidation is queued); returns the unsubscribe. */
  subscribe: (listener: LiveListener) => () => void;
}

/** Exported for tests, which provide their own event source. */
export const LiveContext = createContext<LiveContextValue>({ status: 'idle', subscribe: () => () => undefined });

/**
 * Fan-out of live events to the components that listen (the alert list's
 * "N new" pill). A listener that throws does not stop the others.
 */
export function createLiveBus() {
  const listeners = new Set<LiveListener>();
  return {
    subscribe(listener: LiveListener): () => void {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    emit(event: LiveEvent): void {
      for (const listener of [...listeners]) {
        try {
          listener(event);
        } catch (err) {
          console.error('live event listener failed', err);
        }
      }
    },
  };
}

/**
 * The query keys (group prefixes) a live event type makes stale; empty for a
 * type no module listens to. The shell passes the registered modules' mapping
 * (each module's manifest lists its own keys per event type). An event whose
 * type maps to no key is dropped at the socket. Pass a stable function: the
 * provider reconnects when it changes.
 */
export type LiveKeys = (eventType: string) => readonly QueryKey[];

/**
 * Coalesces invalidations: each query key prefix is refreshed at most once
 * per `windowMs`, so an alert storm does not turn into a request storm. Lists
 * holding several pages are only marked stale (one request per list at most;
 * see `invalidateBounded`).
 */
export function createInvalidator(client: QueryClient, windowMs = 2_000) {
  const pending = new Map<string, QueryKey>();
  let timer: ReturnType<typeof setTimeout> | null = null;
  const flush = () => {
    timer = null;
    const keys = [...pending.values()];
    pending.clear();
    for (const key of keys) void invalidateBounded(client, key);
  };
  return {
    add(keys: readonly QueryKey[]) {
      for (const k of keys) pending.set(hashKey(k), k);
      if (!timer && pending.size) timer = setTimeout(flush, windowMs);
    },
    cancel() {
      if (timer) clearTimeout(timer);
      timer = null;
      pending.clear();
    },
  };
}

export function LiveProvider({ keysFor, children }: { keysFor: LiveKeys; children: ReactNode }) {
  const { status: authStatus, actingTenant } = useAuth();
  const store = useAuthStore();
  const client = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>('idle');
  const [bus] = useState(createLiveBus);

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
      // Only the event types a module listens to are handed on.
      isEvent: (type) => keysFor(type).length > 0,
      onEvent: (event) => {
        inv.add(keysFor(event.type));
        bus.emit(event);
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
    };
  }, [authStatus, actingTenant, client, store, bus, keysFor]);

  // Stable while the status holds, so consumers do not re-render per event.
  const value = useMemo(() => ({ status, subscribe: bus.subscribe }), [status, bus]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveContextValue {
  return useContext(LiveContext);
}

/** Call `handler` for every live event while mounted (the latest handler, without resubscribing). */
export function useLiveEvents(handler: LiveListener): void {
  const { subscribe } = useLive();
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => subscribe((event) => ref.current(event)), [subscribe]);
}
