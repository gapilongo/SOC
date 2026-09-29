import { createContext, useContext, useSyncExternalStore, type ReactNode } from 'react';

import type { ApiClient } from '../api/client';
import type { Session } from './session';
import type { AuthState, AuthStore } from './store';

const SessionContext = createContext<Session | null>(null);

export function SessionProvider({ session, children }: { session: Session; children: ReactNode }) {
  return <SessionContext.Provider value={session}>{children}</SessionContext.Provider>;
}

function useSession(): Session {
  const session = useContext(SessionContext);
  if (!session) throw new Error('SessionProvider is missing');
  return session;
}

export function useApi(): ApiClient {
  return useSession().api;
}

export function useAuthStore(): AuthStore {
  return useSession().auth;
}

export function useAuth(): AuthState {
  const store = useSession().auth;
  return useSyncExternalStore(store.subscribe, store.getState, store.getState);
}
