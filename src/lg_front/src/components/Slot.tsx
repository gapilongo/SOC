/**
 * Rendering of extension points (core/slots.ts, ADR 0015).
 *
 * The shell provides every registered module's contributions once
 * (`ExtensionsProvider`); the owner of a slot renders `SlotOutlet` where the
 * contributions go. Each contribution is lazy and has its own error
 * boundary, so a module's widget that fails to load or crashes renders
 * nothing and leaves its host working.
 */

import { createContext, Suspense, useContext, useMemo, type ReactNode } from 'react';

import { useAuth } from '../auth/AuthContext';
import type { Contribution, Slot } from '../core/slots';
import { ErrorBoundary } from './ErrorBoundary';

const ExtensionsContext = createContext<readonly Contribution[]>([]);

export function ExtensionsProvider({ contributions, children }: { contributions: readonly Contribution[]; children: ReactNode }) {
  return <ExtensionsContext.Provider value={contributions}>{children}</ExtensionsContext.Provider>;
}

/** The contributions to `slot` that apply to the signed-in principal, in registration order. */
export function useContributions<P extends object>(slot: Slot<P>): ReadonlyArray<Contribution<P>> {
  const all = useContext(ExtensionsContext);
  const { principal } = useAuth();
  return useMemo(
    () => all.filter((c) => c.slot.id === slot.id && (c.when?.(principal) ?? true)) as unknown as Contribution<P>[],
    [all, slot.id, principal],
  );
}

const renderNothing = () => null;

/**
 * Where a slot's contributions render. `props` is what the owner passes to
 * each of them; `empty` is shown when nothing is contributed for this
 * principal, `pending` while a contribution's code loads.
 */
export function SlotOutlet<P extends object>({
  slot,
  props,
  empty = null,
  pending = null,
}: {
  slot: Slot<P>;
  props: P;
  empty?: ReactNode;
  pending?: ReactNode;
}) {
  const contributions = useContributions(slot);
  if (contributions.length === 0) return <>{empty}</>;
  return (
    <>
      {contributions.map(({ Component }, i) => (
        <ErrorBoundary key={i} fallback={renderNothing}>
          <Suspense fallback={pending}>
            <Component {...props} />
          </Suspense>
        </ErrorBoundary>
      ))}
    </>
  );
}
