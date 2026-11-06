/**
 * Table row density: compact by default, "Comfortable" on request. A display
 * preference (lib/prefs.ts) exposed as `<html data-density>`: index.css pads
 * table cells from it, and VirtualTable reads it for its row height.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { readPref, writePref } from '../lib/prefs';

export type Density = 'compact' | 'comfortable';

export function parseDensity(value: string | null | undefined): Density {
  return value === 'comfortable' ? 'comfortable' : 'compact';
}

/** Row height of the windowed tables (px). */
export const ROW_HEIGHT: Record<Density, number> = { compact: 44, comfortable: 56 };

interface DensityApi {
  density: Density;
  setDensity: (density: Density) => void;
}

// Without a provider (isolated component tests) tables stay compact.
const DensityContext = createContext<DensityApi>({ density: 'compact', setDensity: () => undefined });

export function DensityProvider({ children }: { children: ReactNode }) {
  const [density, setDensityState] = useState<Density>(() => parseDensity(readPref('density')));

  useEffect(() => {
    document.documentElement.dataset.density = density;
  }, [density]);

  const setDensity = useCallback((next: Density) => {
    setDensityState(next);
    writePref('density', next);
  }, []);

  const api = useMemo(() => ({ density, setDensity }), [density, setDensity]);
  return <DensityContext.Provider value={api}>{children}</DensityContext.Provider>;
}

export function useDensity(): DensityApi {
  return useContext(DensityContext);
}
