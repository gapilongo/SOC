/**
 * Table row density: compact by default (28 px, one line), "Comfortable" on
 * request (44 px, two lines); a dense list (24 px) is the third step of the
 * design. A display preference (lib/prefs.ts) exposed as `<html data-density>`:
 * tokens.css sets `--row-h` and the cell padding from it, and VirtualTable
 * reads the same heights from ROW_HEIGHT (tokens.test.ts keeps them in step).
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { readPref, writePref } from '../lib/prefs';

export const DENSITIES = ['dense', 'compact', 'comfortable'] as const;
export type Density = (typeof DENSITIES)[number];

export function parseDensity(value: string | null | undefined): Density {
  return (DENSITIES as readonly string[]).includes(value ?? '') ? (value as Density) : 'compact';
}

/** Row height of the windowed tables (px): the `--row-h-*` tokens. */
export const ROW_HEIGHT: Record<Density, number> = { dense: 24, compact: 28, comfortable: 44 };

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
