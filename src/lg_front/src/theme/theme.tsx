/**
 * Colour theme: dark (default), light, or "system" (follows the operating
 * system's prefers-color-scheme and its changes). The choice is a display
 * preference kept in localStorage (lib/prefs.ts); the resolved theme is set
 * as `<html data-theme>`, which switches the token values in tokens.css.
 *
 * public/theme-boot.js applies the stored choice before the first paint, so a
 * light-theme user does not see a dark flash; this module owns it afterwards.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { readPref, writePref } from '../lib/prefs';

export const THEME_PREFERENCES = ['dark', 'light', 'system'] as const;
export type ThemePreference = (typeof THEME_PREFERENCES)[number];
export type ResolvedTheme = 'dark' | 'light';

const LIGHT_QUERY = '(prefers-color-scheme: light)';

export function parseThemePreference(value: string | null | undefined): ThemePreference {
  return (THEME_PREFERENCES as readonly string[]).includes(value ?? '') ? (value as ThemePreference) : 'dark';
}

export function resolveTheme(preference: ThemePreference, systemPrefersLight: boolean): ResolvedTheme {
  if (preference === 'system') return systemPrefersLight ? 'light' : 'dark';
  return preference;
}

function lightMedia(): MediaQueryList | null {
  return typeof window.matchMedia === 'function' ? window.matchMedia(LIGHT_QUERY) : null;
}

export function applyTheme(theme: ResolvedTheme, root: HTMLElement = document.documentElement): void {
  root.dataset.theme = theme;
}

interface ThemeApi {
  preference: ThemePreference;
  resolved: ResolvedTheme;
  setPreference: (preference: ThemePreference) => void;
}

const ThemeContext = createContext<ThemeApi | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(() => parseThemePreference(readPref('theme')));
  const [systemLight, setSystemLight] = useState(() => lightMedia()?.matches ?? false);

  useEffect(() => {
    const media = lightMedia();
    if (!media) return;
    const onChange = (e: MediaQueryListEvent) => setSystemLight(e.matches);
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  const resolved = resolveTheme(preference, systemLight);
  useEffect(() => applyTheme(resolved), [resolved]);

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next);
    writePref('theme', next);
  }, []);

  const api = useMemo(() => ({ preference, resolved, setPreference }), [preference, resolved, setPreference]);
  return <ThemeContext.Provider value={api}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeApi {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme outside ThemeProvider');
  return ctx;
}
