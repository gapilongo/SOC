/**
 * Colour theme: "system" (the default: follows the operating system's
 * prefers-color-scheme and its changes), light or dark. The choice is a
 * display preference kept in localStorage (lib/prefs.ts) and remembered; the
 * resolved theme is set as `<html data-theme>`, which switches the token
 * values in tokens.css.
 *
 * public/theme-boot.js applies the stored choice before the first paint, so
 * nobody sees a flash of the other theme; this module owns it afterwards.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { readPref, writePref } from '../lib/prefs';

export const THEME_PREFERENCES = ['system', 'light', 'dark'] as const;
export type ThemePreference = (typeof THEME_PREFERENCES)[number];
export type ResolvedTheme = 'dark' | 'light';

// Light unless the system asks for dark: the same rule as tokens.css and public/theme-boot.js.
const DARK_QUERY = '(prefers-color-scheme: dark)';

export function parseThemePreference(value: string | null | undefined): ThemePreference {
  return (THEME_PREFERENCES as readonly string[]).includes(value ?? '') ? (value as ThemePreference) : 'system';
}

export function resolveTheme(preference: ThemePreference, systemPrefersDark: boolean): ResolvedTheme {
  if (preference === 'system') return systemPrefersDark ? 'dark' : 'light';
  return preference;
}

function darkMedia(): MediaQueryList | null {
  return typeof window.matchMedia === 'function' ? window.matchMedia(DARK_QUERY) : null;
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
  const [systemDark, setSystemDark] = useState(() => darkMedia()?.matches ?? false);

  useEffect(() => {
    const media = darkMedia();
    if (!media) return;
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  const resolved = resolveTheme(preference, systemDark);
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
