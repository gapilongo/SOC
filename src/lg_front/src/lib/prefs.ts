/**
 * Display preferences kept in localStorage (theme, table density).
 *
 * The one place the app touches localStorage (eslint bans it elsewhere:
 * credentials are never persisted). Only small, non-sensitive UI choices go
 * here, under the `lg-sotf.` prefix. Storage can be missing or throw (private
 * windows, blocked site data, quota), so every access is guarded and a
 * failure just means the default applies.
 */

const PREFIX = 'lg-sotf.';

export type PrefKey = 'theme' | 'density';

export function readPref(key: PrefKey): string | null {
  try {
    return window.localStorage.getItem(PREFIX + key);
  } catch {
    return null;
  }
}

export function writePref(key: PrefKey, value: string): void {
  try {
    window.localStorage.setItem(PREFIX + key, value);
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}
