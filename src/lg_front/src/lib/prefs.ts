/**
 * Display preferences kept in localStorage: the theme and the table density,
 * and per user the work queue's row density and saved views.
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

/**
 * Display preferences of one page that each signed-in user keeps separately
 * (the work queue's row density and saved views). The key is closed like
 * `PrefKey`, and the user id is part of the storage key, so two people on one
 * browser do not share them. Not for anything sensitive: a saved view holds
 * filter names only.
 */
export type UserPrefKey = 'queue-density' | 'queue-views';

/** The longest value a user preference may hold (characters). */
export const USER_PREF_MAX = 8_000;

function userKey(key: UserPrefKey, userId: string): string {
  return `${PREFIX}${key}.${userId}`;
}

export function readUserPref(key: UserPrefKey, userId: string | null | undefined): string | null {
  if (!userId) return null;
  try {
    return window.localStorage.getItem(userKey(key, userId));
  } catch {
    return null;
  }
}

export function writeUserPref(key: UserPrefKey, userId: string | null | undefined, value: string): void {
  if (!userId || value.length > USER_PREF_MAX) return;
  try {
    window.localStorage.setItem(userKey(key, userId), value);
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}
