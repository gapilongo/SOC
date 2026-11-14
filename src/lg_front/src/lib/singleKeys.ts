/**
 * Whether single-key shortcuts are on: one switch for the whole console.
 *
 * A shortcut that is one character (`/` for the search field, `T` for a
 * verdict) must be possible to switch off (WCAG 2.1.4). The choice is a
 * display preference each user keeps (lib/prefs.ts); every part of the
 * console that reads it follows a change at once, wherever the switch was
 * pressed. Without a user account, or where the browser keeps nothing, the
 * choice lasts for the page.
 */

import { useCallback, useSyncExternalStore } from 'react';

import { readUserPref, writeUserPref } from './prefs';

const listeners = new Set<() => void>();
/** Choices the browser could not keep, by user id ('' without one). */
const unsaved = new Map<string, boolean>();

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function read(userId: string | null | undefined): boolean {
  return unsaved.get(userId ?? '') ?? readUserPref('single-keys', userId) !== 'off';
}

/** Whether single-key shortcuts are on (the default) for this user, and the switch. */
export function useSingleKeys(userId: string | null | undefined): [boolean, (on: boolean) => void] {
  const on = useSyncExternalStore(subscribe, () => read(userId));
  const set = useCallback(
    (next: boolean) => {
      const value = next ? 'on' : 'off';
      writeUserPref('single-keys', userId, value);
      if (readUserPref('single-keys', userId) === value) unsaved.delete(userId ?? '');
      else unsaved.set(userId ?? '', next);
      for (const listener of [...listeners]) listener();
    },
    [userId],
  );
  return [on, set];
}
