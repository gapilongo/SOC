/**
 * The keys that open the search field from anywhere: Ctrl+K (Cmd+K on a Mac)
 * always, and `/` while nothing is being typed.
 *
 * `/` is a single-key shortcut, so it can be switched off (WCAG 2.1.4): the
 * choice is a display preference (lib/prefs.ts) and the search field's
 * command "Single-key shortcuts" changes it. The shell defines no other
 * single-key shortcut; a page defines its own.
 */

import { useCallback, useEffect, useState } from 'react';

import { readPref, writePref } from '../../lib/prefs';

/** Whether the key was pressed where text is entered: there it is a character, not a shortcut. */
function typing(target: EventTarget | null): boolean {
  const el = target instanceof HTMLElement ? target : null;
  if (!el) return false;
  return el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) || ['textbox', 'combobox'].includes(el.getAttribute('role') ?? '');
}

/** Whether single-key shortcuts are on (the default), and the switch. */
export function useSingleKeys(): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(() => readPref('keys') !== 'off');
  const set = useCallback((next: boolean) => {
    setOn(next);
    writePref('keys', next ? 'on' : 'off');
  }, []);
  return [on, set];
}

/** Ctrl+K or Cmd+K calls `toggle`; `/` calls it while the field is closed, single keys are on and nothing is being typed. */
export function useSearchKeys(toggle: () => void, open: boolean, singleKeys: boolean): void {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        toggle();
      } else if (e.key === '/' && singleKeys && !open && !e.ctrlKey && !e.metaKey && !e.altKey && !typing(e.target)) {
        e.preventDefault();
        toggle();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [toggle, open, singleKeys]);
}
