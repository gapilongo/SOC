/**
 * Keyboard shortcuts of the investigation view. Every shortcut has a visible
 * control; a single-key shortcut acts only outside text fields and can be
 * switched off (WCAG 2.1.4), a choice kept with the display preferences.
 */

import { useEffect, useRef, useState } from 'react';

import { readPref, writePref } from '../../lib/prefs';

/** Inputs that take no text: a character typed on them is free for a shortcut. */
const NOT_TEXT = new Set(['checkbox', 'radio', 'button', 'submit', 'reset', 'file', 'image', 'range', 'color']);

/** The user is typing: a single character belongs to the field, not to the page. */
export function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target instanceof HTMLInputElement) return !NOT_TEXT.has(target.type);
  return target.isContentEditable || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT';
}

/** A bare character key: no Ctrl, Meta or Alt, and not typed into a field. */
export function isSingleKey(e: KeyboardEvent): boolean {
  return !e.ctrlKey && !e.metaKey && !e.altKey && !e.defaultPrevented && !isTyping(e.target);
}

/** Whether single-key shortcuts are on (the default), and the switch. */
export function useSingleKeys(): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(() => readPref('single-keys') !== 'off');
  return [
    on,
    (next: boolean) => {
      setOn(next);
      writePref('single-keys', next ? 'on' : 'off');
    },
  ];
}

/** `handler` on every keydown of the document while the component is mounted (always the latest handler). */
export function useKeydown(handler: (e: KeyboardEvent) => void): void {
  const latest = useRef(handler);
  latest.current = handler;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => latest.current(e);
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);
}
