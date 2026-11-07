import { useEffect, useRef, type RefObject } from 'react';

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

/** Focusable elements that are actually reachable (not hidden, not inside a closed <details>). */
function reachable(panel: HTMLElement): HTMLElement[] {
  return Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((n) => {
    if (n.closest('[hidden]')) return false;
    const details = n.closest('details');
    return !details || details.open || (n.tagName === 'SUMMARY' && n.parentElement === details);
  });
}

// Open traps, innermost last: only the top one handles Escape and Tab.
const trapStack: symbol[] = [];

// Scroll locks held by open traps; the page scrolls again when the last one is released.
let scrollLocks = 0;
let savedOverflow = '';

export interface FocusTrapOptions {
  /** Put focus back on the element that had it before opening (default true). */
  restoreFocus?: boolean;
  /** Called on Escape while this trap is the innermost one. */
  onEscape?: () => void;
  /** Stop the page behind from scrolling while open (default false). */
  lockScroll?: boolean;
}

/**
 * Keeps keyboard focus inside `panelRef` while `open` (WCAG 2.2: 2.1.2, 2.4.3): focus moves to the
 * element marked `data-autofocus` (else the first focusable one, else the panel), Tab and Shift+Tab
 * wrap around inside, and Escape calls `onEscape`. Nested traps stack: only the innermost reacts.
 */
export function useFocusTrap(panelRef: RefObject<HTMLElement | null>, open: boolean, options: FocusTrapOptions = {}): void {
  const { restoreFocus = true, lockScroll = false } = options;
  const onEscapeRef = useRef(options.onEscape);
  onEscapeRef.current = options.onEscape;

  useEffect(() => {
    if (!open) return;
    const token = Symbol('focus-trap');
    trapStack.push(token);
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const panel = panelRef.current;
    const first = panel?.querySelector<HTMLElement>('[data-autofocus]') ?? panel?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? panel)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (trapStack[trapStack.length - 1] !== token) return;
      if (e.key === 'Escape') {
        if (!onEscapeRef.current) return;
        e.stopPropagation();
        onEscapeRef.current();
        return;
      }
      if (e.key !== 'Tab' || !panel) return;
      const nodes = reachable(panel);
      if (nodes.length === 0) {
        e.preventDefault();
        return;
      }
      const firstNode = nodes[0];
      const lastNode = nodes[nodes.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === firstNode || !panel.contains(active))) {
        e.preventDefault();
        lastNode.focus();
      } else if (!e.shiftKey && (active === lastNode || !panel.contains(active))) {
        e.preventDefault();
        firstNode.focus();
      }
    };
    document.addEventListener('keydown', onKey, true);
    if (lockScroll && scrollLocks++ === 0) {
      savedOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', onKey, true);
      trapStack.splice(trapStack.indexOf(token), 1);
      if (lockScroll && --scrollLocks === 0) document.body.style.overflow = savedOverflow;
      if (restoreFocus && previouslyFocused && document.contains(previouslyFocused)) previouslyFocused.focus();
    };
  }, [open, panelRef, restoreFocus, lockScroll]);
}
