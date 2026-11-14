/** Layout measurements for the queue: the room its table has decides the columns, the preview and how tall the list is. */

import { useEffect, useLayoutEffect, useState, type RefObject } from 'react';

/** Whether a media query matches; `fallback` where the browser cannot say (tests, old engines). */
export function useMedia(query: string, fallback: boolean): boolean {
  const read = () => (typeof window.matchMedia === 'function' ? window.matchMedia(query).matches : fallback);
  const [matches, setMatches] = useState(read);
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia(query);
    const onChange = () => setMatches(media.matches);
    onChange();
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [query]);
  return matches;
}

/** The element's content width (px), followed as it changes; `fallback` until it is measured. */
export function useElementWidth(ref: RefObject<HTMLElement | null>, fallback: number): number {
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w) setWidth(Math.round(w));
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [ref]);
  return width;
}

/** Where the queue's list sits on the page (px from the top of the page), and how tall its footer is. */
export interface QueueLayout {
  /** Top of the split (the list and the preview). */
  top: number;
  /** Top of the list's rows, under the table header. */
  listTop: number;
  footer: number;
}

/**
 * Measures the queue's layout so the list can fill what is left of the
 * window. It is read again when the window, the page, the split or the
 * footer changes size: what sits above the list (a notice, the bulk bar)
 * changes its height, and so does the footer when "Load more" appears.
 */
export function useQueueLayout(split: RefObject<HTMLElement | null>, footer: RefObject<HTMLElement | null>): QueueLayout {
  const [layout, setLayout] = useState<QueueLayout>({ top: 0, listTop: 0, footer: 0 });
  useLayoutEffect(() => {
    const el = split.current;
    if (!el) return;
    const measure = () => {
      const y = window.scrollY;
      const top = Math.round(el.getBoundingClientRect().top + y);
      const list = el.querySelector('[data-testid="virtual-scroll"]');
      const listTop = list ? Math.ceil(list.getBoundingClientRect().top + y) : top;
      const foot = footer.current ? Math.ceil(footer.current.getBoundingClientRect().height) : 0;
      setLayout((prev) => (prev.top === top && prev.listTop === listTop && prev.footer === foot ? prev : { top, listTop, footer: foot }));
    };
    measure();
    window.addEventListener('resize', measure);
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure);
    observer?.observe(document.body);
    observer?.observe(el);
    if (el.parentElement) observer?.observe(el.parentElement);
    if (footer.current) observer?.observe(footer.current);
    return () => {
      window.removeEventListener('resize', measure);
      observer?.disconnect();
    };
  }, [split, footer]);
  return layout;
}
