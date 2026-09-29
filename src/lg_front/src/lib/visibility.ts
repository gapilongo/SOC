import { useSyncExternalStore } from 'react';

function subscribe(cb: () => void): () => void {
  document.addEventListener('visibilitychange', cb);
  return () => document.removeEventListener('visibilitychange', cb);
}

export function isPageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState !== 'hidden';
}

/** True while the tab is visible; polling pauses when it is hidden. */
export function usePageVisible(): boolean {
  return useSyncExternalStore(subscribe, isPageVisible, () => true);
}

/** Poll interval that is `false` (paused) while the tab is hidden. */
export function usePollInterval(ms: number): number | false {
  return usePageVisible() ? ms : false;
}
