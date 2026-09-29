import { useEffect, useState } from 'react';

import { usePageVisible } from './visibility';

/** Current time, re-rendered every `intervalMs` while the tab is visible (for countdowns). */
export function useNow(intervalMs = 1_000): number {
  const [now, setNow] = useState(() => Date.now());
  const visible = usePageVisible();
  useEffect(() => {
    if (!visible) return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs, visible]);
  return now;
}
