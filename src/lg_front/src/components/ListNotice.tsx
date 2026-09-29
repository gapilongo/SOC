import { RefreshCw } from 'lucide-react';

import { MAX_PAGES } from '../lib/pagination';
import { Button, cx } from './ui';

export interface ListNoticeState {
  pages: number;
  capped: boolean;
  outdated: boolean;
  isFetching: boolean;
  items: readonly unknown[];
  reloadFromTop: () => Promise<void>;
}

/**
 * Status line for a paginated list with more than one page loaded: automatic
 * refresh pauses there (to bound requests), so say so and offer a reload.
 */
export function ListNotice({ list, noun }: { list: ListNoticeState; noun: string }) {
  if (list.pages <= 1) return null;
  return (
    <div
      role="status"
      className={cx(
        'mb-3 flex flex-wrap items-center gap-3 rounded-md border px-3 py-2 text-sm',
        list.outdated ? 'border-sky-700 bg-sky-950 text-sky-100' : 'border-slate-700 bg-slate-900 text-slate-300',
      )}
    >
      <span>
        {list.outdated
          ? `New activity since these ${noun} loaded.`
          : `${list.items.length} ${noun} loaded; automatic refresh is paused while more than one page is shown.`}
        {list.capped && ` Only the first ${MAX_PAGES} pages are shown; narrow the filters to see older ${noun}.`}
      </span>
      <Button
        size="sm"
        variant={list.outdated ? 'primary' : 'secondary'}
        busy={list.isFetching}
        onClick={() => void list.reloadFromTop()}
        icon={<RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />}
      >
        Reload from top
      </Button>
    </div>
  );
}
