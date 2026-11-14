import { cx } from './cx';

/** One event of a timeline, already worded by the caller. */
export interface TimelineEntry {
  id: string | number;
  /** What happened. */
  title: string;
  /** When (ISO), and how to show it. */
  ts: string;
  time: string;
  /** A qualifier shown next to the title (the step that produced the event). */
  note?: string;
  /** Who or what did it ("by analyst a@b"). */
  byline?: string;
  /** Free text under the entry; line breaks are kept. */
  detail?: string;
}

/**
 * How the events are laid out:
 * - `rail`: a vertical rule with a dot per event, for narrow panels;
 * - `rows`: one ruled row per event with the time at the right, for wide pages.
 */
export type TimelineVariant = 'rail' | 'rows';

/** An ordered list of events. Presentational: the caller fetches, orders and words them. */
export function Timeline({ entries, variant = 'rail', className }: { entries: readonly TimelineEntry[]; variant?: TimelineVariant; className?: string }) {
  if (variant === 'rows') {
    return (
      <ol className={cx('flex flex-col gap-2 text-ctl', className)}>
        {entries.map((e) => (
          <li key={e.id} className="flex flex-wrap justify-between gap-x-3 border-b border-subtle pb-2 last:border-b-0">
            <span className="min-w-0">
              <span className="font-medium text-fg">{e.title}</span>
              {(e.byline || e.note) && <span className="text-secondary"> {[e.byline, e.note].filter(Boolean).join(' · ')}</span>}
              {e.detail && <span className="block whitespace-pre-wrap break-words text-body">{e.detail}</span>}
            </span>
            <time dateTime={e.ts} className="whitespace-nowrap text-xs text-secondary">
              {e.time}
            </time>
          </li>
        ))}
      </ol>
    );
  }
  return (
    <ol className={cx('relative space-y-3 border-l border-strong pl-4', className)}>
      {entries.map((e) => (
        <li key={e.id} className="text-sm">
          <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full bg-muted" aria-hidden="true" />
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium text-fg">{e.title}</span>
            {e.note && <span className="text-xs text-muted">{e.note}</span>}
            <time dateTime={e.ts} className="text-xs text-muted">
              {e.time}
            </time>
          </div>
          {e.byline && <div className="text-xs text-muted">{e.byline}</div>}
          {e.detail && <p className="mt-0.5 whitespace-pre-wrap break-words text-body">{e.detail}</p>}
        </li>
      ))}
    </ol>
  );
}
