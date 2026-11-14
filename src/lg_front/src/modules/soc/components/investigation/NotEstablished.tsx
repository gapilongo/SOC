/**
 * What is not established, in three kinds that are never merged: checked
 * and found nothing (collapsed to one line), not checked, could not check
 * for this customer. None of them counts for or against the outcome.
 */

import type { ReactNode } from 'react';

import type { NotEstablishedItemOut, NotEstablishedOut } from '../../api/investigation';
import { Glyph, type GlyphName } from './glyphs';

function Kind({ glyph, title, count, children }: { glyph: GlyphName; title: string; count: number; children: ReactNode }) {
  return (
    <section data-kind={glyph}>
      <h3 className="mb-1 mt-3 flex items-center gap-[7px] text-ctl font-semibold text-fg">
        <Glyph name={glyph} />
        {title}
        <span className="ml-auto font-mono text-[11.5px] font-medium leading-none text-muted">
          {count}
          <span className="sr-only"> {count === 1 ? 'item' : 'items'}</span>
        </span>
      </h3>
      {count === 0 ? <p className="text-ctl text-muted">Nothing in this kind.</p> : children}
    </section>
  );
}

function Items({ items }: { items: NotEstablishedItemOut[] }) {
  return (
    <ul>
      {items.map((item, i) => (
        <li
          key={`${item.what}-${i}`}
          className="relative break-words py-1 pl-[19px] text-ctl text-body before:absolute before:left-[3px] before:top-2.5 before:h-px before:w-[5px] before:bg-control"
        >
          {item.what}
          {item.why && <small className="block text-xs text-muted">{item.why}</small>}
        </li>
      ))}
    </ul>
  );
}

/** "Reputation of IP 203.0.113.50" -> "reputation of IP 203.0.113.50", for a sentence that lists several. */
const lowerFirst = (value: string) => value.charAt(0).toLowerCase() + value.slice(1);

export function NotEstablished({
  value,
  notCheckedNote,
}: {
  value: NotEstablishedOut;
  /** Said under "Not checked" when the data cannot list everything that was left out. */
  notCheckedNote?: string;
}) {
  const empty = value.checked_empty;
  return (
    <div>
      <Kind glyph="empty" title="Checked, found nothing" count={empty.length}>
        <p className="break-words text-ctl text-body">
          {empty.map((item, i) => (i === 0 ? item.what : lowerFirst(item.what))).join(', ')}.
        </p>
        <details className="mt-1 text-xs">
          <summary className="flex min-h-6 w-fit cursor-pointer items-center text-link">
            Show the {empty.length} {empty.length === 1 ? 'lookup' : 'lookups'}
          </summary>
          <ul className="font-mono leading-[1.6] text-body">
            {empty.map((item, i) => (
              <li key={`${item.what}-${i}`} className="break-words">
                {item.observation_id ? `${item.observation_id}  ` : ''}
                {item.what}
                {item.why ? `  ${item.why}` : ''}
              </li>
            ))}
          </ul>
        </details>
      </Kind>
      <Kind glyph="not" title="Not checked" count={value.not_checked.length}>
        <Items items={value.not_checked} />
      </Kind>
      {notCheckedNote && <p className="mt-1 text-xs text-muted">{notCheckedNote}</p>}
      <Kind glyph="cannot" title="Could not check for this customer" count={value.unavailable.length}>
        <Items items={value.unavailable} />
      </Kind>
      <p className="mt-3 border-t border-dashed border-strong pt-2 text-xs text-muted">
        Nothing in this column counted for or against the outcome. A lookup that returns nothing is never used as proof that something is safe.
      </p>
    </div>
  );
}
