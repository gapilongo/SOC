/**
 * What is not established, in three kinds that are never merged: checked
 * and found nothing (collapsed to one line), not checked, could not check
 * for this customer. None of them counts for or against the outcome.
 */

import type { ReactNode } from 'react';

import type { InvestigationObservationOut, NotEstablishedOut } from '../../api/types';
import { Glyph, type GlyphName } from './glyphs';
import { observationName, observationSubject } from './Observation';

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

function Items({ items }: { items: Array<{ what: string; why?: string | null; source?: string | null }> }) {
  return (
    <ul>
      {items.map((item, i) => (
        <li
          key={`${item.what}-${i}`}
          className="relative break-words py-1 pl-[19px] text-ctl text-body before:absolute before:left-[3px] before:top-2.5 before:h-px before:w-[5px] before:bg-control"
        >
          {item.what}
          {(item.why || item.source) && (
            <small className="block text-xs text-muted">
              {item.source && <span className="font-mono">{item.source}: </span>}
              {item.why}
            </small>
          )}
        </li>
      ))}
    </ul>
  );
}

/**
 * The lookups that found nothing on one line, each kind of lookup named once:
 * "Threat-intelligence reputation: IP address 203.0.113.50, file hash 5d1e...;
 * earlier alerts of this customer for the same entity: user m.keller."
 */
export function emptyLine(ids: readonly string[], byId: ReadonlyMap<string, InvestigationObservationOut>): string {
  const groups = new Map<string, string[]>();
  for (const id of ids) {
    const o = byId.get(id);
    const title = o ? o.title : `Lookup ${id}`;
    const subject = o ? observationSubject(o) : null;
    groups.set(title, [...(groups.get(title) ?? []), ...(subject ? [subject] : [])]);
  }
  const parts = [...groups].map(([title, subjects], i) => {
    const name = i === 0 ? title : title.charAt(0).toLowerCase() + title.slice(1);
    return subjects.length ? `${name}: ${subjects.join(', ')}` : name;
  });
  return `${parts.join('; ')}.`;
}

export function NotEstablished({
  value,
  observations,
  notCheckedNote,
}: {
  value: NotEstablishedOut;
  /** The observations of the investigation: `value.empty` names the ones that found nothing by id. */
  observations: InvestigationObservationOut[];
  /** Said under "Not checked" when the data cannot list everything that was left out. */
  notCheckedNote?: string;
}) {
  const byId = new Map(observations.map((o) => [o.id, o]));
  const empty = value.empty.map((id) => ({ id, name: byId.has(id) ? observationName(byId.get(id) as InvestigationObservationOut) : `Lookup ${id}` }));
  return (
    <div>
      <Kind glyph="empty" title="Checked, found nothing" count={empty.length}>
        <p className="break-words text-ctl text-body">{emptyLine(value.empty, byId)}</p>
        <details className="mt-1 text-xs">
          <summary className="flex min-h-6 w-fit cursor-pointer items-center text-link">
            Show the {empty.length} {empty.length === 1 ? 'lookup' : 'lookups'}
          </summary>
          <ul className="font-mono leading-[1.6] text-body">
            {empty.map((item) => (
              <li key={item.id} className="break-words">
                {item.id}
                {'  '}
                {item.name}
                {byId.get(item.id)?.sources.length ? `  (${byId.get(item.id)?.sources.join(', ')})` : ''}
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
