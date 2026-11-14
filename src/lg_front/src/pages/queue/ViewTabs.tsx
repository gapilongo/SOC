/**
 * The queue's views as tabs with their counts: the built-in ones, then the
 * ones this user saved. "Save view" keeps the current view, chips and
 * density under a name; a saved view can be removed while it is selected.
 */

import { useRef, useState, type FormEvent, type KeyboardEvent } from 'react';

import { cx } from '../../components/ui';
import { QButton } from './controls';
import { SAVED_VIEW_NAME_MAX, countText, type ViewCount } from './model';

export interface ViewTab {
  id: string;
  label: string;
  /** null: not counted (a saved view while another list is loaded). */
  count: ViewCount | null;
  saved: boolean;
}

export const tabDomId = (base: string, id: string) => `${base}-tab-${id}`;

export function ViewTabs({
  idBase,
  panelId,
  tabs,
  value,
  onChange,
  onSave,
  onRemove,
  canSave,
}: {
  idBase: string;
  panelId: string;
  tabs: readonly ViewTab[];
  value: string;
  onChange: (id: string) => void;
  onSave: (name: string) => void;
  onRemove: (id: string) => void;
  /** False once the most views one user keeps are saved. */
  canSave: boolean;
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState('');
  const index = Math.max(0, tabs.findIndex((t) => t.id === value));
  const current = tabs[index];

  const select = (i: number) => {
    const n = tabs.length;
    const next = ((i % n) + n) % n;
    onChange(tabs[next].id);
    refs.current[next]?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    const to = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    select(to);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;
    onSave(trimmed);
    setName('');
    setNaming(false);
  };

  return (
    <div className="flex items-end gap-0.5 overflow-x-auto border-b border-strong">
      <div role="tablist" aria-label="Saved views" className="flex flex-none gap-0.5">
        {tabs.map((t, i) => {
          const selected = t.id === current.id;
          return (
            <button
              key={t.id}
              ref={(el) => {
                refs.current[i] = el;
              }}
              type="button"
              role="tab"
              id={tabDomId(idBase, t.id)}
              aria-selected={selected}
              aria-controls={panelId}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(t.id)}
              onKeyDown={onKeyDown}
              className={cx(
                '-mb-px h-8 flex-none whitespace-nowrap border-b-2 px-[11px] text-ctl focus-visible:-outline-offset-2 touch:min-h-11',
                selected ? 'border-fg font-semibold text-fg' : 'border-transparent text-secondary hover:text-fg',
              )}
            >
              {t.label}
              {t.count && <b className={cx('ml-[5px] font-mono text-[11.5px] font-medium', selected ? 'text-fg' : 'text-muted')}>{countText(t.count)}</b>}
            </button>
          );
        })}
      </div>
      {naming ? (
        <form onSubmit={submit} className="-mb-px flex flex-none items-center gap-1.5 pb-0.5 pl-2">
          <input
            // The form opens on request, so focus belongs in its one field.
            // eslint-disable-next-line jsx-a11y/no-autofocus
            autoFocus
            aria-label="Name of the view"
            value={name}
            maxLength={SAVED_VIEW_NAME_MAX}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') setNaming(false);
            }}
            className="h-7 w-44 rounded-[3px] border border-control bg-raised px-2 text-ctl text-fg"
          />
          <QButton type="submit" disabled={!name.trim()}>
            Save
          </QButton>
          <QButton variant="quiet" onClick={() => setNaming(false)}>
            Cancel
          </QButton>
        </form>
      ) : (
        <>
          {canSave && (
            <button
              type="button"
              onClick={() => setNaming(true)}
              title="Save the current view, chips and density as a view"
              className="-mb-px h-8 flex-none whitespace-nowrap border-b-2 border-transparent px-[11px] text-ctl text-secondary hover:text-fg focus-visible:-outline-offset-2 touch:min-h-11"
            >
              + Save view
            </button>
          )}
          {current.saved && (
            <button
              type="button"
              onClick={() => onRemove(current.id)}
              className="-mb-px h-8 flex-none whitespace-nowrap border-b-2 border-transparent px-[11px] text-ctl text-secondary hover:text-fg focus-visible:-outline-offset-2 touch:min-h-11"
            >
              Remove view
            </button>
          )}
        </>
      )}
    </div>
  );
}
