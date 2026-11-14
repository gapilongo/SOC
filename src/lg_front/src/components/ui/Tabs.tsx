import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { Link, type To } from 'react-router-dom';

import { cx } from './cx';

export interface TabDef<T extends string> {
  id: T;
  label: string;
}

/**
 * How the tabs look:
 * - `segmented`: a bordered group of pills, for sections inside a page (the investigation);
 * - `underline`: a row on a rule with the selected tab underlined, for the views of a whole page.
 */
export type TabsVariant = 'segmented' | 'underline';

const LIST_CLASS: Record<TabsVariant, string> = {
  segmented: 'inline-flex max-w-full flex-wrap gap-1 rounded-control border border-strong bg-raised p-[3px]',
  underline: 'flex flex-wrap gap-1 border-b border-subtle',
};

const PANEL_CLASS: Record<TabsVariant, string> = {
  segmented: 'mt-3.5 focus-visible:outline-offset-4',
  underline: 'mt-4 focus-visible:outline-offset-4',
};

/** One tab of a variant, selected or not. Shared by `Tabs` and `TabLinks`. */
function tabClass(variant: TabsVariant, selected: boolean): string {
  if (variant === 'segmented') {
    return cx('h-8 rounded-tag px-3 text-ctl touch:min-h-11', selected ? 'bg-selected font-semibold text-fg' : 'text-secondary hover:bg-raised-2 hover:text-fg');
  }
  return cx(
    '-mb-px inline-flex h-[38px] items-center gap-2 whitespace-nowrap border-b-2 px-3 text-ctl font-medium touch:min-h-11',
    selected ? 'border-accent text-fg' : 'border-transparent text-secondary hover:text-fg',
  );
}

/**
 * ARIA tabs (WAI-ARIA Authoring Practices, automatic activation): a
 * `tablist` of `tab` buttons with a roving tabindex, so Tab enters the list
 * at the selected tab and leaves it to the panel; Left/Right move and select
 * (wrapping), Home/End go to the first/last tab. Only the selected panel is
 * rendered. The caller owns the selected value (component state or the URL).
 */
export function Tabs<T extends string>({
  label,
  tabs,
  value,
  onChange,
  children,
  className,
  variant = 'segmented',
}: {
  label: string;
  tabs: ReadonlyArray<TabDef<T>>;
  value: T;
  onChange: (next: T) => void;
  /** The selected panel's content. */
  children: ReactNode;
  className?: string;
  variant?: TabsVariant;
}) {
  const base = useId();
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const tabId = (id: T) => `${base}-tab-${id}`;
  const panelId = `${base}-panel`;
  const index = Math.max(0, tabs.findIndex((t) => t.id === value));

  const select = (i: number) => {
    const n = tabs.length;
    const next = ((i % n) + n) % n;
    onChange(tabs[next].id);
    refs.current[next]?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    switch (e.key) {
      case 'ArrowRight':
        e.preventDefault();
        select(index + 1);
        break;
      case 'ArrowLeft':
        e.preventDefault();
        select(index - 1);
        break;
      case 'Home':
        e.preventDefault();
        select(0);
        break;
      case 'End':
        e.preventDefault();
        select(tabs.length - 1);
        break;
      default:
    }
  };

  return (
    <div className={className}>
      <div role="tablist" aria-label={label} className={LIST_CLASS[variant]}>
        {tabs.map((t, i) => {
          const selected = t.id === value;
          return (
            <button
              key={t.id}
              ref={(el) => {
                refs.current[i] = el;
              }}
              type="button"
              role="tab"
              id={tabId(t.id)}
              aria-selected={selected}
              aria-controls={panelId}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(t.id)}
              onKeyDown={onKeyDown}
              className={tabClass(variant, selected)}
            >
              {t.label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={panelId} aria-labelledby={tabId(tabs[index].id)} tabIndex={0} className={PANEL_CLASS[variant]}>
        {children}
      </div>
    </div>
  );
}

export interface TabLinkDef {
  id: string;
  to: To;
  label: ReactNode;
  /** Shown after the label (a count chip). */
  trailing?: ReactNode;
}

/**
 * Tabs that are links: each view has its own URL, so they are a `nav` of
 * links with `aria-current="page"` on the current one, not an ARIA tablist.
 * They look like the `underline` variant of `Tabs`.
 */
export function TabLinks({ label, tabs, current, className }: { label: string; tabs: readonly TabLinkDef[]; current: string; className?: string }) {
  return (
    <nav aria-label={label} className={cx('relative overflow-x-auto border-b border-subtle', className)}>
      <ul className="flex gap-1">
        {tabs.map((t) => (
          <li key={t.id}>
            <Link to={t.to} aria-current={t.id === current ? 'page' : undefined} className={tabClass('underline', t.id === current)}>
              {t.label}
              {t.trailing}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
