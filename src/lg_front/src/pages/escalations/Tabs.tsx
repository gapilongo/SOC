import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react';

import { cx } from '../../components/ui';

export interface TabDef<T extends string> {
  id: T;
  label: string;
}

/**
 * ARIA tabs (WAI-ARIA Authoring Practices, automatic activation): a
 * `tablist` of `tab` buttons with a roving tabindex, so Tab enters the list
 * at the selected tab and leaves it to the panel; Left/Right move and select
 * (wrapping), Home/End go to the first/last tab. Only the selected panel is
 * rendered.
 */
export function Tabs<T extends string>({
  label,
  tabs,
  value,
  onChange,
  children,
  className,
}: {
  label: string;
  tabs: ReadonlyArray<TabDef<T>>;
  value: T;
  onChange: (next: T) => void;
  /** The selected panel's content. */
  children: ReactNode;
  className?: string;
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
      <div
        role="tablist"
        aria-label={label}
        className="inline-flex max-w-full flex-wrap gap-1 rounded-control border border-strong bg-raised p-[3px]"
      >
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
              className={cx(
                'h-8 rounded-tag px-3 text-ctl touch:min-h-11',
                selected ? 'bg-selected font-semibold text-fg' : 'text-secondary hover:bg-raised-2 hover:text-fg',
              )}
            >
              {t.label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={panelId} aria-labelledby={tabId(tabs[index].id)} tabIndex={0} className="mt-3.5 focus-visible:outline-offset-4">
        {children}
      </div>
    </div>
  );
}
