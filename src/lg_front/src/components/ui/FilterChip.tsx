import { Check, ChevronDown } from 'lucide-react';
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';

import { cx } from './cx';

export interface FilterOption {
  value: string;
  label: string;
}

/**
 * A dropdown filter chip ("Severity: High, Medium"): a button that opens a
 * listbox. Several values by default, one with `multiple={false}`.
 *
 * Keyboard: Down, Up, Enter or Space on the chip opens the list; in the list
 * Up/Down/Home/End move, Enter or Space toggles (and closes a single-choice
 * list), Escape closes and returns focus to the chip, Tab closes.
 */
export function FilterChip({
  label,
  options,
  value,
  onChange,
  multiple = true,
  anyLabel = 'Any',
  className,
}: {
  label: string;
  options: readonly FilterOption[];
  value: readonly string[];
  onChange: (next: string[]) => void;
  multiple?: boolean;
  anyLabel?: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const id = useId();
  const listId = `${id}-list`;
  const optionId = (i: number) => `${id}-opt-${i}`;

  const selectedLabels = options.filter((o) => value.includes(o.value)).map((o) => o.label);
  const summary = selectedLabels.length ? selectedLabels.join(', ') : anyLabel;

  useEffect(() => {
    if (!open) return;
    listRef.current?.focus();
    const onPointer = (e: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', onPointer);
    return () => document.removeEventListener('pointerdown', onPointer);
  }, [open]);

  const openList = (at?: number) => {
    const first = options.findIndex((o) => value.includes(o.value));
    setActive(at ?? Math.max(0, first));
    setOpen(true);
  };
  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) buttonRef.current?.focus();
  };
  const toggle = (option: FilterOption) => {
    if (!multiple) {
      onChange(value.includes(option.value) ? [] : [option.value]);
      close(true);
      return;
    }
    onChange(value.includes(option.value) ? value.filter((v) => v !== option.value) : [...value, option.value]);
  };

  const onButtonKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      openList(e.key === 'ArrowUp' ? options.length - 1 : undefined);
    }
  };
  const onListKey = (e: KeyboardEvent<HTMLUListElement>) => {
    const last = options.length - 1;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setActive((i) => Math.min(i + 1, last));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setActive((i) => Math.max(i - 1, 0));
        break;
      case 'Home':
        e.preventDefault();
        setActive(0);
        break;
      case 'End':
        e.preventDefault();
        setActive(last);
        break;
      case 'Enter':
      case ' ': {
        e.preventDefault();
        const option = options[active];
        if (option) toggle(option);
        break;
      }
      case 'Escape':
        e.preventDefault();
        close(true);
        break;
      case 'Tab':
        close(false);
        break;
      default:
    }
  };

  return (
    <div ref={rootRef} className={cx('relative inline-block', className)}>
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        onClick={() => (open ? close(false) : openList())}
        onKeyDown={onButtonKey}
        className={cx(
          'inline-flex h-[34px] max-w-full items-center gap-1.5 rounded-control border bg-raised px-2.5 text-ctl text-secondary touch:min-h-11',
          'hover:bg-raised-2',
          value.length ? 'border-link' : 'border-control',
        )}
      >
        {label}:<span className="truncate font-medium text-fg">{summary}</span>
        <ChevronDown className="h-3.5 w-3.5 flex-none" strokeWidth={2} aria-hidden="true" />
      </button>
      {open && (
        <ul
          ref={listRef}
          id={listId}
          role="listbox"
          tabIndex={-1}
          aria-label={label}
          aria-multiselectable={multiple || undefined}
          aria-activedescendant={options[active] ? optionId(active) : undefined}
          onKeyDown={onListKey}
          className="absolute left-0 z-40 mt-1 max-h-72 min-w-[12rem] overflow-y-auto rounded-card border border-strong bg-raised-2 p-1.5 shadow-popover focus:outline-none"
        >
          {options.map((o, i) => {
            const selected = value.includes(o.value);
            return (
              // Keyboard selection runs through the listbox (aria-activedescendant), as the ARIA pattern prescribes.
              // eslint-disable-next-line jsx-a11y/click-events-have-key-events
              <li
                key={o.value}
                id={optionId(i)}
                role="option"
                aria-selected={selected}
                onPointerDown={(e) => e.preventDefault()}
                onClick={() => {
                  setActive(i);
                  toggle(o);
                }}
                onMouseEnter={() => setActive(i)}
                className={cx(
                  'flex min-h-9 cursor-pointer items-center gap-2 rounded-control px-2.5 text-ctl text-fg touch:min-h-11',
                  i === active && 'bg-selected outline outline-2 -outline-offset-2 outline-focus',
                )}
              >
                <span className={cx('flex h-4 w-4 flex-none items-center justify-center', !selected && 'invisible')} aria-hidden="true">
                  <Check className="h-4 w-4 text-link" strokeWidth={2} />
                </span>
                {o.label}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
