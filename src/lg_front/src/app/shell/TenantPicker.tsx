/**
 * The scope control's picker, for platform admins: a searchable list of the
 * tenants, opened from the control. Loaded on demand (ScopeControl.tsx).
 */

import { Check, ChevronDown } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';

import { useTenants } from '../../api/hooks';
import type { Principal } from '../../auth/store';
import { cx } from '../../components/ui';
import { TENANT_ID } from '../../lib/scope';
import { BOX, Current } from './ScopeControl';
import { filterTenants, useChooseTenant } from './tenants';
import { usePopover } from './usePopover';

const MAX_OPTIONS = 50;

interface Option {
  id: string;
  label: string;
  hint: string;
  suspended?: boolean;
}

export default function TenantPicker({ principal, label }: { principal: Principal; label: string }) {
  const choose = useChooseTenant();
  const { open, setOpen, close, rootRef, buttonRef } = usePopover();
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listId = useId();
  const tenants = useTenants(open);
  const home = principal.homeTenantId;

  useEffect(() => {
    if (open) inputRef.current?.focus();
    else setQuery('');
  }, [open]);

  const options: Option[] = useMemo(() => {
    const matches: Option[] = filterTenants(tenants.data ?? [], query, home)
      .slice(0, MAX_OPTIONS)
      .map((t) => {
        const waiting = t.stats?.open_escalations;
        return {
          id: t.id,
          label: t.name,
          hint: [t.id === home ? 'home' : null, waiting ? `${waiting} need a person` : null].filter(Boolean).join(' · ') || t.id,
          suspended: t.status === 'suspended',
        };
      });
    const typed = query.trim().toLowerCase();
    // The list could not be loaded or does not know the id yet: a typed id still works.
    if (matches.length === 0 && TENANT_ID.test(typed)) matches.push({ id: typed, label: `Use tenant id "${typed}"`, hint: '' });
    return matches;
  }, [tenants.data, query, home]);

  const pick = (o: Option) => {
    choose(o.id, o.hint ? o.label : undefined);
    close();
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((i) => Math.min(i + 1, options.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (options[active]) pick(options[active]);
    }
  };
  const optionId = (i: number) => `${listId}-opt-${i}`;

  return (
    <div ref={rootRef} className="relative min-w-0">
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? `${listId}-pop` : undefined}
        onClick={() => (open ? close() : setOpen(true))}
        className={cx(BOX, 'max-w-full hover:bg-raised-2')}
      >
        <Current label={label} />
        <ChevronDown className="h-3.5 w-3.5 flex-none text-secondary" strokeWidth={1.5} aria-hidden="true" />
      </button>
      {open && (
        <div
          id={`${listId}-pop`}
          role="dialog"
          aria-label="Choose the tenant"
          className="absolute left-0 top-full z-50 mt-1.5 w-80 max-w-[calc(100vw-24px)] rounded-[4px] bg-raised pb-1.5 shadow-popover"
        >
          <div className="flex items-center justify-between px-3 pb-1.5 pt-2.5">
            <span className="eyebrow">Show work for</span>
            <span className="text-xs text-muted">part of the address</span>
          </div>
          <div className="px-3 pb-1.5">
            <label htmlFor={`${listId}-search`} className="sr-only">
              Search tenants
            </label>
            <input
              id={`${listId}-search`}
              ref={inputRef}
              role="combobox"
              aria-expanded="true"
              aria-controls={listId}
              aria-autocomplete="list"
              aria-activedescendant={options[active] ? optionId(active) : undefined}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setActive(0);
              }}
              onKeyDown={onKey}
              placeholder="Search by name or id"
              autoComplete="off"
              spellCheck={false}
              className="block h-7 w-full rounded-control border border-control bg-raised px-2 text-ctl text-fg"
            />
          </div>
          {tenants.isPending && <p className="px-3 py-1 text-xs text-muted">Loading tenants...</p>}
          {tenants.isError && <p className="px-3 py-1 text-xs text-danger-fg">The tenant list could not be loaded; type a tenant id.</p>}
          <ul id={listId} role="listbox" aria-label="Tenants" className="max-h-72 overflow-y-auto">
            {options.map((o, i) => (
              // Keyboard selection runs through the combobox input (aria-activedescendant), as the ARIA pattern prescribes.
              // eslint-disable-next-line jsx-a11y/click-events-have-key-events
              <li
                key={o.id}
                id={optionId(i)}
                role="option"
                aria-selected={i === active}
                onPointerDown={(e) => e.preventDefault()}
                onClick={() => pick(o)}
                onMouseEnter={() => setActive(i)}
                className={cx(
                  'flex min-h-[30px] cursor-pointer items-center gap-2 px-3 py-1 text-ctl',
                  i === active ? 'bg-selected text-fg' : 'text-body',
                  o.id === principal.tenantId && 'font-semibold text-fg',
                )}
              >
                <span className="flex w-3.5 flex-none justify-center">
                  {o.id === principal.tenantId && <Check className="h-3.5 w-3.5" strokeWidth={1.5} aria-label="current" />}
                </span>
                <span className="min-w-0 truncate">{o.label}</span>
                <span className="ml-auto flex-none text-xs font-normal text-muted">
                  {o.suspended ? 'suspended' : o.hint}
                </span>
              </li>
            ))}
          </ul>
          {!tenants.isPending && options.length === 0 && <p className="px-3 py-1 text-xs text-muted">No tenant matches.</p>}
        </div>
      )}
    </div>
  );
}
