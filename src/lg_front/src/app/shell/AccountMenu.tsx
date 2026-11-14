import { Check, Lock, LogOut, Rows3 } from 'lucide-react';
import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { cx } from '../../components/ui';
import { useDensity } from '../../theme/density';
import { usePopover } from './usePopover';

/** Two letters for the avatar: initials of the e-mail's local part ("m.roux" -> "MR"). */
export function initials(email: string | null | undefined): string {
  const local = (email ?? '').split('@')[0] ?? '';
  const parts = local.split(/[._\-+\s]+/).filter(Boolean);
  const letters = parts.length >= 2 ? parts[0][0] + parts[1][0] : local.slice(0, 2);
  return letters.toUpperCase() || '?';
}

export function roleLabel(role: string | null | undefined, platformAdmin: boolean): string {
  const base = role ? role.charAt(0).toUpperCase() + role.slice(1) : 'No role';
  return platformAdmin ? `${base}, platform admin` : base;
}

const ITEM =
  'flex min-h-8 w-full items-center gap-2.5 rounded-control px-2.5 text-left text-ctl text-fg hover:bg-selected focus:bg-selected focus:outline-none touch:min-h-11';

/**
 * The signed-in person at the bottom of the rail, and their menu (ARIA menu
 * button): account security, row density and sign out. Keyboard: Enter,
 * Space or Down opens on the first item, Up on the last; Up/Down/Home/End
 * move; Escape closes and returns focus to the button; Tab closes.
 */
export function AccountMenu({ tenantLabel, onSignOut }: { tenantLabel: string; onSignOut: () => void }) {
  const { principal } = useAuth();
  const { density, setDensity } = useDensity();
  const navigate = useNavigate();
  const { open, setOpen, close, rootRef, buttonRef } = usePopover();
  const [focusAt, setFocusAt] = useState<'first' | 'last'>('first');
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const items = () => Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? []);

  useEffect(() => {
    if (!open) return;
    const all = items();
    (focusAt === 'last' ? all[all.length - 1] : all[0])?.focus();
  }, [open, focusAt]);

  if (!principal) return null;

  const show = (at: 'first' | 'last') => {
    setFocusAt(at);
    setOpen(true);
  };
  const run = (fn: () => void) => () => {
    close(false);
    fn();
  };

  const onButtonKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      show(e.key === 'ArrowUp' ? 'last' : 'first');
    }
  };
  const onMenuKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const all = items();
    const at = all.indexOf(document.activeElement as HTMLElement);
    const move = (i: number) => all[(i + all.length) % all.length]?.focus();
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        move(at + 1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        move(at - 1);
        break;
      case 'Home':
        e.preventDefault();
        move(0);
        break;
      case 'End':
        e.preventDefault();
        move(all.length - 1);
        break;
      case 'Tab':
        close(false);
        break;
      default:
    }
  };

  const role = roleLabel(principal.role, principal.isPlatformAdmin);
  const email = principal.email ?? 'Signed in';

  return (
    <div ref={rootRef} className="relative flex-none border-t border-subtle">
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => (open ? close() : show('first'))}
        onKeyDown={onButtonKey}
        className="flex w-full items-center gap-[9px] px-3.5 py-2.5 text-left hover:bg-raised-2 touch:min-h-11"
      >
        {/* The visible text is the accessible name (WCAG 2.5.3), after the word that says what the button is. */}
        <span className="sr-only">Account: </span>
        <span className="grid h-[26px] w-[26px] flex-none place-items-center rounded-full border border-strong bg-raised-2 text-[10.5px] font-semibold text-fg">
          {initials(principal.email)}
        </span>
        <span className="min-w-0 leading-tight">
          <span className="block truncate font-medium text-fg">{email}</span>
          <span className="block truncate text-2xs text-muted">{role}</span>
        </span>
      </button>
      {open && (
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-label="Account"
          tabIndex={-1}
          onKeyDown={onMenuKey}
          className="absolute bottom-full left-2 z-50 mb-1 flex w-60 flex-col gap-0.5 rounded-[4px] bg-raised p-1.5 shadow-popover"
        >
          <div className="mb-1 border-b border-subtle px-2.5 pb-2 pt-1.5">
            <div className="truncate text-ctl font-medium text-fg">{email}</div>
            <div className="truncate text-xs text-secondary">
              {role} · {tenantLabel}
              {principal.method === 'oidc' ? ' · SSO' : ''}
            </div>
          </div>
          {can.account(principal) && (
            <MenuItem icon={<Lock className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />} onSelect={run(() => navigate('/account'))}>
              Account security
            </MenuItem>
          )}
          <MenuItem
            role="menuitemcheckbox"
            checked={density === 'comfortable'}
            icon={<Rows3 className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            onSelect={() => setDensity(density === 'comfortable' ? 'compact' : 'comfortable')}
          >
            Comfortable rows
          </MenuItem>
          <MenuItem icon={<LogOut className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />} onSelect={run(onSignOut)}>
            Sign out
          </MenuItem>
        </div>
      )}
    </div>
  );
}

function MenuItem({
  role = 'menuitem',
  checked,
  icon,
  onSelect,
  children,
}: {
  role?: 'menuitem' | 'menuitemcheckbox';
  checked?: boolean;
  icon: ReactNode;
  onSelect: () => void;
  children: ReactNode;
}) {
  const checkable = role !== 'menuitem';
  return (
    <button type="button" role={role} aria-checked={checkable ? Boolean(checked) : undefined} tabIndex={-1} onClick={onSelect} className={ITEM}>
      {checkable ? (
        <span className={cx('flex h-4 w-4 flex-none items-center justify-center text-link', !checked && 'invisible')} aria-hidden="true">
          <Check className="h-4 w-4" strokeWidth={2} />
        </span>
      ) : (
        <span className="flex-none text-secondary">{icon}</span>
      )}
      <span className="flex-1">{children}</span>
      {checkable && <span className="flex-none text-secondary">{icon}</span>}
    </button>
  );
}
