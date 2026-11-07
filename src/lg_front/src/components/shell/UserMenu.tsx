import { Check, ChevronDown, Lock, LogOut, Rows3 } from 'lucide-react';
import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { useDensity } from '../../theme/density';
import { useTheme, type ThemePreference } from '../../theme/theme';
import { cx } from '../ui';

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

const THEMES: Array<{ value: ThemePreference; label: string }> = [
  { value: 'dark', label: 'Dark theme' },
  { value: 'light', label: 'Light theme' },
  { value: 'system', label: 'System theme' },
];

const ITEM =
  'flex min-h-9 w-full items-center gap-2.5 rounded-control px-2.5 text-left text-ctl text-fg hover:bg-selected focus:bg-selected focus:outline-none touch:min-h-11';

/**
 * The account menu (ARIA menu button): who is signed in, account security,
 * theme, row density and sign out. Keyboard: Enter, Space or Down opens on
 * the first item, Up on the last; Up/Down/Home/End move; Escape closes and
 * returns focus to the button; Tab closes.
 */
export function UserMenu({ tenantLabel, onSignOut }: { tenantLabel: string; onSignOut: () => void }) {
  const { principal } = useAuth();
  const { preference, setPreference } = useTheme();
  const { density, setDensity } = useDensity();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [focusAt, setFocusAt] = useState<'first' | 'last'>('first');
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const items = () => Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? []);

  useEffect(() => {
    if (!open) return;
    const all = items();
    (focusAt === 'last' ? all[all.length - 1] : all[0])?.focus();
    const onPointer = (e: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', onPointer);
    return () => document.removeEventListener('pointerdown', onPointer);
  }, [open, focusAt]);

  if (!principal) return null;

  const show = (at: 'first' | 'last') => {
    setFocusAt(at);
    setOpen(true);
  };
  const close = (refocus = true) => {
    setOpen(false);
    if (refocus) buttonRef.current?.focus();
  };
  const run = (fn: () => void, refocus = true) => () => {
    close(refocus);
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
      case 'Escape':
        e.preventDefault();
        close();
        break;
      case 'Tab':
        close(false);
        break;
      default:
    }
  };

  const role = roleLabel(principal.role, principal.isPlatformAdmin);
  const email = principal.email ?? 'Signed in';
  const ownAccount = can.account(principal);

  return (
    <div ref={rootRef} className="relative">
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={`Account: ${email}, ${role}`}
        onClick={() => (open ? close() : show('first'))}
        onKeyDown={onButtonKey}
        className="flex h-8 items-center gap-2 rounded-control pl-0.5 pr-1.5 text-fg hover:bg-raised-2 touch:min-h-11"
      >
        <span aria-hidden="true" className="grid h-7 w-7 place-items-center rounded-full bg-selected text-xs font-semibold text-link">
          {initials(principal.email)}
        </span>
        <ChevronDown className="h-3.5 w-3.5 text-secondary" strokeWidth={2} aria-hidden="true" />
      </button>
      {open && (
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-label="Account"
          tabIndex={-1}
          onKeyDown={onMenuKey}
          className="absolute right-0 top-full z-50 mt-1 flex w-64 flex-col gap-0.5 rounded-card border border-strong bg-raised-2 p-1.5 shadow-popover"
        >
          <div className="mb-1 border-b border-strong px-2.5 pb-2.5 pt-2">
            <div className="truncate text-ctl font-medium text-fg">{email}</div>
            <div className="truncate text-xs text-secondary">
              {role} · {tenantLabel}
              {principal.method === 'oidc' ? ' · SSO' : ''}
            </div>
          </div>
          {ownAccount && (
            <MenuItem icon={<Lock className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />} onSelect={run(() => navigate('/account'), false)}>
              Account security
            </MenuItem>
          )}
          <div role="group" aria-label="Theme" className="my-0.5 border-y border-strong py-0.5">
            {THEMES.map((t) => (
              <MenuItem key={t.value} role="menuitemradio" checked={preference === t.value} onSelect={() => setPreference(t.value)}>
                {t.label}
              </MenuItem>
            ))}
          </div>
          <MenuItem
            role="menuitemcheckbox"
            checked={density === 'comfortable'}
            icon={<Rows3 className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />}
            onSelect={() => setDensity(density === 'comfortable' ? 'compact' : 'comfortable')}
          >
            Comfortable rows
          </MenuItem>
          <MenuItem icon={<LogOut className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />} onSelect={run(onSignOut, false)}>
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
  role?: 'menuitem' | 'menuitemradio' | 'menuitemcheckbox';
  checked?: boolean;
  icon?: ReactNode;
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
      {checkable && icon && <span className="flex-none text-secondary">{icon}</span>}
    </button>
  );
}
