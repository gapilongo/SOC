import { Loader2 } from 'lucide-react';
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

import { cx } from './cx';

export type ButtonVariant = 'primary' | 'secondary' | 'quiet' | 'destructive';
export type ButtonSize = 'sm' | 'md' | 'lg';

const VARIANTS: Record<ButtonVariant, string> = {
  primary: 'border border-accent bg-accent text-on-accent enabled:hover:border-accent-hover enabled:hover:bg-accent-hover',
  secondary: 'border border-control bg-raised text-fg enabled:hover:bg-raised-2',
  quiet: 'border border-transparent bg-transparent text-secondary enabled:hover:bg-raised-2 enabled:hover:text-fg',
  destructive: 'border border-danger bg-raised text-danger-fg enabled:hover:bg-tint-danger',
};

// 24 px (inside a table row), 28 px (the default), 36 px (the one primary action); every size grows to 44 px on touch screens.
const SIZES: Record<ButtonSize, { box: string; square: string }> = {
  sm: { box: 'min-h-ctl-sm px-2 text-xs', square: 'h-ctl-sm w-ctl-sm flex-none' },
  md: { box: 'min-h-ctl px-2.5 text-ctl', square: 'h-ctl w-ctl flex-none' },
  lg: { box: 'min-h-ctl-lg px-3.5 text-sm', square: 'h-ctl-lg w-ctl-lg flex-none' },
};

const BASE = 'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-control font-medium transition-colors touch:min-h-ctl-touch';

/**
 * The classes of a button, for a link that looks like one (navigation stays a
 * link: `<Link className={buttonClass('primary')}>`).
 */
export function buttonClass(variant: ButtonVariant = 'secondary', size: ButtonSize = 'md', className?: string): string {
  return cx(BASE, SIZES[size].box, LINK_VARIANTS[variant], className);
}

// The variants without `enabled:` (a link has no disabled state); spelled out so Tailwind sees each class.
const LINK_VARIANTS: Record<ButtonVariant, string> = {
  primary: 'border border-accent bg-accent text-on-accent hover:border-accent-hover hover:bg-accent-hover hover:text-on-accent',
  secondary: 'border border-control bg-raised text-fg hover:bg-raised-2',
  quiet: 'border border-transparent bg-transparent text-secondary hover:bg-raised-2 hover:text-fg',
  destructive: 'border border-danger bg-raised text-danger-fg hover:bg-tint-danger',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  busy?: boolean;
  icon?: ReactNode;
}

/**
 * Buttons: primary (one per view), secondary, quiet (no border until hovered)
 * and destructive. Disabled buttons are dimmed and keep no hover state. A
 * button with an icon and no text is square; give it an aria-label.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', busy = false, icon, className, children, disabled, type = 'button', ...rest },
  ref,
) {
  const iconOnly = children === undefined || children === null || children === false;
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={cx(
        BASE,
        'disabled:cursor-not-allowed disabled:opacity-55',
        iconOnly ? cx(SIZES[size].square, 'touch:min-w-ctl-touch') : SIZES[size].box,
        VARIANTS[variant],
        className,
      )}
      {...rest}
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" strokeWidth={1.75} aria-hidden="true" /> : icon}
      {children}
    </button>
  );
});
