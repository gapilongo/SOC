import { Loader2 } from 'lucide-react';
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

import { cx } from './cx';

export type ButtonVariant = 'primary' | 'secondary' | 'quiet' | 'destructive';
export type ButtonSize = 'sm' | 'md' | 'lg';

const VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-accent font-semibold text-on-accent enabled:hover:bg-accent-hover',
  secondary: 'border border-control bg-raised font-medium text-fg enabled:hover:bg-raised-2',
  quiet: 'bg-transparent font-medium text-link enabled:hover:bg-raised-2 enabled:hover:text-link-hover',
  destructive: 'border border-danger bg-raised font-semibold text-danger-fg enabled:hover:bg-tint-danger',
};

// 32 / 36 / 40 px; every size grows to 44 px on touch screens.
const SIZES: Record<ButtonSize, { box: string; square: string }> = {
  sm: { box: 'min-h-8 px-3 py-1 text-ctl', square: 'h-8 w-8 flex-none' },
  md: { box: 'min-h-9 px-3.5 py-1.5 text-sm', square: 'h-9 w-9 flex-none' },
  lg: { box: 'min-h-10 px-4 py-2 text-sm', square: 'h-10 w-10 flex-none' },
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  busy?: boolean;
  icon?: ReactNode;
}

/**
 * Buttons: primary (one per view), secondary, quiet (link-like) and
 * destructive. Disabled buttons are dimmed and keep no hover state. A button
 * with an icon and no text is square; give it an aria-label.
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
        'inline-flex items-center justify-center gap-2 rounded-control transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-50 touch:min-h-11',
        iconOnly ? cx(SIZES[size].square, 'touch:min-w-11') : SIZES[size].box,
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
