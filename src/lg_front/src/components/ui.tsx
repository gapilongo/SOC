import { AlertTriangle, Inbox, Loader2, RefreshCw } from 'lucide-react';
import {
  forwardRef,
  useId,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';

import { describeError } from '../api/client';

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-sky-600 text-white hover:bg-sky-500 disabled:bg-sky-900 disabled:text-slate-400',
  secondary:
    'bg-slate-800 text-slate-100 border border-slate-600 hover:bg-slate-700 disabled:text-slate-500 disabled:hover:bg-slate-800',
  danger: 'bg-red-700 text-white hover:bg-red-600 disabled:bg-red-950 disabled:text-slate-400',
  ghost: 'text-slate-200 hover:bg-slate-800 disabled:text-slate-500',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: 'sm' | 'md';
  busy?: boolean;
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', busy = false, icon, className, children, disabled, type = 'button', ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={cx(
        'inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400',
        'disabled:cursor-not-allowed',
        size === 'sm' ? 'px-2.5 py-1 text-xs' : 'px-3.5 py-2 text-sm',
        VARIANTS[variant],
        className,
      )}
      {...rest}
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : icon}
      {children}
    </button>
  );
});

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cx('rounded-lg border border-slate-800 bg-slate-900', className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-3">
          {title && <h2 className="text-sm font-semibold text-slate-100">{title}</h2>}
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-white">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-slate-300">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <span role="status" className="inline-flex items-center gap-2 text-sm text-slate-300">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
      {label}
    </span>
  );
}

export function LoadingState({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center py-12">
      <Spinner label={label} />
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <Inbox className="h-8 w-8 text-slate-500" aria-hidden="true" />
      <p className="text-sm font-medium text-slate-200">{title}</p>
      {children && <div className="max-w-md text-sm text-slate-400">{children}</div>}
    </div>
  );
}

/** API error display: the message, validation details and the request id for support. */
export function ErrorMessage({ error, onRetry, compact = false }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const { message, requestId, details } = describeError(error);
  return (
    <div
      role="alert"
      className={cx('rounded-md border border-red-800 bg-red-950/60 text-sm text-red-100', compact ? 'px-3 py-2' : 'p-4')}
    >
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-4 w-4 flex-none text-red-300" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p>{message}</p>
          {details.length > 0 && (
            <ul className="mt-1 list-disc pl-5 text-red-200">
              {details.map((d, i) => (
                <li key={i}>{d}</li>
              ))}
            </ul>
          )}
          {requestId && (
            <p className="mt-1 text-xs text-red-200/80">
              Request ID: <span className="select-all font-mono">{requestId}</span>
            </p>
          )}
        </div>
        {onRetry && (
          <Button size="sm" variant="ghost" onClick={onRetry} icon={<RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />}>
            Retry
          </Button>
        )}
      </div>
    </div>
  );
}

const FIELD_CLASS =
  'block w-full rounded-md border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 ' +
  'focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400 disabled:opacity-60';

interface FieldShellProps {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  className?: string;
  children: (ids: { id: string; describedBy: string | undefined }) => ReactNode;
}

export function FieldShell({ label, hint, error, className, children }: FieldShellProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(' ') || undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-slate-300">
        {label}
      </label>
      {children({ id, describedBy })}
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-slate-400">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="mt-1 text-xs text-red-300">
          {error}
        </p>
      )}
    </div>
  );
}

type InputProps = InputHTMLAttributes<HTMLInputElement> & { label: ReactNode; hint?: ReactNode; error?: string | null; wrapperClassName?: string };

export const TextField = forwardRef<HTMLInputElement, InputProps>(function TextField(
  { label, hint, error, wrapperClassName, className, ...rest },
  ref,
) {
  return (
    <FieldShell label={label} hint={hint} error={error} className={wrapperClassName}>
      {({ id, describedBy }) => (
        <input
          ref={ref}
          id={id}
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
          className={cx(FIELD_CLASS, className)}
          {...rest}
        />
      )}
    </FieldShell>
  );
});

type SelectProps = SelectHTMLAttributes<HTMLSelectElement> & { label: ReactNode; hint?: ReactNode; error?: string | null; wrapperClassName?: string };

export function SelectField({ label, hint, error, wrapperClassName, className, children, ...rest }: SelectProps) {
  return (
    <FieldShell label={label} hint={hint} error={error} className={wrapperClassName}>
      {({ id, describedBy }) => (
        <select id={id} aria-describedby={describedBy} className={cx(FIELD_CLASS, className)} {...rest}>
          {children}
        </select>
      )}
    </FieldShell>
  );
}

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & { label: ReactNode; hint?: ReactNode; error?: string | null; wrapperClassName?: string };

export function TextAreaField({ label, hint, error, wrapperClassName, className, ...rest }: TextareaProps) {
  return (
    <FieldShell label={label} hint={hint} error={error} className={wrapperClassName}>
      {({ id, describedBy }) => (
        <textarea
          id={id}
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
          className={cx(FIELD_CLASS, 'font-mono', className)}
          {...rest}
        />
      )}
    </FieldShell>
  );
}

export function Checkbox({ label, hint, className, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode; hint?: ReactNode }) {
  const id = useId();
  return (
    <div className={cx('flex items-start gap-2', className)}>
      <input
        id={id}
        type="checkbox"
        className="mt-0.5 h-4 w-4 rounded border-slate-500 bg-slate-950 text-sky-500 focus:ring-sky-400"
        aria-describedby={hint ? `${id}-hint` : undefined}
        {...rest}
      />
      <div>
        <label htmlFor={id} className="text-sm text-slate-200">
          {label}
        </label>
        {hint && (
          <p id={`${id}-hint`} className="text-xs text-slate-400">
            {hint}
          </p>
        )}
      </div>
    </div>
  );
}

/** A group of toggle buttons for multi-valued filters (`?status=a&status=b`). */
export function ToggleGroup({
  label,
  options,
  value,
  onChange,
  format = (v) => v.replace(/_/g, ' '),
}: {
  label: string;
  options: readonly string[];
  value: string[];
  onChange: (next: string[]) => void;
  format?: (v: string) => string;
}) {
  return (
    <fieldset>
      <legend className="mb-1 text-xs font-medium text-slate-300">{label}</legend>
      <div className="flex flex-wrap gap-1">
        {options.map((opt) => {
          const on = value.includes(opt);
          return (
            <button
              key={opt}
              type="button"
              aria-pressed={on}
              onClick={() => onChange(on ? value.filter((v) => v !== opt) : [...value, opt])}
              className={cx(
                'rounded-full border px-2.5 py-0.5 text-xs capitalize focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400',
                on ? 'border-sky-400 bg-sky-900 text-sky-50' : 'border-slate-600 text-slate-300 hover:bg-slate-800',
              )}
            >
              {format(opt)}
            </button>
          );
        })}
      </div>
    </fieldset>
  );
}

export function JsonBlock({ value, label }: { value: unknown; label: string }) {
  return (
    <pre
      role="region"
      aria-label={label}
      // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
      tabIndex={0}
      className="max-h-80 overflow-auto rounded-md border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-200 focus:outline focus:outline-2 focus:outline-sky-400"
    >
      {JSON.stringify(value ?? null, null, 2)}
    </pre>
  );
}

export function DefinitionList({ items }: { items: Array<[ReactNode, ReactNode]> }) {
  return (
    <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-slate-400">{k}</dt>
          <dd className="min-w-0 break-words text-slate-100">{v ?? '-'}</dd>
        </div>
      ))}
    </dl>
  );
}
