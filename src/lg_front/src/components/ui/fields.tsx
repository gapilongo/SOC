import {
  forwardRef,
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';

import { cx } from './cx';

/** Shared look of text inputs, selects and text areas: 36 px, 44 px on touch screens. */
export const FIELD_CLASS =
  'block w-full rounded-control border border-control bg-canvas px-3 text-ctl text-fg placeholder:text-muted ' +
  'focus:border-focus focus:outline-none focus:ring-1 focus:ring-focus disabled:cursor-not-allowed disabled:opacity-60';

const SINGLE_LINE = 'h-9 touch:min-h-11';

interface FieldShellProps {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  className?: string;
  children: (ids: { id: string; describedBy: string | undefined }) => ReactNode;
}

/** A labelled field: label above, hint and error below, wired with aria-describedby. */
export function FieldShell({ label, hint, error, className, children }: FieldShellProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(' ') || undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1.5 block text-ctl font-semibold text-fg">
        {label}
      </label>
      {children({ id, describedBy })}
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-secondary">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="mt-1 text-xs text-danger-fg">
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
          className={cx(FIELD_CLASS, SINGLE_LINE, className)}
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
        <select id={id} aria-describedby={describedBy} className={cx(FIELD_CLASS, SINGLE_LINE, className)} {...rest}>
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
          className={cx(FIELD_CLASS, 'py-2 font-mono', className)}
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
        className="mt-0.5 h-4 w-4 flex-none rounded border-control bg-canvas accent-accent"
        aria-describedby={hint ? `${id}-hint` : undefined}
        {...rest}
      />
      <div>
        <label htmlFor={id} className="text-sm text-body">
          {label}
        </label>
        {hint && (
          <p id={`${id}-hint`} className="text-xs text-secondary">
            {hint}
          </p>
        )}
      </div>
    </div>
  );
}
