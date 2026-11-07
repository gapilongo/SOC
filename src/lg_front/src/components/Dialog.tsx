import { X } from 'lucide-react';
import { useId, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

import { Button, cx } from './ui';
import { useFocusTrap } from './useFocusTrap';

/**
 * Modal surface (centered dialog or side drawer): traps focus, closes on
 * Escape, restores focus to the element that opened it, and hides the
 * background from assistive technology via aria-modal.
 */
export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  variant = 'dialog',
  size = 'md',
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  variant?: 'dialog' | 'drawer';
  size?: 'sm' | 'md' | 'lg' | 'xl';
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descId = useId();
  useFocusTrap(panelRef, open, { onEscape: onClose, lockScroll: true });

  if (!open) return null;

  const widths = { sm: 'max-w-md', md: 'max-w-xl', lg: 'max-w-3xl', xl: 'max-w-5xl' };
  const panelClass =
    variant === 'drawer'
      ? cx('fixed inset-y-0 right-0 flex w-full flex-col border-l border-strong bg-raised shadow-2xl', widths[size])
      : cx('relative mx-4 flex max-h-[90vh] w-full flex-col rounded-card border border-strong bg-raised shadow-2xl', widths[size]);

  return createPortal(
    <div className={cx('fixed inset-0 z-50 flex', variant === 'dialog' && 'items-center justify-center')}>
      <div className="absolute inset-0 bg-black/60" aria-hidden="true" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        tabIndex={-1}
        className={cx(panelClass, 'focus:outline-none')}
      >
        <header className="flex items-start justify-between gap-3 border-b border-subtle px-5 py-4">
          <div className="min-w-0">
            <h2 id={titleId} className="break-words text-base font-semibold text-fg">
              {title}
            </h2>
            {description && (
              <div id={descId} className="mt-1 text-sm text-secondary">
                {description}
              </div>
            )}
          </div>
          <Button variant="quiet" size="sm" aria-label="Close" onClick={onClose} icon={<X className="h-4 w-4" aria-hidden="true" />} />
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        {footer && <footer className="flex flex-wrap justify-end gap-2 border-t border-subtle px-5 py-3">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  danger = false,
  busy = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={title}
      size="sm"
      footer={
        <>
          <Button onClick={onCancel} data-autofocus>
            Cancel
          </Button>
          <Button variant={danger ? 'destructive' : 'primary'} busy={busy} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="text-sm text-body">{children}</div>
    </Modal>
  );
}
