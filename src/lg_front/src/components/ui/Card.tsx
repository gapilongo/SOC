import { AlertTriangle, Info } from 'lucide-react';
import type { ReactNode } from 'react';

import { cx } from './cx';

export type CardVariant = 'default' | 'attention' | 'approval';

const CARD_BAR: Record<CardVariant, string> = {
  default: '',
  // Work waiting on a human: amber bar only.
  attention: 'shadow-bar-attention pl-[3px]',
  // Containment waiting for approval: violet bar only.
  approval: 'shadow-bar-approval pl-[3px]',
};

/** A raised panel (radius 12). Attention and approval cards carry a 3 px inset bar. */
export function Card({
  title,
  actions,
  children,
  className,
  variant = 'default',
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  variant?: CardVariant;
}) {
  return (
    <section className={cx('rounded-card border border-subtle bg-raised', CARD_BAR[variant], className)} data-variant={variant === 'default' ? undefined : variant}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle px-4 py-3">
          {title && <h2 className="text-sm font-semibold text-fg">{title}</h2>}
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
        <h1 className="text-xl font-semibold text-fg">{title}</h1>
        {description && <p className="mt-0.5 max-w-3xl text-ctl text-secondary">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export type BannerTone = 'warning' | 'attention' | 'info';

const BANNER_BAR: Record<BannerTone, string> = {
  warning: 'shadow-bar-warning',
  attention: 'shadow-bar-attention',
  info: 'shadow-bar-info',
};

/**
 * An inline notice on the raised-2 surface with a 3 px bar: simulated
 * evidence, conflicts, blocked guardrails (warning); work waiting (attention);
 * context (info). The icon and the title carry the meaning, not the bar colour.
 */
export function Banner({
  tone = 'warning',
  title,
  children,
  actions,
  role,
  className,
}: {
  tone?: BannerTone;
  title?: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  role?: 'status' | 'alert' | 'note';
  className?: string;
}) {
  const Icon = tone === 'info' ? Info : AlertTriangle;
  return (
    <div role={role} data-tone={tone} className={cx('flex items-start gap-2.5 rounded-control bg-raised-2 py-3 pl-[15px] pr-3', BANNER_BAR[tone], className)}>
      <Icon className="mt-px h-4 w-4 flex-none text-secondary" strokeWidth={1.75} aria-hidden="true" />
      <div className="min-w-0 flex-1">
        {title && <p className="text-ctl font-semibold text-fg">{title}</p>}
        {children && <div className="text-xs text-body">{children}</div>}
      </div>
      {actions && <div className="flex flex-none flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
