import { AlertTriangle, Info } from 'lucide-react';
import type { ReactNode } from 'react';

import { cx } from './cx';

export type CardVariant = 'default' | 'attention' | 'approval';

const CARD_BAR: Record<CardVariant, string> = {
  default: '',
  // Work waiting on a human: amber bar only.
  attention: 'shadow-bar-attention pl-3',
  // Containment waiting for approval: violet bar only.
  approval: 'shadow-bar-approval pl-3',
};

/**
 * A section of the sheet: no box and no background. Its title sits over a
 * rule; without a title the rule opens the section. Attention and approval
 * sections carry a 2 px bar on the left.
 */
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
  const headed = Boolean(title || actions);
  return (
    <section className={cx('min-w-0', !headed && 'border-t border-strong', CARD_BAR[variant], className)} data-variant={variant === 'default' ? undefined : variant}>
      {headed && (
        <header className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 border-b border-strong pb-2">
          {title && <h2 className="text-base font-semibold text-fg">{title}</h2>}
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="py-3">{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
      {/* The text takes the room the actions leave, so the actions stay on the right instead of dropping below a long description. */}
      <div className="flex min-w-[min(20rem,100%)] flex-1 flex-wrap items-baseline gap-x-4 gap-y-1">
        <h1 className="text-xl font-semibold text-fg">{title}</h1>
        {description && <p className="max-w-3xl flex-1 basis-80 text-ctl text-secondary">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export type BannerTone = 'warning' | 'attention' | 'info';

const BANNER_TINT: Record<BannerTone, string> = {
  warning: 'bg-tint-warn shadow-bar-warning',
  attention: 'bg-tint-warn',
  info: 'bg-tint-info',
};

/**
 * An inline notice on a tint: simulated evidence, conflicts, blocked
 * guardrails (warning, with a bar); work waiting (attention); context (info).
 * The icon and the title carry the meaning, not the colour.
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
    <div role={role} data-tone={tone} className={cx('flex flex-wrap items-start gap-x-2.5 gap-y-2 rounded-tag px-3 py-2', BANNER_TINT[tone], className)}>
      <Icon className="mt-0.5 h-4 w-4 flex-none text-secondary" strokeWidth={1.5} aria-hidden="true" />
      <div className="min-w-0 flex-1 basis-48">
        {title && <p className="text-ctl font-semibold text-fg">{title}</p>}
        {children && <div className="text-ctl text-body">{children}</div>}
      </div>
      {actions && <div className="flex flex-none flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
