/**
 * The three voices of an investigation, never mixed:
 *
 *   observed  a tool returned it     filled square, monospace on the recessed surface
 *   claimed   the model wrote it     ring, plain text
 *   decided   a check, the policy    diamond
 *             or a person            filled dot in the accent colour
 *
 * The same marks label the claims, the steps and the decision, so a reader
 * always knows who is speaking.
 */

import type { ReactNode } from 'react';

import { cx } from '../ui';

export type Voice = 'observed' | 'claimed' | 'decided' | 'person';

const MARK: Record<Voice, string> = {
  observed: 'bg-control',
  claimed: 'rounded-full border-1.5 border-control',
  decided: 'rotate-45 scale-90 bg-fg',
  person: 'rounded-full bg-accent',
};

/** The 7 px mark of a voice (decorative: the words beside it say who speaks). */
export function VoiceMark({ voice, className }: { voice: Voice; className?: string }) {
  return <span aria-hidden="true" data-voice={voice} className={cx('inline-block h-2 w-2 flex-none', MARK[voice], className)} />;
}

/** A voice label: the mark and who speaks, in small capitals. */
export function VoiceTag({ voice, children, className }: { voice: Voice; children: ReactNode; className?: string }) {
  return (
    <span className={cx('inline-flex items-center gap-1 whitespace-nowrap font-mono text-2xs font-medium uppercase leading-none tracking-label text-muted', className)}>
      <VoiceMark voice={voice} />
      {children}
    </span>
  );
}

const KEYCAP: Record<'plain' | 'inverse' | 'on-accent', string> = {
  plain: 'border-strong bg-canvas text-secondary',
  inverse: 'border-canvas/50 bg-transparent text-canvas',
  'on-accent': 'border-on-accent/50 bg-transparent text-on-accent',
};

/** A key of the keyboard, as printed on it; `inverse` on a pressed (dark) button, `on-accent` on a primary one. */
export function Keycap({ children, tone = 'plain', className }: { children: ReactNode; tone?: 'plain' | 'inverse' | 'on-accent'; className?: string }) {
  return (
    <kbd
      className={cx(
        // Size and face come from the base `kbd` rule (index.css); the tone sets the colours.
        'border-b-2',
        KEYCAP[tone],
        className,
      )}
    >
      {children}
    </kbd>
  );
}

/** A small fact about the alert: a label and its value (the value in the foreground colour). */
export function FactChip({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <span className="inline-flex min-h-ctl-sm max-w-full items-center gap-1 rounded-tag bg-raised-2 px-1.5 text-xs text-secondary">
      {label}
      <b className={cx('min-w-0 break-all font-semibold text-fg', mono && 'font-mono text-2xs')}>{children}</b>
    </span>
  );
}

/** A small bordered label in capitals ("Decoded by code", "Simulated"). */
export function SmallTag({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'warn' }) {
  return (
    <span
      className={cx(
        'whitespace-nowrap rounded-tag px-1 py-0.5 font-mono text-2xs font-medium uppercase leading-none tracking-label',
        tone === 'warn' ? 'bg-tint-warn text-warn-fg' : 'border border-strong text-secondary',
      )}
    >
      {children}
    </span>
  );
}
