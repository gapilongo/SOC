/** The small marks of a queue row: severity as bars and a word, the outcome so far, the deadline. Shape and word first; colour repeats them. */

import { cx } from '../../components/ui';
import { OUTCOME_TEXT, severityBars, type Due, type Outcome } from './model';

const BAR_HEIGHT = ['h-[4px]', 'h-[6.5px]', 'h-[9px]', 'h-[12px]'];

const BAR_ON: Record<string, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
};

/** Severity: four bars (critical lights all, info none) and the word; critical and high in bold. */
export function SeverityBars({ value, className }: { value: string | null | undefined; className?: string }) {
  if (!value) return <span className="text-muted">-</span>;
  const lit = severityBars(value);
  return (
    <span
      data-severity={value}
      className={cx('inline-flex items-center gap-1.5 whitespace-nowrap capitalize', lit >= 3 ? 'font-semibold text-fg' : 'text-body', className)}
    >
      <span className="flex h-3 flex-none items-end gap-px" aria-hidden="true">
        {BAR_HEIGHT.map((h, i) => (
          <span key={h} className={cx('w-[3px]', h, i < lit ? BAR_ON[value] : 'bg-strong')} />
        ))}
      </span>
      {value}
    </span>
  );
}

const OUTCOME_COLOR: Record<Outcome, string> = { threat: 'text-state-bad', review: 'text-state-waiting' };

function OutcomeGlyph({ outcome, label }: { outcome: Outcome; label?: string }) {
  return (
    <svg
      viewBox="0 0 12 12"
      className={cx('h-3 w-3 flex-none', OUTCOME_COLOR[outcome])}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      {label && <title>{label}</title>}
      {outcome === 'threat' ? (
        <>
          <path fill="currentColor" d="M6 .4 11.6 6 6 11.6.4 6z" />
          <path className="stroke-canvas" d="M6 3.2v3.2M6 8.4v.2" strokeWidth="1.5" strokeLinecap="round" />
        </>
      ) : (
        <path fill="none" stroke="currentColor" strokeWidth="1.6" d="M6 1.3 10.7 6 6 10.7 1.3 6z" />
      )}
    </svg>
  );
}

/**
 * What the analysis made of the item so far: a filled diamond (likely
 * malicious) or an open one (not proven either way). `text`: 'none' shows the
 * mark alone (it then carries the words as its name), 'short' and 'long' add
 * them beside it.
 */
export function OutcomeMark({ outcome, text = 'short', className }: { outcome: Outcome | null; text?: 'none' | 'short' | 'long'; className?: string }) {
  if (!outcome) return <span className="text-muted">-</span>;
  const words = OUTCOME_TEXT[outcome];
  return (
    <span data-outcome={outcome} className={cx('inline-flex items-center gap-1.5 whitespace-nowrap text-body', className)}>
      <OutcomeGlyph outcome={outcome} label={text === 'none' ? words.short : undefined} />
      {text !== 'none' && words[text]}
    </span>
  );
}

/** Time to the deadline. Overdue and under ten minutes are bold in the danger colour and say so in words. */
export function DueIn({ due, className }: { due: Due; className?: string }) {
  const hot = due.state === 'overdue' || due.state === 'soon';
  return (
    <span
      data-due={due.state}
      title={due.label}
      className={cx('whitespace-nowrap font-mono tabular-nums', hot ? 'font-semibold text-danger-fg' : due.state === 'none' ? 'text-muted' : 'font-medium text-body', className)}
    >
      {due.text}
      {due.state === 'soon' && (
        <>
          <span aria-hidden="true"> !</span>
          <span className="sr-only"> due soon</span>
        </>
      )}
    </span>
  );
}
