/**
 * Claimed: one statement of the model (or, marked as such, of the rules),
 * beside the observations it rests on. The check is always visible: backed by named observations, rejected
 * by the checker (struck through, with the reason) or unsupported (no fact
 * cited). With the verdict hidden only the number and the observations stay.
 */

import type { ReactNode } from 'react';

import type { InvestigationClaimOut } from '../../api/types';
import { cx } from '../../../../components/ui';
import { Glyph } from './glyphs';
import { VoiceTag } from './voices';

function Stance({ direction }: { direction: InvestigationClaimOut['direction'] }) {
  if (direction !== 'malicious' && direction !== 'benign') return null;
  const malicious = direction === 'malicious';
  return (
    <span className="inline-flex items-center gap-1 text-xs text-secondary">
      <Glyph name={malicious ? 'up' : 'down'} className={cx('h-2.5 w-2.5', malicious ? 'text-state-bad' : 'text-state-ok')} />
      {malicious ? 'Points to malicious' : 'Points to benign'}
    </span>
  );
}

function Check({ claim }: { claim: InvestigationClaimOut }) {
  if (claim.check === 'supported') {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-ok-fg">
        <Glyph name="tick" />
        Backed by {claim.observation_ids.length ? claim.observation_ids.join(', ') : 'an observation'}
      </span>
    );
  }
  if (claim.check === 'rejected') {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-danger-fg">
        <Glyph name="cannot" />
        Rejected by the checker
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-warn-fg">
      <Glyph name="not" />
      Unsupported
    </span>
  );
}

export function ClaimRow({
  claim,
  number,
  selected = false,
  hidden = false,
  onSelect,
  children,
}: {
  claim: InvestigationClaimOut;
  /** The claim's number on the page (also its keyboard shortcut). */
  number: number;
  selected?: boolean;
  /** The verdict is hidden: the claim's text, direction and check are withheld, the observations stay. */
  hidden?: boolean;
  onSelect?: () => void;
  /** The observations the claim rests on. */
  children?: ReactNode;
}) {
  const rejected = claim.check === 'rejected';
  return (
    <div
      data-claim={claim.id}
      data-check={hidden ? undefined : claim.check}
      className={cx(
        'relative grid grid-cols-[26px_minmax(0,1fr)] gap-x-2.5 gap-y-2 border-b border-subtle py-3',
        'min-[900px]:grid-cols-[26px_minmax(0,0.7fr)_minmax(0,1.3fr)] min-[900px]:gap-x-4 min-[900px]:gap-y-0',
        selected && 'before:absolute before:inset-y-0 before:-left-3.5 before:w-0.5 before:bg-accent',
      )}
    >
      <button
        type="button"
        aria-label={`Claim ${number}, select`}
        aria-pressed={selected}
        onClick={onSelect}
        className={cx(
          'grid h-6 w-6 place-items-center rounded-tag border font-mono text-xs font-semibold leading-none',
          selected ? 'border-fg bg-fg text-canvas' : 'border-strong text-fg hover:bg-raised-2',
        )}
      >
        {number}
      </button>
      {!hidden && (
        <div className="min-w-0">
          <p className={cx('break-words text-sm leading-snug', rejected ? 'text-secondary line-through decoration-control' : 'text-fg')}>{claim.text}</p>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-2.5 gap-y-1.5 text-xs text-muted">
            {claim.written_by === 'rules' && <VoiceTag voice="decided">Stated by the rules</VoiceTag>}
            <Stance direction={claim.direction} />
            <Check claim={claim} />
          </div>
          {claim.check !== 'supported' && claim.check_reason && <p className="mt-1.5 text-xs text-muted">{claim.check_reason}</p>}
        </div>
      )}
      <div className={cx('col-span-full flex min-w-0 flex-col gap-1.5', hidden ? 'min-[900px]:col-span-2 min-[900px]:col-start-2' : 'min-[900px]:col-span-1')}>
        {children ?? <p className="text-xs text-muted">No observation is cited for this claim.</p>}
      </div>
    </div>
  );
}
