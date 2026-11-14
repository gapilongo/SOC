/**
 * The 12 px marks of the investigation view. Shape carries the meaning and
 * the word next to it repeats it; colour only repeats both. Every glyph is
 * decorative (`aria-hidden`): the text beside it is the accessible name.
 */

import type { ReactNode } from 'react';

import { cx } from '../ui';

export type GlyphName =
  | 'threat'
  | 'review'
  | 'backed'
  | 'audit'
  | 'approval'
  | 'run'
  | 'rule'
  | 'cached'
  | 'person'
  | 'empty'
  | 'not'
  | 'cannot'
  | 'up'
  | 'down'
  | 'tick';

const CANVAS = 'rgb(var(--c-canvas))';

const PATHS: Record<GlyphName, ReactNode> = {
  threat: (
    <>
      <path fill="currentColor" d="M6 .4 11.6 6 6 11.6.4 6z" />
      <path d="M6 3.2v3.2M6 8.4v.2" stroke={CANVAS} strokeWidth="1.5" strokeLinecap="round" />
    </>
  ),
  review: <path fill="none" stroke="currentColor" strokeWidth="1.6" d="M6 1.3 10.7 6 6 10.7 1.3 6z" />,
  backed: (
    <>
      <rect x=".8" y=".8" width="10.4" height="10.4" fill="currentColor" />
      <path d="M3.2 6.2l2 2 3.6-4.2" fill="none" stroke={CANVAS} strokeWidth="1.6" />
    </>
  ),
  audit: (
    <>
      <rect x="1.3" y="1.3" width="9.4" height="9.4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="2.2 1.6" />
      <path d="M3.6 6.2l1.7 1.7 3-3.6" fill="none" stroke="currentColor" strokeWidth="1.5" />
    </>
  ),
  approval: (
    <>
      <circle cx="6" cy="6" r="4.7" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="6" cy="6" r="1.8" fill="currentColor" />
    </>
  ),
  run: (
    <>
      <circle cx="6" cy="6" r="4.7" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <path d="M6 1.3a4.7 4.7 0 0 1 0 9.4z" fill="currentColor" />
    </>
  ),
  rule: <path fill="currentColor" d="M.8 1.5h10.4L7.3 6.3v4.6L4.7 9.6V6.3z" />,
  cached: <path fill="none" stroke="currentColor" strokeWidth="1.5" d="M3.8 3.8V1.2h7v7H8.2M1.2 3.8h7v7h-7z" />,
  person: (
    <>
      <circle cx="6" cy="3.6" r="2.6" fill="currentColor" />
      <path fill="currentColor" d="M1 11.5c0-2.8 2.2-4.4 5-4.4s5 1.6 5 4.4z" />
    </>
  ),
  empty: <circle cx="6" cy="6" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.6" />,
  not: <circle cx="6" cy="6" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="2.4 2.2" />,
  cannot: (
    <>
      <circle cx="6" cy="6" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <path d="M2.8 9.2l6.4-6.4" stroke="currentColor" strokeWidth="1.6" />
    </>
  ),
  up: <path fill="currentColor" d="M6 1.2 11.3 10.6H.7z" />,
  down: <path fill="none" stroke="currentColor" strokeWidth="1.6" d="M6 10.2 1.8 2.4h8.4z" />,
  tick: <path d="M1.8 6.4l2.8 2.8 5.6-6.4" fill="none" stroke="currentColor" strokeWidth="1.8" />,
};

export function Glyph({ name, className }: { name: GlyphName; className?: string }) {
  return (
    <svg viewBox="0 0 12 12" aria-hidden="true" focusable="false" data-glyph={name} className={cx('h-3 w-3 flex-none', className)}>
      {PATHS[name]}
    </svg>
  );
}
