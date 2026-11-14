/**
 * What the investigation did: a log of actions in plain words, each marked
 * with who acted (code, the model, a check or the policy, a person). It is
 * not the model's reasoning, and it never shows an engine node name.
 */

import { Fragment } from 'react';

import type { StepOut } from '../../api/investigation';
import { formatDateTime } from '../../../../lib/format';
import { clockOf } from './clock';
import { VoiceMark, type Voice } from './voices';

const ACTOR: Record<string, { voice: Voice; label: string }> = {
  code: { voice: 'observed', label: 'Code' },
  model: { voice: 'claimed', label: 'Model' },
  check: { voice: 'decided', label: 'Check' },
  policy: { voice: 'decided', label: 'Policy' },
  person: { voice: 'person', label: 'Person' },
};

export function StepList({
  steps,
  hideModelOutput = false,
}: {
  steps: StepOut[];
  /** The verdict is hidden: what a model step produced (its assessment) is withheld with it. */
  hideModelOutput?: boolean;
}) {
  return (
    <ol>
      {steps.map((step, i) => {
        const at = clockOf(step.ts);
        const date = at?.day ?? step.ts;
        const actor = ACTOR[step.actor] ?? ACTOR.code;
        const newDay = i === 0 || (clockOf(steps[i - 1].ts)?.day ?? steps[i - 1].ts) !== date;
        const produced = hideModelOutput && step.actor === 'model' ? null : step.produced;
        return (
          <Fragment key={`${step.ts}-${i}`}>
            {newDay && <li className="pb-0.5 pt-2 font-mono text-2xs uppercase tracking-[0.05em] text-muted first:pt-0">{date}</li>}
            <li
              data-actor={step.actor}
              className="grid grid-cols-[58px_14px_minmax(0,1fr)] items-baseline gap-x-2 border-b border-subtle py-[5px] text-ctl min-[900px]:grid-cols-[62px_16px_minmax(0,1fr)_auto]"
            >
              <time dateTime={step.ts} title={formatDateTime(step.ts)} className="font-mono text-[11.5px] leading-normal text-muted">
                {at?.time ?? '-'}
              </time>
              <span className="flex h-2 items-center justify-center self-center">
                <VoiceMark voice={actor.voice} className="h-2 w-2" />
                <span className="sr-only">{actor.label}: </span>
              </span>
              <span className="min-w-0 break-words text-body">{step.text}</span>
              {produced && (
                <span className="col-start-3 break-words font-mono text-[11.5px] leading-normal text-secondary min-[900px]:col-start-auto min-[900px]:max-w-[26rem] min-[900px]:text-right">
                  {produced}
                </span>
              )}
            </li>
          </Fragment>
        );
      })}
    </ol>
  );
}
