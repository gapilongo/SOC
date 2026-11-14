/**
 * The bar over the list while rows are selected. Claim works on any
 * selection. Deciding several at once is offered only for one look-alike
 * group: rows that differ each need their own decision.
 */

import { useState } from 'react';

import { BULK_MAX_ITEMS, type EscalationOut } from '../../api/types';
import { ErrorMessage } from '../../components/ui';
import { CloseDialog, type BulkResult } from '../escalations/BulkActions';
import { QButton } from './controls';
import { sharedLookAlike } from './model';

export function BatchBar({
  selected,
  capped,
  claiming,
  claimError,
  onClaim,
  onClear,
  onResult,
}: {
  selected: EscalationOut[];
  /** More rows were asked for than one bulk request takes. */
  capped: boolean;
  claiming: boolean;
  claimError: unknown;
  onClaim: () => void;
  onClear: () => void;
  onResult: (r: BulkResult) => void;
}) {
  const [deciding, setDeciding] = useState(false);
  const n = selected.length;
  const group = sharedLookAlike(selected);

  return (
    <div role="region" aria-label="Bulk actions" className="flex flex-col gap-2 py-0.5">
      <div className="flex min-h-[37px] flex-wrap items-center gap-2 rounded-[3px] border border-accent/50 bg-selected px-2.5 py-1 text-ctl text-fg">
        <b className="font-semibold tabular-nums" aria-live="polite">
          {n} selected
        </b>
        <span className="text-secondary">
          {group
            ? 'Look-alikes: same rule, same source, same finding. One decision and one reason are recorded on each.'
            : n > 1
              ? 'Bulk decide is offered only for look-alikes. These rows differ, so each needs its own decision.'
              : 'Open the row to decide it.'}
          {capped && ` At most ${BULK_MAX_ITEMS} at a time.`}
        </span>
        <span className="flex-1" />
        <QButton busy={claiming} onClick={onClaim}>
          Claim {n} <kbd>C</kbd>
        </QButton>
        {group && (
          <QButton onClick={() => setDeciding(true)}>
            Decide all {n}…
          </QButton>
        )}
        <QButton variant="quiet" onClick={onClear}>
          Clear
        </QButton>
      </div>
      {Boolean(claimError) && <ErrorMessage error={claimError} compact />}
      {deciding && (
        <CloseDialog
          items={selected}
          onClose={() => setDeciding(false)}
          onDone={(r) => {
            setDeciding(false);
            onClear();
            onResult(r);
          }}
        />
      )}
    </div>
  );
}
