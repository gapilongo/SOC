import type { JsonObject, VerificationState } from '../../api/types';
import { humanize } from '../../lib/format';
import { Badge, type Tone } from '../Badge';

const TONE: Record<VerificationState, Tone> = { pending: 'info', verified: 'good', failed: 'critical', inconclusive: 'warn' };

/** What each verification state proves (docs/microsoft.md "Verification"). */
export const VERIFICATION_HELP: Record<VerificationState, string> = {
  pending: 'Microsoft accepted the change; LG-SOTF is re-checking that it is in effect.',
  verified: 'A re-read in Microsoft shows the change is in effect.',
  failed: 'Microsoft shows a state that contradicts the change.',
  inconclusive: 'The change could not be checked (deadline passed, no permission to read, or the integration is unavailable).',
};

function reasonOf(detail: JsonObject | null | undefined): string | null {
  const reason = detail?.reason;
  return typeof reason === 'string' && reason ? humanize(reason) : null;
}

/** The verification state of an executed action ("-" when the action has none). */
export function VerificationBadge({ value, detail }: { value: VerificationState | null | undefined; detail?: JsonObject | null }) {
  if (!value) return <span className="text-muted">-</span>;
  const reason = reasonOf(detail);
  const title = reason ? `${VERIFICATION_HELP[value]} Reason: ${reason}.` : VERIFICATION_HELP[value];
  return (
    <Badge tone={TONE[value] ?? 'neutral'} title={title}>
      {value}
      {reason && value !== 'verified' ? ` (${reason})` : ''}
    </Badge>
  );
}
