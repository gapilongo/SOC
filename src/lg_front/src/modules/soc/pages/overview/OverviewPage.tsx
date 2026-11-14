/**
 * The Overview of console v2 (docs/design/console-v2, `#overview`), in its
 * order: what needs the signed-in person now; what was closed without a
 * person and how those closes are verified; the next deadlines; and, for
 * admins, platform health. Every figure says what it counts and over which
 * window, a rate or a mean over too few observations is withheld in words,
 * and a figure the API does not report reads "not measured yet".
 */

import { RefreshCw } from 'lucide-react';
import { useState } from 'react';

import { readQueueFigures } from '../../api/fields';
import { useDashboardSummary, useLivePollInterval } from '../../api/hooks';
import type { DashboardOut } from '../../api/types';
import { useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';
import { OnboardingBanner } from '../onboarding/Onboarding';
import { SetupCallout } from '../setup/SetupCallout';
import { Button, ErrorMessage, LoadingState, PageHeader, Segmented } from '../../../../components/ui';
import { formatRelative } from '../../../../lib/format';
import { useNow } from '../../../../lib/useNow';
import { Deadlines } from './Deadlines';
import { DEFAULT_WINDOW_HOURS, WINDOWS, windowPhrase } from './figures';
import { HandledBar } from './HandledBar';
import { NeedsYouNow } from './NeedsYouNow';
import { PlatformHealth } from './PlatformHealth';
import { Verification } from './Verification';

export default function OverviewPage() {
  const { principal } = useAuth();
  const isAdmin = can.admin(principal);
  const [windowHours, setWindowHours] = useState(DEFAULT_WINDOW_HOURS);
  const interval = useLivePollInterval();
  const q = useDashboardSummary(windowHours, { refetchInterval: interval });
  const now = useNow(30_000);
  // The last summary stays on the page while another window loads, so the blocks neither blank nor
  // load again; every figure is worded from the window of the summary it came from, not from the switch.
  const [held, setHeld] = useState<DashboardOut>();
  if (q.data && q.data !== held) setHeld(q.data);
  const d = q.data ?? held;
  const queue = readQueueFigures(d);
  const phrase = windowPhrase(d?.window_hours ?? windowHours);

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          <>
            Your work first. Then what was closed without a person, and how that is checked.
            {d && (
              <>
                {' '}
                <span role="status">Updated {formatRelative(d.generated_at, now)}.</span>
              </>
            )}
          </>
        }
        actions={
          <>
            <Segmented
              label="Time window"
              options={WINDOWS.map((w) => ({ value: w.hours, label: w.short, title: w.phrase.replace(/^the l/, 'L') }))}
              value={windowHours}
              onChange={setWindowHours}
            />
            <Button
              aria-label="Refresh"
              title="Refresh"
              onClick={() => void q.refetch()}
              busy={q.isFetching}
              icon={<RefreshCw className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />}
            />
          </>
        }
      />
      {can.setup(principal) && <SetupCallout />}
      {isAdmin && <OnboardingBanner />}
      {q.isPending && !d && <LoadingState label="Loading the overview" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {d && (
        <div className="flex flex-col gap-[30px]">
          {queue && <NeedsYouNow queue={queue} now={now} interval={interval} />}
          <HandledBar d={d} phrase={phrase} isAdmin={isAdmin} />
          <Verification />
          {queue && <Deadlines queue={queue} now={now} interval={interval} />}
          {isAdmin && <PlatformHealth d={d} phrase={phrase} />}
        </div>
      )}
    </>
  );
}
