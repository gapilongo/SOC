import { Link } from 'react-router-dom';

import { OnboardingChecklist, SampleAlertsButton, useDismissOnboarding, useOnboardingStatus } from './onboarding/Onboarding';
import { useAuth } from '../../../auth/AuthContext';
import { can } from '../../../auth/roles';
import { Button, Card, ErrorMessage, LoadingState, PageHeader, buttonClass } from '../../../components/ui';

export default function GettingStartedPage() {
  const q = useOnboardingStatus();
  const dismiss = useDismissOnboarding();
  const { principal } = useAuth();
  const s = q.data;
  return (
    <>
      <PageHeader
        title="Getting started"
        description="The steps that take a new tenant from empty to triaging real alerts. Progress is worked out from your tenant's data."
        actions={
          <>
            {can.setup(principal) && (
              <Link to="/setup" className={buttonClass('secondary', 'sm')}>
                Setup wizard
              </Link>
            )}
            {s && !s.dismissed && (
              <Button size="sm" variant="quiet" busy={dismiss.isPending} onClick={() => dismiss.mutate()}>
                Hide the dashboard banner
              </Button>
            )}
          </>
        }
      />
      {q.isPending && <LoadingState label="Loading checklist" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {s && (
        <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <Card title={`Checklist: ${s.completed} of ${s.total} done`}>
            <OnboardingChecklist status={s} />
          </Card>
          <Card title="Try it with sample alerts">
            <div className="space-y-3 text-sm text-secondary">
              <p>
                Send five synthetic alerts (a brute-force login, a test-file detection, beaconing, an encoded PowerShell command and a
                scheduled scan) through the normal ingestion pipeline and watch them being triaged.
              </p>
              <p>
                They use reserved test domains and addresses only, are marked as samples, are not counted in your usage and are
                stored once however often you send them.
              </p>
              <SampleAlertsButton sent={s.samples_sent} />
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
