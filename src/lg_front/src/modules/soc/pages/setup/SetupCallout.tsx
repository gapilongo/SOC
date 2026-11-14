/**
 * The Overview's first-run notices for the install's platform admin: an
 * invitation to the setup wizard until setup is done, and once the wizard is
 * finished, a link to start a proof of value.
 */

import { ArrowRight, Rocket } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

import { Banner, buttonClass } from '../../../../components/ui';
import { POV_HREF } from '../../lib/links';
import type { SetupDoneState } from './SetupWizardPage';
import { useSetup } from './useSetup';

function justFinished(state: unknown): boolean {
  return Boolean(state && typeof state === 'object' && (state as Partial<SetupDoneState>).setupDone);
}

export function SetupCallout() {
  const location = useLocation();
  const setup = useSetup();
  if (justFinished(location.state)) {
    return (
      <Banner
        tone="info"
        role="status"
        title="Setup complete"
        className="mb-5"
        actions={
          <Link to={POV_HREF} className={buttonClass('primary', 'sm')}>
            Start a proof of value
            <ArrowRight className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
          </Link>
        }
      >
        Measure the triage on your own alerts before you rely on it.
      </Banner>
    );
  }
  if (!setup.data || setup.data.completed) return null;
  return (
    <section aria-labelledby="setup-callout-title" className="mb-5 rounded-card border border-link/50 bg-tint-info p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-[min(16rem,100%)] flex-1">
          <h2 id="setup-callout-title" className="flex items-center gap-2 text-sm font-semibold text-fg">
            <Rocket className="h-4 w-4 flex-none text-link" strokeWidth={1.75} aria-hidden="true" />
            Finish setting up LG-SOTF
          </h2>
          <p className="mt-1 text-sm text-body">
            Confirm your account, name your organisation and first tenant, pick and test the language model, and watch the
            sample alerts being triaged. It takes a few minutes.
          </p>
        </div>
        <Link to="/setup" className={buttonClass('primary', 'sm')}>
          Start setup
        </Link>
      </div>
    </section>
  );
}
