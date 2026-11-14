/**
 * Proof of value: where the setup wizard ends. A placeholder until the PoV
 * run (window, backtest and shadow period, signed report) is built; it says
 * so and points at what an admin can do meanwhile.
 */

import { Link } from 'react-router-dom';

import { Card, PageHeader, buttonClass } from '../../../components/ui';

export default function PovPage() {
  return (
    <>
      <PageHeader
        title="Proof of value"
        description="Measure what the triage does on your own alerts before you rely on it."
      />
      <Card title="Coming in a later release">
        <div className="space-y-3 text-sm text-secondary">
          <p>
            A proof-of-value run will replay a window of your closed alerts against the triage, then shadow your analysts for a
            period, and report agreement, missed threats and analyst hours saved, with the numbers behind every figure.
          </p>
          <p>Meanwhile, connect a real alert source so the triage works on your own alerts, and review the verdicts.</p>
          <div className="flex flex-wrap gap-2 pt-1">
            <Link to="/sources" className={buttonClass('primary', 'md')}>
              Connect a source
            </Link>
            <Link to="/getting-started" className={buttonClass('secondary', 'md')}>
              Getting started
            </Link>
          </div>
        </div>
      </Card>
    </>
  );
}
