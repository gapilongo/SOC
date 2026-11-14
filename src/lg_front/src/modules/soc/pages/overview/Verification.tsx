/**
 * "How the AI's closes are verified": the blind audit of the last 30 days
 * (closes eligible, sampled, labelled, and labelled malicious by an analyst
 * who could not see the AI's verdict), with the rate only when the sample
 * carries one. The two other checks of the console v2 design, planted
 * attacks and the safety net, are not reported by the API yet: each shows
 * "Not measured yet" and what it will count, never a figure.
 */

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import type { BlindAuditReportOut } from '../../api/types';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';
import { ErrorMessage, Spinner } from '../../../../components/ui';
import { formatInt } from '../../../../lib/format';
import { defaultRange } from '../../lib/reports';
import { auditFigure, dayRange, plural, sampleNote } from './figures';
import { BLIND_AUDIT_HREF, REPORTS_HREF } from './links';
import { Figure, FigureRow, LABEL, SectionHead, Withheld } from './parts';

const LINK = 'text-link underline underline-offset-2 hover:text-link-hover';
const AUDIT_LABEL = 'Blind audit, last 30 days';

/** "2,410 closes without a person eligible, 200 sampled, 180 labelled (4 unsure), 20 waiting for a label" */
function populations(r: BlindAuditReportOut): string {
  const e = r.estimate;
  return [
    `${plural(e.frame_size, 'close', 'closes')} without a person eligible`,
    `${formatInt(e.sampled)} sampled`,
    `${formatInt(e.labelled)} labelled${e.unsure > 0 ? ` (${formatInt(e.unsure)} unsure)` : ''}`,
    `${formatInt(e.pending)} waiting for a label`,
  ].join(', ');
}

function BlindAudit({ report }: { report: BlindAuditReportOut }) {
  const { principal } = useAuth();
  const e = report.estimate;
  const f = auditFigure(e);
  const window = `Runs of ${dayRange(report.from, report.to)} (UTC).`;
  const more = (
    <Link to={REPORTS_HREF} className={LINK}>
      Full estimate in Reports
    </Link>
  );
  if (f.state === 'none') {
    return (
      <Figure
        state="none"
        label={AUDIT_LABEL}
        big="No sample drawn"
        muted
        small={
          <>
            {window}{' '}
            {can.admin(principal) && can.decide(principal) ? (
              <>
                Draw one on the{' '}
                <Link to={BLIND_AUDIT_HREF} className={LINK}>
                  Blind audit page
                </Link>
                , or turn on the weekly sample in the tenant settings.
              </>
            ) : (
              'An admin draws a sample, or turns on the weekly one in the tenant settings.'
            )}
          </>
        }
      >
        No AI close was sampled for a blind audit in this period, so nothing is claimed about missed threats.
      </Figure>
    );
  }
  if (f.state === 'unlabelled') {
    return (
      <Figure
        state="unlabelled"
        label={AUDIT_LABEL}
        big="None labelled yet"
        muted
        small={
          <>
            {populations(report)}. {window} {more}.
          </>
        }
      >
        {plural(e.sampled, 'AI close was', 'AI closes were')} sampled; no analyst has labelled one malicious or benign yet.
      </Figure>
    );
  }
  return (
    <Figure
      state={f.state}
      label={AUDIT_LABEL}
      big={`${formatInt(e.malicious)} of ${formatInt(f.decided)}`}
      small={
        <>
          <p>
            {f.state === 'rate' ? (
              <>
                Missed-threat rate {f.rate}
                {f.interval && <>, 95% interval {f.interval}</>}.{f.worstCase && <> Counting unsure and waiting samples as malicious: {f.worstCase}.</>}
              </>
            ) : (
              <>
                <Withheld>too few for a rate</Withheld> ({sampleNote(f.decided, e.min_samples)}).
              </>
            )}
          </p>
          <p>
            {populations(report)}. {window} {more}.
          </p>
        </>
      }
    >
      sampled AI {f.decided === 1 ? 'close was' : 'closes were'} labelled malicious by an analyst who could not see the AI&apos;s verdict.
    </Figure>
  );
}

function AuditSlot() {
  const api = useApi();
  // The report's default window: the 30 days ending today (UTC). It does not follow the page's window switch.
  const { from, to } = useMemo(() => defaultRange(), []);
  const q = useQuery({ queryKey: qk.reportBlindAudit.range(from, to), queryFn: ({ signal }) => endpoints.blindAuditReport(api, from, to, signal) });
  if (q.isSuccess) return <BlindAudit report={q.data} />;
  return (
    <div data-figure={q.isError ? 'error' : 'loading'} className="min-w-0 py-3 pb-3.5 lg:pr-5">
      <h3 className={LABEL}>{AUDIT_LABEL}</h3>
      <div className="mt-2">{q.isError ? <ErrorMessage error={q.error} compact onRetry={() => void q.refetch()} /> : <Spinner label="Loading the blind audit" />}</div>
    </div>
  );
}

export function Verification() {
  return (
    <section aria-labelledby="ov-verify">
      <SectionHead id="ov-verify" title="How the AI's closes are verified" note="Measured, not estimated. Each figure names what it counts and over which period." />
      <FigureRow>
        <AuditSlot />
        <Figure state="not-measured" label="Planted attacks" big="Not measured yet" muted small="No attacks are planted yet, so no miss rate is claimed from them.">
          Attack alerts planted in live traffic, and how many of them the AI closed.
        </Figure>
        <Figure state="not-measured" label="Safety net" big="Not measured yet" muted small="These counts are not reported yet, so none is shown.">
          AI closes reopened because a person confirmed a related threat, and closes linked to an open case and left closed.
        </Figure>
      </FigureRow>
    </section>
  );
}
