import { describe, expect, it } from 'vitest';

import type { AlertDetailOut, FindingOut } from '../../api/types';
import { aiVerdict, escalationIdOf, evidenceFlags, kindWords, originWords, statusShort, statusWords } from './alertSummary';
import { formatAge } from './AlertsPage';
import { closedWindow, isTodayWindow, startOfToday, viewCount, viewFilters, viewFromParams, viewHref, viewLabel } from './views';

const p = (query: string) => new URLSearchParams(query);

describe('alert views', () => {
  it('opens Needs analyst on a bare URL or a deep link, All on a filtered (overview) link', () => {
    expect(viewFromParams(p(''))).toBe('needs_analyst');
    expect(viewFromParams(p('alert=a-1'))).toBe('needs_analyst');
    expect(viewFromParams(p('severity=high&from=2026-11-05T12:00:00Z'))).toBe('all');
    expect(viewFromParams(p('status=waiting_human'))).toBe('all');
    expect(viewFromParams(p('view=closed&severity=high'))).toBe('closed');
    expect(viewFromParams(p('view=nonsense'))).toBe('needs_analyst');
    expect(viewFromParams(p('q='))).toBe('needs_analyst');
  });

  it('turns a view into API filters: its statuses replace the URL status, Closed adds the window', () => {
    const base = { severity: ['high'], status: ['failed'], closed_from: 'x' };
    const window = { closed_from: '2026-11-07T00:00:00.000Z' };
    expect(viewFilters('all', base, window)).toBe(base);
    expect(viewFilters('needs_analyst', base, window)).toEqual({ severity: ['high'], status: ['waiting_human'] });
    expect(viewFilters('processing', {}, window)).toEqual({ status: ['new', 'queued', 'processing'] });
    expect(viewFilters('closed', base, window)).toEqual({ severity: ['high'], status: ['closed'], closed_from: '2026-11-07T00:00:00.000Z' });
  });

  it('counts each tab from by_status; All has no count', () => {
    const byStatus = { waiting_human: 103, waiting_approval: 1, new: 1, queued: 2, processing: 3, closed: 4 };
    expect(viewCount('needs_analyst', byStatus)).toBe(103);
    expect(viewCount('processing', byStatus)).toBe(6);
    expect(viewCount('failed', byStatus)).toBe(0);
    expect(viewCount('closed', byStatus)).toBe(4);
    expect(viewCount('all', byStatus)).toBeNull();
    expect(viewCount('closed', undefined)).toBeNull();
  });

  it('builds tab links that keep the filters but not the status or another view\'s window', () => {
    const href = viewHref('awaiting_approval', p('view=all&status=failed&severity=high&closed_from=x&alert=a-1'));
    const q = new URL(href, 'http://x').searchParams;
    expect(q.get('view')).toBe('awaiting_approval');
    expect(q.getAll('severity')).toEqual(['high']);
    expect(q.has('status')).toBe(false);
    expect(q.has('closed_from')).toBe(false);
    expect(q.get('alert')).toBe('a-1');
    expect(new URL(viewHref('closed', p('closed_from=x')), 'http://x').searchParams.get('closed_from')).toBe('x');
  });

  it('closes "today" from local midnight unless the URL sets the window', () => {
    const now = new Date(2026, 10, 7, 15, 30);
    expect(startOfToday(now)).toBe(new Date(2026, 10, 7).toISOString());
    expect(closedWindow(p(''), now)).toEqual({ closed_from: new Date(2026, 10, 7).toISOString() });
    expect(closedWindow(p('closed_from=a&closed_to=b'), now)).toEqual({ closed_from: 'a', closed_to: 'b' });
    expect(isTodayWindow(p(''))).toBe(true);
    expect(isTodayWindow(p('closed_to=b'))).toBe(false);
    expect(viewLabel('closed', true)).toBe('Closed today');
    expect(viewLabel('closed', false)).toBe('Closed');
    expect(viewLabel('all')).toBe('All');
  });
});

function detail(summary: Record<string, unknown>, findings: FindingOut[] = []): Pick<AlertDetailOut, 'summary' | 'findings'> {
  return { summary, findings };
}

describe('alert summary readers', () => {
  it('reads the AI verdict from the analysis, then the close summary, then the disposition', () => {
    expect(aiVerdict({ summary: { analysis: { verdict: 'inconclusive' } }, confidence: 41.6 })).toEqual({ verdict: 'inconclusive', confidence: 42 });
    expect(aiVerdict({ summary: { verdict: 'benign' }, disposition: 'malicious' })).toEqual({ verdict: 'benign', confidence: null });
    expect(aiVerdict({ summary: {}, disposition: 'malicious', confidence: null })).toEqual({ verdict: 'malicious', confidence: null });
    expect(aiVerdict({})).toEqual({ verdict: null, confidence: null });
  });

  it('finds the escalation id', () => {
    expect(escalationIdOf({ summary: { escalation_id: 'e-1' } })).toBe('e-1');
    expect(escalationIdOf({ summary: { escalation_id: 3 } })).toBeNull();
    expect(escalationIdOf({})).toBeNull();
  });

  it('flags simulated evidence wherever the workflow recorded it, and dry runs', () => {
    expect(evidenceFlags(detail({}))).toEqual({ simulated: false, simulatedSources: [], dryRun: false });
    expect(evidenceFlags(detail({ simulated_evidence: true })).simulated).toBe(true);
    expect(evidenceFlags(detail({ analysis: { simulated_evidence: true } })).simulated).toBe(true);
    expect(
      evidenceFlags(detail({ analysis: { tools: [{ simulated: true, source: 'otx', results: [{ source: 'abuseipdb' }, 'junk'] }, { simulated: false, source: 'live' }, null] } })),
    ).toEqual({ simulated: true, simulatedSources: ['abuseipdb', 'otx'], dryRun: false });
    const finding: FindingOut = { origin: 'threat_intel', kind: 'ip', target: '192.0.2.1', source: 'virustotal', status: 'ok', verdict: 'clean', data: { simulated: true } };
    expect(evidenceFlags(detail({}, [finding])).simulatedSources).toEqual(['virustotal']);
    expect(evidenceFlags(detail({ dry_run: true })).dryRun).toBe(true);
    expect(evidenceFlags({ summary: undefined, findings: undefined })).toEqual({ simulated: false, simulatedSources: [], dryRun: false });
  });

  it('words statuses, kinds and origins', () => {
    expect(statusWords('waiting_human')).toBe('Waiting for an analyst');
    expect(statusWords('some_new_state')).toBe('some new state');
    expect(statusShort('waiting_human')).toBe('Needs analyst');
    expect(statusShort('closed')).toBe('Closed');
    expect(kindWords('ip')).toBe('IP');
    expect(kindWords('command_line')).toBe('Command line');
    expect(originWords('history')).toBe('Your history');
    expect(originWords('threat_intel')).toBe('Threat intel');
  });

  it('formats a short age', () => {
    const now = Date.parse('2026-11-07T12:00:00Z');
    expect(formatAge('2026-11-07T11:59:30Z', now)).toBe('now');
    expect(formatAge('2026-11-07T11:48:00Z', now)).toBe('12 min ago');
    expect(formatAge('2026-11-07T09:00:00Z', now)).toBe('3 h ago');
    expect(formatAge('2026-11-02T12:00:00Z', now)).toBe('5 d ago');
    expect(formatAge('not a date', now)).toBe('-');
  });
});
