import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import type {
  InvestigationClaimOut,
  InvestigationClosedByOut,
  InvestigationObservationOut,
  InvestigationOutcomeOut,
  OutcomeTrackRecordOut,
  PlainStepOut,
} from '../../api/types';
import { AI_CLOSED_INVESTIGATION, ESCALATED_INVESTIGATION } from '../../../../test/investigationReadModels';
import {
  ClaimRow,
  FactChip,
  Glyph,
  Keycap,
  MAX_SQUARES,
  NotEstablished,
  Observation,
  OutcomeHeadline,
  OutcomeTag,
  SeverityBars,
  SmallTag,
  StepList,
  TrackRecord,
  VoiceTag,
  observationName,
  outcomeKind,
  outcomeLabel,
  outcomeWords,
  splitHeadline,
} from '.';

const outcome = (overrides: Partial<InvestigationOutcomeOut> = {}): InvestigationOutcomeOut => ({ category: null, reason: null, blockers: [], evidence: [], closed_by: null, ...overrides });

const closedBy = (overrides: Partial<InvestigationClosedByOut> = {}): InvestigationClosedByOut => ({
  kind: 'ai',
  reason: { code: 'policy:close', sentence: 'The AI closed it on approved benign evidence.' },
  at: '2026-11-14T10:04:00Z',
  decision: null,
  rule_id: null,
  rule_name: null,
  source_alert_id: null,
  ...overrides,
});

const NO_SUMMARY = { text: null, written_by: null };

const observation = (overrides: Partial<InvestigationObservationOut> = {}): InvestigationObservationOut => ({
  id: 'O-01',
  tool: 'reputation',
  title: 'Threat-intelligence reputation',
  kind: 'domain',
  target: 'cdn-invoice-portal.example',
  sources: ['virustotal'],
  at: '2026-11-14T09:44:28Z',
  outcome: 'success',
  verdict: 'suspicious',
  cached: false,
  excerpt: [{ text: 'virustotal  ok  suspicious', marks: [{ start: 16, end: 26 }] }],
  excerpt_truncated: false,
  input_sha256: null,
  output_sha256: '9f2c81d7aa00000000000000000000000000000000000000000000000000041e1',
  ...overrides,
});

const claim = (overrides: Partial<InvestigationClaimOut> = {}): InvestigationClaimOut => ({
  id: 'C-01',
  text: 'Word started PowerShell directly from an email attachment.',
  written_by: 'model',
  direction: 'malicious',
  observation_ids: ['O-01', 'O-02'],
  check: 'supported',
  check_reason: null,
  ...overrides,
});

const track = (overrides: Partial<OutcomeTrackRecordOut> = {}): OutcomeTrackRecordOut => ({
  category: 'needs_decision',
  basis: 'analyst_decisions',
  window_days: 90,
  total: 34,
  confirmed: 31,
  min_samples: 30,
  rate: 0.9118,
  ...overrides,
});

// The headline links a cached verdict to its alert: it renders inside a router.
const renderInRouter = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe('OutcomeHeadline', () => {
  it('needs a decision, likely malicious: the category, the verdict as the largest text, who wrote it, why it is with a person and what blocks an AI close', () => {
    const { container } = renderInRouter(
      <OutcomeHeadline outcome={ESCALATED_INVESTIGATION.outcome} summary={ESCALATED_INVESTIGATION.summary} status="waiting_human" checkLine="1 of the 5 claims is backed by what the tools returned; 4 cite no fact.">
        <span>subject</span>
      </OutcomeHeadline>,
    );
    expect(container.firstElementChild).toHaveAttribute('data-headline', 'needs_decision');
    expect(screen.getByText('Needs your decision: likely malicious')).toHaveAttribute('data-outcome', 'needs_decision');
    expect(container.querySelector('[data-glyph="threat"]')).toBeInTheDocument();
    expect(screen.getByText(/^Word ran a hidden, encoded PowerShell command/).tagName).toBe('P');
    expect(screen.getByText('Summary written by the model')).toBeInTheDocument();
    expect(screen.getByText('Why it is with you.').parentElement).toHaveTextContent(
      'Why it is with you. No automatic rule applies to this alert, so a person decides. 1 of the 5 claims is backed by what the tools returned; 4 cite no fact.',
    );
    const blockers = within(screen.getByRole('list', { name: 'Why the AI may not close it on its own' })).getAllByRole('listitem');
    expect(blockers.map((b) => b.textContent)).toEqual([
      "This customer has not allowed the AI to close alerts on the model's word.",
      'The first model assessment called it a likely or confirmed threat.',
      'The deeper analysis did not judge it benign.',
    ]);
    expect(screen.getByText('subject')).toBeInTheDocument();
  });

  it('needs a decision, unsure: its own category and mark', () => {
    const { container } = renderInRouter(<OutcomeHeadline outcome={outcome({ category: 'needs_review' })} summary={{ text: 'Unclear.', written_by: 'rules' }} status="waiting_human" />);
    expect(screen.getByText('Needs your decision: unsure')).toBeInTheDocument();
    expect(container.querySelector('[data-glyph="review"]')).toBeInTheDocument();
    expect(screen.getByText('Summary written by the rules')).toBeInTheDocument();
    expect(screen.queryByText(/^Why it/)).not.toBeInTheDocument();
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });

  it('closed by the AI and sampled for audit: says why it was closed and when', () => {
    renderInRouter(<OutcomeHeadline outcome={AI_CLOSED_INVESTIGATION.outcome} summary={AI_CLOSED_INVESTIGATION.summary} status="closed" />);
    expect(screen.getByText('Closed by AI, sampled for audit')).toBeInTheDocument();
    expect(screen.getByText('Why it was closed.').parentElement).toHaveTextContent(
      "Why it was closed. The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit.",
    );
    expect(screen.getByText('A routine package install by the configuration management agent, seen on 38 hosts this week.')).toBeInTheDocument();
    expect(document.querySelector('time')).toHaveAttribute('dateTime', '2026-11-14T10:04:00Z');
  });

  it('closed by the AI on evidence: names the approved benign signals the rules found', () => {
    renderInRouter(
      <OutcomeHeadline
        outcome={outcome({ category: 'ai_closed_evidence', evidence: ['known_scanner', 'test_environment'], closed_by: closedBy(), reason: closedBy().reason })}
        summary={{ text: 'A scheduled vulnerability scan.', written_by: 'rules' }}
        status="closed"
      />,
    );
    expect(screen.getByText('Closed by AI, backed by evidence')).toBeInTheDocument();
    expect(screen.getByText('Approved benign signals the rules found').parentElement).toHaveTextContent('known scanner, test environment');
    expect(screen.queryByText('Why the AI may not close it on its own')).not.toBeInTheDocument();
  });

  it('closed by a rule, an earlier verdict or an analyst: who closed it comes before the AI category, with what the record holds', () => {
    const rule = closedBy({ kind: 'suppression_rule', reason: { code: 'suppression_rule', sentence: 'A suppression rule matched this alert before any analysis.' }, rule_id: 'r1', rule_name: 'Backup window' });
    const { unmount } = renderInRouter(<OutcomeHeadline outcome={outcome({ closed_by: rule, reason: rule.reason })} summary={NO_SUMMARY} status="closed" />);
    expect(screen.getByText('Closed by a suppression rule')).toBeInTheDocument();
    // Without a summary the reason is the headline, said once.
    expect(screen.getAllByText('A suppression rule matched this alert before any analysis.')).toHaveLength(1);
    expect(screen.queryByText('Why it was closed.')).not.toBeInTheDocument();
    expect(screen.getByText('Backup window')).toBeInTheDocument();
    unmount();

    const cached = closedBy({ kind: 'cached_verdict', reason: { code: 'verdict_cache', sentence: 'An analyst decided the same alert before.' }, decision: 'benign_positive', source_alert_id: 'a-0' });
    const second = renderInRouter(<OutcomeHeadline outcome={outcome({ closed_by: cached })} summary={NO_SUMMARY} status="closed" />);
    expect(screen.getByText('Closed by an earlier analyst verdict')).toBeInTheDocument();
    expect(screen.getByText('Decision: benign, expected here')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'The alert the analyst decided' })).toHaveAttribute('href', '/alerts/a-0');
    second.unmount();

    const analyst = closedBy({ kind: 'analyst', reason: { code: 'analyst:true_positive', sentence: 'An analyst decided it was a true positive.' }, decision: 'true_positive', at: null });
    renderInRouter(
      <OutcomeHeadline
        outcome={outcome({ category: 'needs_decision', closed_by: analyst, blockers: [{ code: 'tier_off', sentence: 'Not allowed.' }] })}
        summary={{ text: 'Malicious.', written_by: 'model' }}
        status="closed"
      />,
    );
    expect(screen.getByText('Closed by an analyst')).toBeInTheDocument();
    expect(screen.queryByText('Needs your decision: likely malicious')).not.toBeInTheDocument();
    expect(screen.getByText('Why it was closed.').parentElement).toHaveTextContent('An analyst decided it was a true positive.');
    expect(screen.getByText('Decision: true positive')).toBeInTheDocument();
    // What kept the AI from closing it no longer matters once a person closed it.
    expect(screen.queryByText('Not allowed.')).not.toBeInTheDocument();
  });

  it('verdict hidden: the category, the sentence and the reasons are withheld; the subject stays', () => {
    const { container, rerender } = renderInRouter(
      <OutcomeHeadline outcome={ESCALATED_INVESTIGATION.outcome} summary={ESCALATED_INVESTIGATION.summary} status="waiting_human" hidden checkLine="1 of the 1 claim is backed.">
        <span>subject</span>
      </OutcomeHeadline>,
    );
    expect(container.firstElementChild).toHaveAttribute('data-headline', 'hidden');
    expect(screen.getByRole('note')).toHaveTextContent('The verdict and the claims are hidden. Read what the tools returned, choose your own verdict in the bar below, then press V to compare.');
    for (const withheld of ['Word ran a hidden', 'No automatic rule applies', 'Needs your decision: likely malicious', '1 of the 1 claim is backed.', 'Summary written by the model', 'The deeper analysis did not judge it benign.']) {
      expect(screen.queryByText(withheld, { exact: false })).not.toBeInTheDocument();
    }
    expect(screen.getByText('subject')).toBeInTheDocument();
    rerender(
      <MemoryRouter>
        <OutcomeHeadline outcome={null} summary={NO_SUMMARY} status="closed" hidden canReveal={false} />
      </MemoryRouter>,
    );
    expect(screen.getByRole('note')).toHaveTextContent('withheld for everyone until an analyst labels it on the Blind audit page');
  });

  it('no outcome yet: still investigating, failed, or no investigation at all', () => {
    const { rerender, container } = renderInRouter(<OutcomeHeadline outcome={null} summary={NO_SUMMARY} status="processing" />);
    expect(screen.getByText('Being investigated')).toBeInTheDocument();
    expect(screen.getByText('The investigation is still running.')).toBeInTheDocument();
    expect(container.querySelectorAll('.animate-pulse')).toHaveLength(2);
    const again = (status: string, o: InvestigationOutcomeOut | null = null) =>
      rerender(
        <MemoryRouter>
          <OutcomeHeadline outcome={o} summary={NO_SUMMARY} status={status} />
        </MemoryRouter>,
      );
    again('failed');
    expect(screen.getByText('Investigation failed')).toBeInTheDocument();
    expect(screen.getByText('The investigation failed before it reached a verdict.')).toBeInTheDocument();
    again('closed', outcome());
    expect(screen.getByText('Closed')).toBeInTheDocument();
    expect(screen.getByText('No investigation ran: the model saw only the alert.')).toBeInTheDocument();
    again('waiting_approval', outcome({ category: 'needs_decision', reason: { code: 'awaiting_approval', sentence: 'The response waits for an approval.' } }));
    expect(screen.getByText('Needs your decision: likely malicious')).toBeInTheDocument();
    expect(screen.getByText('The response waits for an approval.')).toBeInTheDocument();
  });

  it('keeps the headline to a sentence or two and continues a long summary under it', () => {
    const long = `${'A sentence of the summary. '.repeat(14)}The end.`;
    renderInRouter(<OutcomeHeadline outcome={outcome({ category: 'ai_closed_evidence', closed_by: closedBy() })} summary={{ text: long, written_by: 'model' }} status="closed" />);
    const { headline, rest } = splitHeadline(long);
    expect(headline.length).toBeLessThanOrEqual(260);
    expect(headline.endsWith('summary.')).toBe(true);
    expect(rest.endsWith('The end.')).toBe(true);
    expect(screen.getByText(headline)).toBeInTheDocument();
    expect(screen.getByText(rest)).toBeInTheDocument();
    expect(splitHeadline('  Short   one. ')).toEqual({ headline: 'Short one.', rest: '' });
    expect(splitHeadline('x'.repeat(400)).rest).toBe('');
  });

  it('maps who closed it, the category or the status to one outcome', () => {
    expect(outcomeKind(outcome({ category: 'ai_closed_evidence', closed_by: closedBy() }), 'closed')).toBe('ai_closed_evidence');
    expect(outcomeKind(outcome({ category: 'something_new', closed_by: closedBy() }), 'closed')).toBe('closed');
    expect(outcomeKind(outcome({ closed_by: closedBy({ kind: 'robot' }) }), 'closed')).toBe('closed');
    expect(outcomeKind(outcome({ category: 'needs_review' }), 'waiting_human')).toBe('needs_review');
    expect(outcomeKind(outcome({ category: 'ai_closed_audit' }), 'closed')).toBe('ai_closed_audit');
    expect(outcomeKind(outcome(), 'waiting_human')).toBe('unknown');
    expect(outcomeKind(outcome(), 'closed')).toBe('closed');
    expect(outcomeKind(null, 'queued')).toBe('investigating');
    expect(outcomeKind(null, 'waiting_approval')).toBe('waiting_approval');
    expect(outcomeKind(null, 'closed')).toBe('closed');
    expect(outcomeKind(null, 'waiting_human')).toBe('unknown');
    expect(outcomeLabel('closed_cached')).toBe('Closed by an earlier analyst verdict');
    render(<OutcomeTag kind="waiting_approval" />);
    expect(screen.getByText('Waiting for an approval')).toBeInTheDocument();
  });
});

describe('Observation', () => {
  it('returned data: id, what was looked up, outcome, verdict, sources, time, hash, and only the marked characters highlighted', () => {
    const { container } = render(<Observation observation={observation({ input_sha256: '41be7d0c9a' })} />);
    const block = container.querySelector('[data-observation="O-01"]') as HTMLElement;
    expect(block).toHaveAttribute('data-outcome', 'success');
    expect(block).toHaveTextContent('O-01');
    expect(block).toHaveTextContent('Threat-intelligence reputation: domain cdn-invoice-portal.example');
    expect(within(block).getByText('returned data')).toBeInTheDocument();
    expect(within(block).getByText('Verdict suspicious')).toBeInTheDocument();
    expect(block).toHaveTextContent('virustotal');
    expect(block.querySelector('time')).toHaveAttribute('dateTime', '2026-11-14T09:44:28Z');
    expect(within(block).getByText('sha256 9f2c…41e1')).toHaveAttribute('title', expect.stringMatching(/^9f2c81d7aa/));
    expect([...block.querySelectorAll('mark')].map((m) => m.textContent)).toEqual(['suspicious']);
    expect(block.querySelector('pre')).toHaveTextContent('virustotal ok suspicious');
    expect(within(block).getByText('Hashes of this call')).toBeInTheDocument();
    expect(block.querySelector('details pre')).toHaveTextContent('input sha256 41be7d0c9a output sha256 9f2c81d7aa');
  });

  it('returned nothing and failed: said in words, with their own outcome and no hash line', () => {
    const { container, rerender } = render(
      <Observation observation={observation({ id: 'O-04', outcome: 'empty', verdict: null, excerpt: [{ text: 'virustotal  not_found', marks: [] }], output_sha256: null, at: null, sources: ['virustotal', 'abuseipdb'] })} />,
    );
    const empty = container.querySelector('[data-observation="O-04"]') as HTMLElement;
    expect(empty).toHaveAttribute('data-outcome', 'empty');
    expect(within(empty).getByText('returned nothing')).toBeInTheDocument();
    expect(empty).toHaveTextContent('virustotal, abuseipdb · time not recorded');
    expect(empty).not.toHaveTextContent('sha256');
    expect(empty.querySelector('mark')).toBeNull();
    expect(empty.querySelector('details')).toBeNull();
    expect(within(empty).queryByText(/^Verdict/)).not.toBeInTheDocument();
    rerender(<Observation observation={observation({ id: 'O-06', outcome: 'failed', verdict: null, sources: [], excerpt: [{ text: 'virustotal  error', marks: [] }], output_sha256: null })} />);
    const failed = container.querySelector('[data-observation="O-06"]') as HTMLElement;
    expect(failed).toHaveAttribute('data-outcome', 'failed');
    expect(within(failed).getByText('failed')).toBeInTheDocument();
    // Without a source, the tool is named.
    expect(failed).toHaveTextContent('reputation ·');
  });

  it('flags cached and cut results, explains under a rule, and does not repeat itself the second time', () => {
    const o = observation({ cached: true, verdict: 'harmless', excerpt_truncated: true, excerpt: [{ text: 'line one', marks: [] }, { text: 'line two', marks: [] }] });
    const { container, rerender } = render(
      <Observation observation={o}>
        <p>What this command does</p>
      </Observation>,
    );
    expect(screen.getByText('Cached')).toBeInTheDocument();
    expect(screen.getByText('Verdict harmless')).toBeInTheDocument();
    expect(screen.getByText('The excerpt is cut: the tool returned more lines.')).toBeInTheDocument();
    expect(screen.getByText('What this command does')).toBeInTheDocument();
    expect(container.querySelector('pre')?.textContent).toBe('line one\nline two');
    rerender(<Observation observation={o} repeated />);
    expect(screen.getByText('same observation as above')).toBeInTheDocument();
    for (const gone of ['Cached', 'returned data', 'Hashes of this call', 'Verdict harmless', 'The excerpt is cut: the tool returned more lines.']) expect(screen.queryByText(gone)).not.toBeInTheDocument();
  });

  it('ignores highlight ranges that do not fit the line, and words every outcome and lookup', () => {
    const marks = [{ start: 2, end: 4 }, { start: 3, end: 5 }, { start: 4, end: 99 }, { start: -1, end: 2 }, { start: 5, end: 5 }, { start: 0.5, end: 2 }];
    const { container } = render(<Observation observation={observation({ excerpt: [{ text: 'abcdef', marks }], output_sha256: 'short' })} />);
    expect([...container.querySelectorAll('mark')].map((m) => m.textContent)).toEqual(['cd']);
    expect(container.querySelector('pre')?.textContent).toBe('abcdef');
    expect(screen.getByText('sha256 short')).toBeInTheDocument();
    expect(outcomeWords({ outcome: 'success' })).toBe('returned data');
    expect(outcomeWords({ outcome: 'empty' })).toBe('returned nothing');
    expect(outcomeWords({ outcome: 'failed' })).toBe('failed');
    expect(observationName({ title: 'Threat-intelligence reputation', kind: 'ip', target: '203.0.113.50' })).toBe('Threat-intelligence reputation: IP address 203.0.113.50');
    expect(observationName({ title: 'Lookup', kind: null, target: 'x' })).toBe('Lookup: x');
    expect(observationName({ title: 'Lookup', kind: 'process_name', target: null })).toBe('Lookup');
  });
});

describe('ClaimRow', () => {
  it('backed: the claim, its direction and the observations that back it; selecting it is a button', async () => {
    const onSelect = vi.fn();
    const { container } = render(
      <ClaimRow claim={claim()} number={1} onSelect={onSelect}>
        <Observation observation={observation()} />
      </ClaimRow>,
    );
    const row = container.querySelector('[data-claim="C-01"]') as HTMLElement;
    expect(row).toHaveAttribute('data-check', 'supported');
    expect(screen.getByText('Word started PowerShell directly from an email attachment.')).not.toHaveClass('line-through');
    expect(screen.getByText('Points to malicious')).toBeInTheDocument();
    expect(screen.getByText('Backed by O-01, O-02')).toBeInTheDocument();
    expect(screen.queryByText('Stated by the rules')).not.toBeInTheDocument();
    expect(row.querySelector('[data-observation="O-01"]')).toBeInTheDocument();
    const button = screen.getByRole('button', { name: 'Claim 1, select' });
    expect(button).toHaveAttribute('aria-pressed', 'false');
    await userEvent.click(button);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('unsupported: says so, with the reason, and that no observation is cited; a rule claim is marked as the rules’', () => {
    const { container } = render(<ClaimRow claim={claim({ check: 'unsupported', observation_ids: [], written_by: 'rules', check_reason: 'The model named no observation for it.' })} number={4} selected />);
    expect(container.querySelector('[data-claim]')).toHaveAttribute('data-check', 'unsupported');
    expect(screen.getByText('Unsupported')).toBeInTheDocument();
    expect(screen.getByText('The model named no observation for it.')).toBeInTheDocument();
    expect(screen.getByText('No observation is cited for this claim.')).toBeInTheDocument();
    expect(screen.getByText('Stated by the rules')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Claim 4, select' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('rejected by the checker: stays on the page, struck through, with the reason', () => {
    render(
      <ClaimRow
        claim={claim({ check: 'rejected', direction: 'benign', check_reason: 'It rests on a lookup that returned nothing.', text: 'There is no sign of lateral movement.' })}
        number={6}
      />,
    );
    expect(screen.getByText('There is no sign of lateral movement.')).toHaveClass('line-through');
    expect(screen.getByText('Rejected by the checker')).toBeInTheDocument();
    expect(screen.getByText('Points to benign')).toBeInTheDocument();
    expect(screen.getByText('It rests on a lookup that returned nothing.')).toBeInTheDocument();
  });

  it('verdict hidden: the number and the observations stay, the claim and its check are withheld', () => {
    const { container } = render(
      <ClaimRow claim={claim({ check_reason: 'reason', written_by: 'rules' })} number={2} hidden>
        <Observation observation={observation()} />
      </ClaimRow>,
    );
    expect(container.querySelector('[data-claim]')).not.toHaveAttribute('data-check');
    expect(screen.getByRole('button', { name: 'Claim 2, select' })).toBeInTheDocument();
    expect(container.querySelector('[data-observation="O-01"]')).toBeInTheDocument();
    for (const withheld of ['Word started PowerShell directly from an email attachment.', 'Points to malicious', 'Backed by O-01, O-02', 'Stated by the rules']) {
      expect(screen.queryByText(withheld)).not.toBeInTheDocument();
    }
  });

  it('a backed claim without ids still says it is backed, hides a reason it does not need, and shows no direction it does not know', () => {
    render(<ClaimRow claim={claim({ observation_ids: [], check_reason: 'not shown', direction: 'context' })} number={1} />);
    expect(screen.getByText('Backed by an observation')).toBeInTheDocument();
    expect(screen.queryByText('not shown')).not.toBeInTheDocument();
    expect(screen.queryByText(/Points to/)).not.toBeInTheDocument();
  });
});

describe('NotEstablished', () => {
  it('keeps three kinds apart on a real read model: empty lookups named on one line, the others listed with their reason', () => {
    const { container } = render(
      <NotEstablished value={ESCALATED_INVESTIGATION.not_established} observations={ESCALATED_INVESTIGATION.observations} notCheckedNote="Not yet available: without a playbook." />,
    );
    const kind = (name: string) => container.querySelector(`[data-kind="${name}"]`) as HTMLElement;
    expect(within(kind('empty')).getByRole('heading', { name: /Checked, found nothing/ })).toHaveTextContent('4 items');
    // Each kind of lookup is named once, with everything it looked up.
    expect(kind('empty')).toHaveTextContent(
      'Earlier alerts of this customer for the same entity: user m.keller, host WS-FIN-0142; threat-intelligence reputation: IP address 203.0.113.50, file hash 5d1e',
    );
    expect(within(kind('empty')).getByText('Show the 4 lookups')).toBeInTheDocument();
    expect(kind('empty').querySelectorAll('details li')).toHaveLength(4);
    expect(kind('empty').querySelectorAll('details li')[2]).toHaveTextContent('O-04 Threat-intelligence reputation: IP address 203.0.113.50 (virustotal, abuseipdb)');
    expect(within(kind('not')).getByRole('heading', { name: /Not checked/ })).toHaveTextContent('1 item');
    expect(kind('not')).toHaveTextContent("What else happened on the host and for the user around the alertThe investigation cannot query the source's own event data yet.");
    expect(within(kind('cannot')).getByRole('heading', { name: /Could not check for this customer/ })).toHaveTextContent('1');
    expect(kind('cannot')).toHaveTextContent('Threat-intelligence reputationvirustotal: The source did not answer.');
    expect(screen.getByText('Not yet available: without a playbook.')).toBeInTheDocument();
    expect(screen.getByText(/A lookup that returns nothing is never used as proof that something is safe/)).toBeInTheDocument();
  });

  it('says when a kind is empty, and names a lookup it does not have by its id', () => {
    const { container } = render(<NotEstablished value={{ empty: ['O-09'], not_checked: [], unavailable: [] }} observations={[]} />);
    expect(screen.getAllByText('Nothing in this kind.')).toHaveLength(2);
    expect(screen.getByText('Show the 1 lookup')).toBeInTheDocument();
    expect(container.querySelector('[data-kind="empty"]')).toHaveTextContent('Lookup O-09.');
  });
});

describe('TrackRecord', () => {
  it('draws one square per alert and gives the counts, never a percentage', () => {
    const { container } = render(<TrackRecord record={ESCALATED_INVESTIGATION.track_record} scope="Northwind Logistics" />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'counted');
    expect(screen.getByText('Analysts confirmed 31 of 34')).toBeInTheDocument();
    expect(container).toHaveTextContent('Analysts confirmed 31 of 34 alerts sent to a person as likely malicious.');
    const squares = screen.getByRole('img', { name: '34 alerts: 31 confirmed, 3 not' });
    expect(squares.querySelectorAll('[data-square="confirmed"]')).toHaveLength(31);
    expect(squares.querySelectorAll('[data-square="other"]')).toHaveLength(3);
    expect(container).toHaveTextContent('Northwind Logistics, last 90 days, analyst decisions.');
    expect(container).not.toHaveTextContent('%');
    expect(container).not.toHaveTextContent('0.91');
    expect(screen.queryByText('too few for a rate')).not.toBeInTheDocument();
  });

  it('refuses a rate on a small sample: the counts and the squares, and the words "too few for a rate"', () => {
    const { container } = render(<TrackRecord record={AI_CLOSED_INVESTIGATION.track_record} scope="Northwind Logistics" />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'few');
    expect(container).toHaveTextContent('Blind-audit labels agreed with the AI on 11 of 12 alerts the AI closed and sampled for audit.');
    expect(screen.getByText('too few for a rate')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: '12 alerts: 11 confirmed, 1 not' }).children).toHaveLength(12);
    expect(container).toHaveTextContent('last 90 days, blind-audit labels.');
    expect(container).not.toHaveTextContent('%');
  });

  it('above 60 alerts: the fraction and a bar; each category has its own words', () => {
    const { container, rerender } = render(<TrackRecord record={track({ category: 'needs_review', total: 200, confirmed: 150, rate: 0.75 })} scope="Acme" />);
    expect(screen.getByText('Analysts decided true positive on 150 of 200')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: '150 of 200 alerts confirmed' }).firstElementChild).toHaveStyle({ width: '75%' });
    expect(container.querySelector('[data-square]')).toBeNull();
    expect(container).not.toHaveTextContent('%');
    expect(MAX_SQUARES).toBe(60);
    rerender(<TrackRecord record={track({ category: 'ai_closed_evidence', basis: 'blind_audit_labels', total: 40, confirmed: 39 })} scope="Acme" />);
    expect(container).toHaveTextContent('Blind-audit labels agreed with the AI on 39 of 40 alerts the AI closed on approved evidence.');
    rerender(<TrackRecord record={track({ category: 'something_new', total: 31, confirmed: 30 })} scope="Acme" />);
    expect(container).toHaveTextContent('People confirmed 30 of 31 alerts with this outcome.');
  });

  it('no record, and nothing decided yet', () => {
    const { container, rerender } = render(<TrackRecord record={null} scope="Acme" />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'none');
    expect(container).toHaveTextContent('Not measured for this alert.');
    rerender(<TrackRecord record={null} scope="Acme" none="Not yet available: this API version does not count it." />);
    expect(container).toHaveTextContent('Not yet available: this API version does not count it.');
    rerender(<TrackRecord record={track({ total: 0, confirmed: 0, rate: null })} scope="Acme" />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'empty');
    expect(container).toHaveTextContent('None of the alerts sent to a person as likely malicious has been decided yet.');
    rerender(<TrackRecord record={track({ total: 1, confirmed: 5, rate: null })} scope="Acme" />);
    expect(screen.getByRole('img', { name: '1 alert: 1 confirmed, 0 not' })).toBeInTheDocument();
    expect(screen.getByText('too few for a rate')).toBeInTheDocument();
  });
});

describe('StepList', () => {
  const steps: PlainStepOut[] = [
    ...ESCALATED_INVESTIGATION.steps,
    { ts: '2026-11-16T12:00:00Z', actor: 'person', text: 'An analyst decided: true positive.', produced: null },
    { ts: '2026-11-16T12:00:01Z', actor: 'check', text: 'Checker compared each claim.', produced: null },
    { ts: 'not a date', actor: 'robot', text: 'Something else.', produced: null },
  ];

  it('marks who acted on each step of a real read model, in words for a screen reader, with what the step produced', () => {
    const { container } = render(<StepList steps={steps} />);
    const rows = [...container.querySelectorAll('li[data-actor]')];
    expect(rows).toHaveLength(ESCALATED_INVESTIGATION.steps.length + 3);
    expect(rows[0]).toHaveTextContent('Code: Alert received.');
    expect(rows[1].querySelector('[data-voice]')).toHaveAttribute('data-voice', 'decided');
    const model = rows.find((r) => r.getAttribute('data-actor') === 'model') as HTMLElement;
    expect(model.querySelector('[data-voice]')).toHaveAttribute('data-voice', 'claimed');
    expect(rows.at(-3)).toHaveTextContent('Person: An analyst decided: true positive.');
    expect(rows.at(-2)).toHaveTextContent('Check: Checker compared each claim.');
    expect(rows.at(-1)?.querySelector('[data-voice]')).toHaveAttribute('data-voice', 'observed');
    expect(rows[0].querySelector('time')).toHaveAttribute('dateTime', '2026-11-14T09:44:26Z');
    expect(rows[0].querySelector('time')?.textContent).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(rows.at(-1)?.querySelector('time')).toHaveTextContent('-');
    expect(screen.getByText('4 lookups · verdict malicious')).toBeInTheDocument();
    // A day heading at the first step and wherever the day changes.
    expect(container.querySelectorAll('li:not([data-actor])')).toHaveLength(3);
    expect(container).not.toHaveTextContent(/node\.completed|await_analyst|plan_response/);
  });

  it('withholds what the model produced while the verdict is hidden', () => {
    render(<StepList steps={steps} hideModelOutput />);
    expect(screen.queryByText('4 lookups · verdict malicious')).not.toBeInTheDocument();
    expect(screen.getByText('level L2 · priority 8')).toBeInTheDocument();
  });
});

describe('small parts', () => {
  it('severity as bars and the word, not capitalised by CSS', () => {
    const { container, rerender } = render(<SeverityBars value="critical" suffix="risk" />);
    const tag = container.firstElementChild as HTMLElement;
    expect(tag).toHaveTextContent('Critical risk');
    expect(tag).toHaveAttribute('data-severity', 'critical');
    expect(tag).not.toHaveClass('capitalize');
    expect(tag.querySelector('svg')).toHaveAttribute('data-bars', '4');
    expect(tag.querySelectorAll('rect.fill-sev-critical')).toHaveLength(4);
    rerender(<SeverityBars value="medium" />);
    expect(container.querySelector('svg')).toHaveAttribute('data-bars', '2');
    expect(container.querySelectorAll('rect.fill-sev-medium')).toHaveLength(2);
    expect(container.querySelectorAll('rect.fill-strong')).toHaveLength(2);
    rerender(<SeverityBars value="unheard_of" />);
    expect(container).toHaveTextContent('Unheard of');
    expect(container.querySelector('svg')).toHaveAttribute('data-bars', '0');
    expect(container.querySelectorAll('rect.fill-strong')).toHaveLength(4);
    rerender(<SeverityBars value={null} />);
    expect(container).toHaveTextContent('-');
  });

  it('voice tags, keycaps, chips and glyphs', () => {
    const { container } = render(
      <>
        <VoiceTag voice="observed">Observed</VoiceTag>
        <VoiceTag voice="person">Person</VoiceTag>
        <Keycap>T</Keycap>
        <Keycap tone="inverse">B</Keycap>
        <Keycap tone="on-accent">Ctrl</Keycap>
        <FactChip label="Host" mono>
          WS-FIN-0142
        </FactChip>
        <SmallTag>Decoded by code</SmallTag>
        <Glyph name="tick" />
      </>,
    );
    expect(screen.getByText('Observed').querySelector('[data-voice="observed"]')).toHaveAttribute('aria-hidden', 'true');
    expect(container.querySelectorAll('kbd')).toHaveLength(3);
    expect(screen.getByText('WS-FIN-0142').parentElement).toHaveTextContent('HostWS-FIN-0142');
    expect(screen.getByText('Decoded by code')).toBeInTheDocument();
    expect(container.querySelector('[data-glyph="tick"]')).toHaveAttribute('aria-hidden', 'true');
  });
});
