import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type { ClaimOut, InvestigationOutcomeOut, ObservationOut, StepOut } from '../../api/investigation';
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
  outcomeKind,
  outcomeLabel,
  outcomeWords,
  splitHeadline,
} from '.';

const outcome = (overrides: Partial<InvestigationOutcomeOut> = {}): InvestigationOutcomeOut => ({ category: null, reason: null, closed_by: null, ...overrides });

const observation = (overrides: Partial<ObservationOut> = {}): ObservationOut => ({
  id: 'O-01',
  title: 'Process tree of PID 7340',
  tool: 'Wazuh indexer',
  at: '2026-11-14T09:44:28Z',
  outcome: 'success',
  rows: 3,
  excerpt: [{ text: 'WINWORD.EXE (6124) started powershell.exe (7340)', marks: [[0, 11], [27, 41]] }],
  output_sha256: '9f2c81d7aa00000000000000000000000000000000000000000000000000041e1',
  ...overrides,
});

const claim = (overrides: Partial<ClaimOut> = {}): ClaimOut => ({
  id: 'c-1',
  text: 'Word started PowerShell directly from an email attachment.',
  direction: 'malicious',
  observation_ids: ['O-01', 'O-02'],
  check: 'supported',
  ...overrides,
});

describe('OutcomeHeadline', () => {
  it('needs a decision, likely malicious: the category, the verdict as the largest text, who wrote it and why it is with a person', () => {
    const { container } = render(
      <OutcomeHeadline
        outcome={outcome({ category: 'needs_decision_malicious', reason: { code: 'grey_zone', text: 'The AI did not close this alert: a second alert fired on the host.' } })}
        summary={{ text: 'Word ran a hidden, encoded PowerShell command.', source: 'model' }}
        status="waiting_human"
        checkLine="5 of the 6 claims are backed by what the tools returned; 1 was rejected."
      >
        <span>subject</span>
      </OutcomeHeadline>,
    );
    expect(container.firstElementChild).toHaveAttribute('data-headline', 'needs_decision_malicious');
    expect(screen.getByText('Needs your decision: likely malicious')).toHaveAttribute('data-outcome', 'needs_decision_malicious');
    expect(container.querySelector('[data-glyph="threat"]')).toBeInTheDocument();
    expect(screen.getByText('Word ran a hidden, encoded PowerShell command.').tagName).toBe('P');
    expect(screen.getByText('Summary written by the model')).toBeInTheDocument();
    expect(screen.getByText('Why it is with you.').parentElement).toHaveTextContent(
      'Why it is with you. The AI did not close this alert: a second alert fired on the host. 5 of the 6 claims are backed by what the tools returned; 1 was rejected.',
    );
    expect(screen.getByText('subject')).toBeInTheDocument();
  });

  it('needs a decision, unsure: its own category and mark', () => {
    const { container } = render(<OutcomeHeadline outcome={outcome({ category: 'needs_decision_unsure' })} summary={{ text: 'Unclear.', source: 'rules' }} status="waiting_human" />);
    expect(screen.getByText('Needs your decision: unsure')).toBeInTheDocument();
    expect(container.querySelector('[data-glyph="review"]')).toBeInTheDocument();
    expect(screen.getByText('Summary written by the rules')).toBeInTheDocument();
    expect(screen.queryByText(/^Why it/)).not.toBeInTheDocument();
  });

  it('closed by the AI: says why it was closed; sampled for audit has its own category', () => {
    const reason = { code: 'policy:close', text: 'Low threat corroborated by approved benign evidence.' };
    const { unmount } = render(
      <OutcomeHeadline outcome={outcome({ category: 'ai_closed', reason, closed_by: { kind: 'ai', reason: reason.text } })} summary={{ text: 'A routine package install.', source: null }} status="closed" />,
    );
    expect(screen.getByText('Closed by AI')).toBeInTheDocument();
    expect(screen.getByText('Why it was closed.').parentElement).toHaveTextContent('Why it was closed. Low threat corroborated by approved benign evidence.');
    expect(screen.queryByText(/Summary written/)).not.toBeInTheDocument();
    unmount();
    render(<OutcomeHeadline outcome={outcome({ category: 'ai_closed_audit' })} summary={null} status="closed" />);
    expect(screen.getByText('Closed by AI, sampled for audit')).toBeInTheDocument();
  });

  it('closed without an analysis: the reason is the headline, said once', () => {
    const text = 'Suppression rule "Patch window" matched this alert.';
    render(<OutcomeHeadline outcome={outcome({ reason: { code: 'suppression_rule', text }, closed_by: { kind: 'suppression_rule', reason: text } })} summary={null} status="closed" />);
    expect(screen.getByText('Closed by a suppression rule')).toBeInTheDocument();
    expect(screen.getAllByText(text)).toHaveLength(1);
    expect(screen.queryByText('Why it was closed.')).not.toBeInTheDocument();
  });

  it('verdict hidden: the category, the sentence and the reason are withheld; the subject stays', () => {
    const { container, rerender } = render(
      <OutcomeHeadline
        outcome={outcome({ category: 'needs_decision_malicious', reason: { code: null, text: 'The reason.' } })}
        summary={{ text: 'The verdict sentence.', source: 'model' }}
        status="waiting_human"
        hidden
        checkLine="1 of the 1 claim is backed."
      >
        <span>subject</span>
      </OutcomeHeadline>,
    );
    expect(container.firstElementChild).toHaveAttribute('data-headline', 'hidden');
    const note = screen.getByRole('note');
    expect(note).toHaveTextContent('The verdict and the claims are hidden. Read what the tools returned, choose your own verdict in the bar below, then press V to compare.');
    for (const withheld of ['The verdict sentence.', 'The reason.', 'Needs your decision: likely malicious', '1 of the 1 claim is backed.', 'Summary written by the model']) {
      expect(screen.queryByText(withheld, { exact: false })).not.toBeInTheDocument();
    }
    expect(screen.getByText('subject')).toBeInTheDocument();
    rerender(<OutcomeHeadline outcome={outcome()} summary={null} status="closed" hidden canReveal={false} />);
    expect(screen.getByRole('note')).toHaveTextContent('withheld for everyone until an analyst labels it on the Blind audit page');
  });

  it('still investigating, failed, and no investigation at all', () => {
    const { rerender, container } = render(<OutcomeHeadline outcome={outcome()} summary={null} status="processing" />);
    expect(screen.getByText('Being investigated')).toBeInTheDocument();
    expect(screen.getByText('The investigation is still running.')).toBeInTheDocument();
    expect(container.querySelectorAll('.animate-pulse')).toHaveLength(2);
    rerender(<OutcomeHeadline outcome={outcome()} summary={null} status="failed" />);
    expect(screen.getByText('Investigation failed')).toBeInTheDocument();
    expect(screen.getByText('The investigation failed before it reached a verdict.')).toBeInTheDocument();
    rerender(<OutcomeHeadline outcome={outcome()} summary={null} status="closed" />);
    expect(screen.getByText('No investigation ran: the model saw only the alert.')).toBeInTheDocument();
    rerender(<OutcomeHeadline outcome={outcome({ reason: { code: null, text: 'Two approvals are pending.' } })} summary={null} status="waiting_approval" />);
    expect(screen.getByText('Why it waits.')).toBeInTheDocument();
  });

  it('keeps the headline to a sentence or two and continues a long summary under it', () => {
    const long = `${'A sentence of the summary. '.repeat(14)}The end.`;
    render(<OutcomeHeadline outcome={outcome({ category: 'ai_closed' })} summary={{ text: long, source: 'model' }} status="closed" />);
    const { headline, rest } = splitHeadline(long);
    expect(headline.length).toBeLessThanOrEqual(260);
    expect(headline.endsWith('summary.')).toBe(true);
    expect(rest.endsWith('The end.')).toBe(true);
    expect(screen.getByText(headline)).toBeInTheDocument();
    expect(screen.getByText(rest)).toBeInTheDocument();
    expect(splitHeadline('  Short   one. ')).toEqual({ headline: 'Short one.', rest: '' });
    expect(splitHeadline('x'.repeat(400)).rest).toBe('');
  });

  it('maps a category, who closed it, or the status to one outcome', () => {
    expect(outcomeKind(outcome({ category: 'ai_closed' }), 'closed')).toBe('ai_closed');
    expect(outcomeKind(outcome({ category: 'something_new' }), 'closed')).toBe('closed');
    expect(outcomeKind(outcome({ closed_by: { kind: 'analyst', reason: null } }), 'closed')).toBe('closed_analyst');
    expect(outcomeKind(outcome({ closed_by: { kind: 'cached_verdict', reason: null } }), 'closed')).toBe('closed_cached');
    expect(outcomeKind(outcome(), 'waiting_approval')).toBe('waiting_approval');
    expect(outcomeKind(outcome(), 'queued')).toBe('investigating');
    expect(outcomeKind(outcome(), 'waiting_human')).toBe('unknown');
    expect(outcomeLabel('closed_cached')).toBe('Closed by an earlier analyst verdict');
    render(<OutcomeTag kind="waiting_approval" />);
    expect(screen.getByText('Waiting for an approval')).toBeInTheDocument();
  });
});

describe('Observation', () => {
  it('returned rows: id, title, outcome, tool, time, hash, and only the marked characters highlighted', () => {
    const { container } = render(<Observation observation={observation({ detail: 'template wazuh.process_tree v2', input_sha256: '41be7d0c9a' })} />);
    const block = container.querySelector('[data-observation="O-01"]') as HTMLElement;
    expect(block).toHaveAttribute('data-outcome', 'success');
    expect(block).toHaveTextContent('O-01');
    expect(block).toHaveTextContent('Process tree of PID 7340');
    expect(within(block).getByText('returned 3 rows')).toBeInTheDocument();
    expect(block).toHaveTextContent('Wazuh indexer');
    expect(block.querySelector('time')).toHaveAttribute('dateTime', '2026-11-14T09:44:28Z');
    expect(within(block).getByText('sha256 9f2c…41e1')).toHaveAttribute('title', expect.stringMatching(/^9f2c81d7aa/));
    expect([...block.querySelectorAll('mark')].map((m) => m.textContent)).toEqual(['WINWORD.EXE', 'powershell.exe']);
    expect(block.querySelector('pre')).toHaveTextContent('WINWORD.EXE (6124) started powershell.exe (7340)');
    expect(within(block).getByText('Query and full result')).toBeInTheDocument();
    expect(block.querySelector('details pre')).toHaveTextContent('input sha256 41be7d0c9a output sha256 9f2c81d7aa');
    expect(block.querySelector('details pre')).toHaveTextContent('template wazuh.process_tree v2');
  });

  it('returned nothing and failed: said in words, with their own outcome', () => {
    const { container, rerender } = render(
      <Observation observation={observation({ id: 'O-10', outcome: 'empty', rows: null, excerpt: [{ text: '0 rows.' }], output_sha256: null, at: null })} />,
    );
    const empty = container.querySelector('[data-observation="O-10"]') as HTMLElement;
    expect(empty).toHaveAttribute('data-outcome', 'empty');
    expect(within(empty).getByText('returned nothing')).toBeInTheDocument();
    expect(empty).toHaveTextContent('time not recorded');
    expect(empty).toHaveTextContent('no hash yet');
    expect(empty.querySelector('mark')).toBeNull();
    expect(empty.querySelector('details')).toBeNull();
    rerender(<Observation observation={observation({ id: 'O-11', outcome: 'failed', excerpt: [{ text: 'The provider did not answer in 30 s.' }] })} />);
    const failed = container.querySelector('[data-observation="O-11"]') as HTMLElement;
    expect(failed).toHaveAttribute('data-outcome', 'failed');
    expect(within(failed).getByText('failed')).toBeInTheDocument();
    expect(failed).toHaveTextContent('The provider did not answer in 30 s.');
  });

  it('flags simulated and cached results, explains under a rule, and does not repeat itself the second time', () => {
    const o = observation({ simulated: true, cached: true, rows: 1, excerpt: [{ text: 'line one' }, { text: 'line two' }], detail: 'full' });
    const { container, rerender } = render(
      <Observation observation={o}>
        <p>What this command does</p>
      </Observation>,
    );
    expect(screen.getByText('Simulated')).toBeInTheDocument();
    expect(screen.getByText('Cached')).toBeInTheDocument();
    expect(screen.getByText('returned 1 row')).toBeInTheDocument();
    expect(screen.getByText('What this command does')).toBeInTheDocument();
    expect(container.querySelector('pre')?.textContent).toBe('line one\nline two');
    rerender(<Observation observation={o} repeated />);
    expect(screen.getByText('same observation as above')).toBeInTheDocument();
    for (const gone of ['Simulated', 'Cached', 'returned 1 row', 'Query and full result']) expect(screen.queryByText(gone)).not.toBeInTheDocument();
  });

  it('ignores highlight ranges that do not fit the line, and words every outcome', () => {
    const { container } = render(
      <Observation observation={observation({ excerpt: [{ text: 'abcdef', marks: [[2, 4], [3, 5], [4, 99], [-1, 2], [5, 5], [0.5, 2]] }], output_sha256: 'short' })} />,
    );
    expect([...container.querySelectorAll('mark')].map((m) => m.textContent)).toEqual(['cd']);
    expect(container.querySelector('pre')?.textContent).toBe('abcdef');
    expect(screen.getByText('sha256 short')).toBeInTheDocument();
    expect(outcomeWords({ outcome: 'success', rows: null })).toBe('returned data');
    expect(outcomeWords({ outcome: 'success', rows: 12 })).toBe('returned 12 rows');
    expect(outcomeWords({ outcome: 'empty' })).toBe('returned nothing');
    expect(outcomeWords({ outcome: 'failed' })).toBe('failed');
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
    const row = container.querySelector('[data-claim="c-1"]') as HTMLElement;
    expect(row).toHaveAttribute('data-check', 'supported');
    expect(screen.getByText('Word started PowerShell directly from an email attachment.')).not.toHaveClass('line-through');
    expect(screen.getByText('Points to malicious')).toBeInTheDocument();
    expect(screen.getByText('Backed by O-01, O-02')).toBeInTheDocument();
    expect(row.querySelector('[data-observation="O-01"]')).toBeInTheDocument();
    const button = screen.getByRole('button', { name: 'Claim 1, select' });
    expect(button).toHaveAttribute('aria-pressed', 'false');
    expect(button).toHaveTextContent('1');
    await userEvent.click(button);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('unsupported: says so, with the reason, and that no observation is cited', () => {
    const { container } = render(<ClaimRow claim={claim({ check: 'unsupported', observation_ids: [], direction: null, check_reason: 'It names no lookup.' })} number={4} selected />);
    expect(container.querySelector('[data-claim]')).toHaveAttribute('data-check', 'unsupported');
    expect(screen.getByText('Unsupported')).toBeInTheDocument();
    expect(screen.getByText('It names no lookup.')).toBeInTheDocument();
    expect(screen.getByText('No observation is cited for this claim.')).toBeInTheDocument();
    expect(screen.queryByText(/Points to/)).not.toBeInTheDocument();
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
      <ClaimRow claim={claim({ check_reason: 'reason' })} number={2} hidden>
        <Observation observation={observation()} />
      </ClaimRow>,
    );
    expect(container.querySelector('[data-claim]')).not.toHaveAttribute('data-check');
    expect(screen.getByRole('button', { name: 'Claim 2, select' })).toBeInTheDocument();
    expect(container.querySelector('[data-observation="O-01"]')).toBeInTheDocument();
    for (const withheld of ['Word started PowerShell directly from an email attachment.', 'Points to malicious', 'Backed by O-01, O-02']) {
      expect(screen.queryByText(withheld)).not.toBeInTheDocument();
    }
  });

  it('a backed claim without ids still says it is backed, and hides a reason it does not need', () => {
    render(<ClaimRow claim={claim({ observation_ids: [], check_reason: 'not shown' })} number={1} />);
    expect(screen.getByText('Backed by an observation')).toBeInTheDocument();
    expect(screen.queryByText('not shown')).not.toBeInTheDocument();
  });
});

describe('NotEstablished', () => {
  it('keeps three kinds apart: empty lookups on one line, the others listed with their reason', () => {
    const { container } = render(
      <NotEstablished
        value={{
          checked_empty: [
            { what: 'Reputation of 203.0.113.50', why: 'abuseipdb has no record.', observation_id: 'O-07' },
            { what: 'Reputation of the document hash', observation_id: null },
          ],
          not_checked: [{ what: 'Who else received this email', why: 'The playbook has no step for it.' }],
          unavailable: [{ what: 'Mail gateway logs', why: 'No mail source is connected.' }, { what: 'Sandbox run' }],
        }}
        notCheckedNote="Not yet available: what the playbook leaves out."
      />,
    );
    const kind = (name: string) => container.querySelector(`[data-kind="${name}"]`) as HTMLElement;
    expect(within(kind('empty')).getByRole('heading', { name: /Checked, found nothing/ })).toHaveTextContent('2 items');
    expect(kind('empty')).toHaveTextContent('Reputation of 203.0.113.50, reputation of the document hash.');
    expect(within(kind('empty')).getByText('Show the 2 lookups')).toBeInTheDocument();
    expect(kind('empty').querySelectorAll('details li')).toHaveLength(2);
    expect(kind('empty').querySelector('details li')).toHaveTextContent('O-07 Reputation of 203.0.113.50 abuseipdb has no record.');
    expect(within(kind('not')).getByRole('heading', { name: /Not checked/ })).toHaveTextContent('1 item');
    expect(kind('not')).toHaveTextContent('Who else received this emailThe playbook has no step for it.');
    expect(within(kind('cannot')).getByRole('heading', { name: /Could not check for this customer/ })).toHaveTextContent('2');
    expect(within(kind('cannot')).getAllByRole('listitem')).toHaveLength(2);
    expect(screen.getByText('Not yet available: what the playbook leaves out.')).toBeInTheDocument();
    expect(screen.getByText(/A lookup that returns nothing is never used as proof that something is safe/)).toBeInTheDocument();
  });

  it('says when a kind is empty', () => {
    const { container } = render(<NotEstablished value={{ checked_empty: [{ what: 'One lookup' }], not_checked: [], unavailable: [] }} />);
    expect(screen.getAllByText('Nothing in this kind.')).toHaveLength(2);
    expect(screen.getByText('Show the 1 lookup')).toBeInTheDocument();
    expect(container.querySelector('[data-kind="empty"]')).not.toHaveTextContent('Nothing in this kind.');
  });
});

describe('TrackRecord', () => {
  const props = { outcome: 'alerts sent to a person as likely malicious', scope: 'Northwind Logistics' };

  it('draws one square per alert and gives the counts, never a percentage', () => {
    const { container } = render(<TrackRecord record={{ confirmed: 31, total: 34, window_days: 90, min_samples: 30 }} {...props} />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'counted');
    expect(screen.getByText('Analysts confirmed 31 of 34')).toBeInTheDocument();
    const squares = screen.getByRole('img', { name: '34 alerts: 31 confirmed, 3 not' });
    expect(squares.querySelectorAll('[data-square="confirmed"]')).toHaveLength(31);
    expect(squares.querySelectorAll('[data-square="other"]')).toHaveLength(3);
    expect(container).toHaveTextContent('Northwind Logistics, last 90 days.');
    expect(container).not.toHaveTextContent('%');
    expect(screen.queryByText('too few for a rate')).not.toBeInTheDocument();
  });

  it('refuses a rate on a small sample: the counts and the squares, and the words "too few for a rate"', () => {
    const { container } = render(<TrackRecord record={{ confirmed: 9, total: 12, window_days: 90, min_samples: 30 }} {...props} />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'few');
    expect(container).toHaveTextContent('Of the alerts sent to a person as likely malicious, analysts decided 12 so far and confirmed 9.');
    expect(screen.getByText('too few for a rate')).toBeInTheDocument();
    expect(screen.queryByText(/Analysts confirmed/)).not.toBeInTheDocument();
    expect(screen.getByRole('img', { name: '12 alerts: 9 confirmed, 3 not' }).children).toHaveLength(12);
    expect(container).not.toHaveTextContent('%');
  });

  it('above 60 alerts: the fraction and a bar', () => {
    const { container } = render(<TrackRecord record={{ confirmed: 150, total: 200, window_days: 30, min_samples: 30 }} {...props} />);
    expect(screen.getByText('Analysts confirmed 150 of 200')).toBeInTheDocument();
    const bar = screen.getByRole('img', { name: '150 of 200 alerts confirmed' });
    expect(bar.firstElementChild).toHaveStyle({ width: '75%' });
    expect(container.querySelector('[data-square]')).toBeNull();
    expect(container).not.toHaveTextContent('%');
    expect(MAX_SQUARES).toBe(60);
  });

  it('no data yet, and nothing decided yet', () => {
    const { container, rerender } = render(<TrackRecord record={null} {...props} />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'none');
    expect(container).toHaveTextContent('Not measured yet.');
    expect(container).toHaveTextContent('How often analysts confirmed the alerts sent to a person as likely malicious is not counted yet, so no figure is shown.');
    rerender(<TrackRecord record={{ confirmed: 0, total: 0, window_days: 90, min_samples: 30 }} {...props} />);
    expect(container.firstElementChild).toHaveAttribute('data-track', 'empty');
    expect(container).toHaveTextContent('Of the alerts sent to a person as likely malicious, analysts have decided none yet.');
    rerender(<TrackRecord record={{ confirmed: 5, total: 1, window_days: 90, min_samples: 30 }} {...props} />);
    expect(screen.getByRole('img', { name: '1 alert: 1 confirmed, 0 not' })).toBeInTheDocument();
  });
});

describe('StepList', () => {
  const steps: StepOut[] = [
    { ts: '2026-11-14T09:44:26Z', actor: 'code', text: 'Alert received.', produced: 'rule group office_macro' },
    { ts: '2026-11-14T09:44:33Z', actor: 'model', text: 'The model wrote the analysis.', produced: 'assessed as malicious' },
    { ts: '2026-11-14T09:44:34Z', actor: 'check', text: 'Checker compared each claim.' },
    { ts: '2026-11-14T09:44:35Z', actor: 'policy', text: 'Sent to an analyst.' },
    { ts: '2026-11-16T12:00:00Z', actor: 'person', text: 'An analyst decided: true positive.' },
    { ts: 'not a date', actor: 'robot', text: 'Something else.' },
  ];

  it('marks who acted on each step, in words for a screen reader, with what the step produced', () => {
    const { container } = render(<StepList steps={steps} />);
    const rows = [...container.querySelectorAll('li[data-actor]')];
    expect(rows.map((r) => r.getAttribute('data-actor'))).toEqual(['code', 'model', 'check', 'policy', 'person', 'robot']);
    expect(rows.map((r) => r.querySelector('[data-voice]')?.getAttribute('data-voice'))).toEqual(['observed', 'claimed', 'decided', 'decided', 'person', 'observed']);
    expect(rows[0]).toHaveTextContent('Code: Alert received.rule group office_macro');
    expect(rows[1]).toHaveTextContent('Model: The model wrote the analysis.assessed as malicious');
    expect(rows[4]).toHaveTextContent('Person: An analyst decided: true positive.');
    expect(rows[0].querySelector('time')).toHaveAttribute('dateTime', '2026-11-14T09:44:26Z');
    expect(rows[0].querySelector('time')?.textContent).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(rows[5].querySelector('time')).toHaveTextContent('-');
    // A day heading at the first step and wherever the day changes.
    expect(container.querySelectorAll('li:not([data-actor])')).toHaveLength(3);
  });

  it('withholds what the model produced while the verdict is hidden', () => {
    render(<StepList steps={steps} hideModelOutput />);
    expect(screen.queryByText('assessed as malicious')).not.toBeInTheDocument();
    expect(screen.getByText('rule group office_macro')).toBeInTheDocument();
  });
});

describe('small parts', () => {
  it('severity as bars and the word, not capitalised by CSS', () => {
    const { container, rerender } = render(<SeverityBars value="critical" suffix="risk" />);
    const tag = container.firstElementChild as HTMLElement;
    expect(tag).toHaveTextContent('Critical risk');
    expect(tag).toHaveAttribute('data-severity', 'critical');
    expect(tag).not.toHaveClass('capitalize');
    expect(tag.querySelectorAll('.bg-sev-critical')).toHaveLength(4);
    rerender(<SeverityBars value="medium" />);
    expect(container.querySelectorAll('.bg-sev-medium')).toHaveLength(2);
    expect(container.querySelectorAll('.bg-strong')).toHaveLength(2);
    rerender(<SeverityBars value="unheard_of" />);
    expect(container).toHaveTextContent('Unheard of');
    expect(container.querySelectorAll('.bg-strong')).toHaveLength(4);
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
