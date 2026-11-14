import { describe, expect, it } from 'vitest';

import { ALERT_ID, event, investigationAlert, investigationEscalation, investigationEvents, investigationPreview } from '../test/investigation';
import { ADAPTER_GAPS, INVESTIGATION_VERSION, adaptInvestigation } from './investigation';
import type { AlertDetailOut, FindingOut } from './types';

const closed = (summary: Record<string, unknown>, overrides: Partial<AlertDetailOut> = {}) =>
  adaptInvestigation({ alert: investigationAlert({ status: 'closed', summary, findings: [], ...overrides }) });

const finding = (overrides: Partial<FindingOut>): FindingOut => ({
  origin: 'threat_intel',
  kind: 'ip',
  target: '198.51.100.7',
  source: 'abuseipdb',
  status: 'ok',
  verdict: 'harmless',
  checked_at: '2026-11-14T09:44:28Z',
  ...overrides,
});

describe('adaptInvestigation: an alert that waits for an analyst', () => {
  const inv = adaptInvestigation({
    alert: investigationAlert(),
    escalation: investigationEscalation(),
    events: investigationEvents(),
    preview: investigationPreview(),
  });

  it('declares the shape version, the alert and what today’s data cannot fill', () => {
    expect(inv.version).toBe(INVESTIGATION_VERSION);
    expect(inv.alert_id).toBe(ALERT_ID);
    expect(inv.not_yet_available).toEqual([...ADAPTER_GAPS]);
    expect(inv.track_record).toBeNull();
  });

  it('puts a malicious verdict that waits for a person in "needs your decision: likely malicious", with the decide reason in plain words', () => {
    expect(inv.outcome).toEqual({
      category: 'needs_decision_malicious',
      reason: { code: 'false_positive_review', text: 'The AI did not close this alert: high severity alerts are closed only by an analyst.' },
      closed_by: null,
    });
  });

  it('marks the summary as written by the model', () => {
    expect(inv.summary).toEqual({
      text: 'Word ran a hidden, encoded PowerShell command that downloaded a script from a three-day-old domain. Two minutes later the same host read LSASS memory.',
      source: 'model',
    });
  });

  it('turns every lookup into an observation with its outcome, and highlights only the provider’s own verdict', () => {
    expect(inv.observations.map((o) => [o.id, o.outcome, o.tool])).toEqual([
      ['O-01', 'success', 'virustotal'],
      ['O-02', 'empty', 'abuseipdb'],
      ['O-03', 'success', 'history'],
      ['O-04', 'failed', 'virustotal'],
    ]);
    const [first, second, third, fourth] = inv.observations;
    expect(first.title).toBe('Reputation of domain cdn-invoice-portal.example');
    expect(first.excerpt[0].text).toMatch(/^verdict\s+malicious$/);
    const [start, end] = first.excerpt[0].marks?.[0] ?? [0, 0];
    expect(first.excerpt[0].text.slice(start, end)).toBe('malicious');
    expect(first.excerpt.map((l) => l.text.replace(/\s+/g, ' '))).toEqual([
      'verdict malicious',
      'malicious engines 14',
      'total engines 91',
      'registered 2026-11-11',
      'categories phishing, malware',
    ]);
    expect(first.excerpt.slice(1).every((l) => l.marks === undefined)).toBe(true);
    expect(first).toMatchObject({ at: '2026-11-14T09:44:28Z', rows: null, input_sha256: null, output_sha256: null, cached: false, simulated: false, detail: null });
    expect(second.excerpt).toEqual([{ text: 'No record for this IP address.' }]);
    expect(third).toMatchObject({ title: 'Earlier alerts of this tenant for host WS-FIN-0142', cached: true });
    // An "unknown" verdict is not a threat signal: nothing is highlighted.
    expect(third.excerpt[0].marks).toBeUndefined();
    expect(fourth.excerpt).toEqual([{ text: 'virustotal answered with an error.' }]);
    expect(fourth.at).toBeNull();
  });

  it('lists what the analysis stated as claims: backed only by a lookup that returned data', () => {
    expect(inv.claims.map((c) => [c.id, c.direction, c.check, c.observation_ids])).toEqual([
      ['1', null, 'supported', ['O-01']],
      ['2', null, 'unsupported', ['O-02']],
      ['3', null, 'unsupported', []],
      ['4', 'malicious', 'unsupported', []],
      ['5', 'malicious', 'unsupported', []],
      ['6', 'benign', 'unsupported', []],
    ]);
    expect(inv.claims[0].check_reason).toBeNull();
    expect(inv.claims[1].check_reason).toBe('The lookup it names returned nothing, and nothing found is never counted as proof.');
    expect(inv.claims[2].check_reason).toBe('It names no lookup.');
  });

  it('keeps the three kinds of "not established" apart', () => {
    expect(inv.not_established.checked_empty).toEqual([{ what: 'Reputation of IP address 203.0.113.50', why: 'abuseipdb has no record.', observation_id: 'O-02' }]);
    expect(inv.not_established.unavailable).toEqual([
      { what: expect.stringMatching(/^Reputation of file hash 5d1e/), why: 'virustotal answered with an error.', observation_id: 'O-04' },
    ]);
    // An indicator of the alert that no lookup was recorded for.
    expect(inv.not_established.not_checked).toEqual([{ what: 'Reputation of domain unchecked.example', why: 'No lookup was recorded for it.' }]);
  });

  it('writes the steps in plain words, oldest first, without an engine node name', () => {
    expect(inv.steps.map((s) => [s.actor, s.text, s.produced])).toEqual([
      ['check', 'Checked the suppression rules and earlier analyst verdicts: none applies.', null],
      ['model', 'Triage: the rules and the model scored the alert.', '1 sign of an attack · 0 of a false positive'],
      ['code', 'Looked for related alerts of this tenant: 2 found.', '3 shared indicators'],
      ['model', 'The model wrote the analysis after 4 lookups.', 'assessed as malicious'],
      ['policy', 'Decision policy: send it to an analyst. High severity alerts are closed only by an analyst.', null],
      ['policy', 'Sent to an analyst, level L2.', null],
    ]);
    const words = inv.steps.map((s) => `${s.text} ${s.produced ?? ''}`).join(' ');
    for (const node of ['gate', 'node', 'plan_response', 'await_analyst', 'execute_actions']) expect(words).not.toContain(node);
  });

  it('carries the response preview as the proposed response', () => {
    expect(inv.response?.actions.map((a) => a.approval_entry)).toEqual([
      'isolate_host:WS-FIN-0142',
      'kill_process:powershell.exe PID 7340',
      'block_domain:cdn-invoice-portal.example',
      'reset_password:m.keller@acme.example',
    ]);
    expect(inv.response?.dry_run_forced).toBe(false);
  });
});

describe('adaptInvestigation: outcome', () => {
  it('is "unsure" when the analysis did not call it malicious, and takes the reason from the alert without an escalation', () => {
    const base = investigationAlert();
    const alert = investigationAlert({ summary: { ...base.summary, analysis: { verdict: 'inconclusive', conclusion: 'Unclear.' }, decision: { reason: 'assessment in the grey zone', code: 'grey_zone' } } });
    const inv = adaptInvestigation({ alert });
    expect(inv.outcome.category).toBe('needs_decision_unsure');
    expect(inv.outcome.reason).toEqual({ code: 'grey_zone', text: 'The AI did not close this alert: assessment in the grey zone.' });
    expect(inv.summary).toEqual({ text: 'Unclear.', source: null });
    expect(inv.response).toBeNull();
    expect(inv.steps).toEqual([]);
  });

  it('reads the verdict and the summary from the escalation when the alert has no analysis, and gives no reason it was not sent', () => {
    const alert = investigationAlert({ status: 'processing', summary: {}, findings: [] });
    const escalation = investigationEscalation({ status: 'open', reason: '', routing: null, summary: { verdict: 'malicious', conclusion: 'Beaconing to a known C2 host.', llm_used: false } });
    const inv = adaptInvestigation({ alert, escalation });
    expect(inv.outcome).toEqual({ category: 'needs_decision_malicious', reason: null, closed_by: null });
    expect(inv.summary).toEqual({ text: 'Beaconing to a known C2 host.', source: 'rules' });
  });

  it('has no category while the alert is being investigated or waits for an approval', () => {
    for (const status of ['processing', 'waiting_approval', 'failed']) {
      const inv = adaptInvestigation({ alert: investigationAlert({ status, summary: {}, findings: [] }), escalation: investigationEscalation({ status: 'decided' }) });
      expect(inv.outcome).toEqual({ category: null, reason: null, closed_by: null });
      expect(inv.summary).toBeNull();
    }
  });

  it('closed by the AI on the analysis alone: sampled for audit, with the policy’s reason', () => {
    const inv = closed({ close_reason: 'ai_closed:audit_required', decision: { reason: 'AI-closed, audit required: the analysis judged it benign' } });
    expect(inv.outcome).toEqual({
      category: 'ai_closed_audit',
      reason: { code: 'ai_closed:audit_required', text: 'AI-closed, audit required: the analysis judged it benign.' },
      closed_by: { kind: 'ai', reason: 'AI-closed, audit required: the analysis judged it benign.' },
    });
    expect(closed({ close_reason: 'ai_closed:audit_required' }).outcome.closed_by?.reason).toBe('The analysis judged it benign. It stays in the pool for the blind audit.');
  });

  it('closed by the AI: by the policy, after a response, or at triage', () => {
    expect(closed({ close_reason: 'policy:close', decision: { reason: 'low threat corroborated by approved benign evidence' } }).outcome).toMatchObject({
      category: 'ai_closed',
      closed_by: { kind: 'ai', reason: 'Low threat corroborated by approved benign evidence.' },
    });
    expect(closed({ close_reason: 'policy:close' }).outcome.closed_by?.reason).toBe('The decision policy closed it.');
    expect(closed({ close_reason: 'policy:response' }).outcome).toMatchObject({ category: 'ai_closed', closed_by: { kind: 'ai', reason: 'The decision policy judged it malicious and the response plan finished.' } });
    expect(closed({ close_reason: 'triage:false_positive' }).outcome).toMatchObject({ category: 'ai_closed', closed_by: { kind: 'ai', reason: 'Triage judged it a false positive.' } });
  });

  it('closed by a person, a suppression rule or an earlier analyst verdict: no AI category, and who closed it', () => {
    expect(closed({ close_reason: 'analyst:true_positive' }).outcome).toEqual({
      category: null,
      reason: { code: 'analyst:true_positive', text: 'An analyst decided: true positive.' },
      closed_by: { kind: 'analyst', reason: 'An analyst decided: true positive.' },
    });
    expect(closed({ close_reason: 'analyst:escalated_elsewhere' }).outcome.closed_by).toEqual({ kind: 'analyst', reason: 'An analyst decided: escalated elsewhere.' });
    expect(closed({ close_reason: 'analyst:' }).outcome.closed_by).toEqual({ kind: 'analyst', reason: 'An analyst decided it.' });
    expect(closed({ close_reason: 'suppression_rule', suppressed_by: { type: 'suppression_rule', name: 'Patch window' } }).outcome.closed_by).toEqual({
      kind: 'suppression_rule',
      reason: 'Suppression rule "Patch window" matched this alert.',
    });
    expect(closed({ close_reason: 'suppression_rule' }).outcome.closed_by).toEqual({ kind: 'suppression_rule', reason: 'A suppression rule matched this alert.' });
    expect(closed({ suppressed_by: { type: 'verdict_cache', decision: 'benign_positive' } }).outcome.closed_by).toEqual({
      kind: 'cached_verdict',
      reason: 'An analyst decided the same alert before (benign, expected here); that verdict was applied.',
    });
    expect(closed({ close_reason: 'verdict_cache' }).outcome.closed_by).toEqual({
      kind: 'cached_verdict',
      reason: 'An analyst decided the same alert before; that verdict was applied.',
    });
  });

  it('says nothing about a close it cannot read', () => {
    expect(closed({}).outcome).toEqual({ category: null, reason: null, closed_by: null });
    expect(closed({ close_reason: 'reopened:related_threat' }).outcome).toEqual({ category: null, reason: null, closed_by: null });
    expect(adaptInvestigation({ alert: investigationAlert({ status: 'closed', summary: undefined, findings: undefined }) }).outcome.category).toBeNull();
  });
});

describe('adaptInvestigation: observations and what is not established', () => {
  it('says why a lookup could not be made, and files a skipped one under "not checked"', () => {
    const alert = investigationAlert({
      normalized: {},
      findings: [
        finding({ status: 'not_configured', source: 'greynoise' }),
        finding({ status: 'unsupported', source: 'urlhaus' }),
        finding({ status: 'rate_limited', source: 'virustotal' }),
        finding({ status: 'skipped', source: 'otx' }),
        finding({ status: 'timeout', source: 'shodan' }),
      ],
    });
    const inv = adaptInvestigation({ alert });
    expect(inv.observations.map((o) => o.outcome)).toEqual(['failed', 'failed', 'failed', 'failed', 'failed']);
    expect(inv.not_established.unavailable.map((i) => i.why)).toEqual([
      'greynoise is not configured for this tenant.',
      'urlhaus does not answer for this kind of indicator.',
      'virustotal refused the lookup: its rate limit was reached.',
      'shodan did not answer (timeout).',
    ]);
    expect(inv.not_established.not_checked).toEqual([{ what: 'Reputation of IP address 198.51.100.7', why: 'The lookup at otx was skipped.', observation_id: 'O-04' }]);
    expect(inv.not_established.checked_empty).toEqual([]);
  });

  it('bounds a long result: six lines on the page, the rest on demand; a simulated result is flagged, not listed', () => {
    const data = { simulated: true, a: 1, b: true, c: 'x'.repeat(400), d: ['p', 2], e: 5, f: 6, nested: { skip: 1 }, none: null, blank: ' ', empty: [{}] };
    const inv = adaptInvestigation({ alert: investigationAlert({ findings: [finding({ verdict: 'suspicious', data })] }) });
    const [o] = inv.observations;
    expect(o.simulated).toBe(true);
    expect(o.excerpt).toHaveLength(6);
    expect(o.excerpt[0].text.slice(...(o.excerpt[0].marks?.[0] ?? [0, 0]))).toBe('suspicious');
    expect(o.excerpt[3].text.length).toBeLessThanOrEqual(200);
    expect(o.excerpt[3].text.endsWith('…')).toBe(true);
    expect(o.detail?.split('\n').map((l) => l.split(/\s+/)[0])).toEqual(['verdict', 'a', 'b', 'c', 'd', 'e', 'f']);
    expect(o.detail).not.toContain('simulated');
  });

  it('shows a lookup without a verdict as unknown, and drops malformed findings', () => {
    const alert = investigationAlert({
      findings: [finding({ verdict: '', data: undefined }), { origin: 'other' } as unknown as FindingOut, finding({ source: '' })],
    });
    const inv = adaptInvestigation({ alert });
    expect(inv.observations).toHaveLength(1);
    expect(inv.observations[0].excerpt).toEqual([{ text: 'verdict  unknown' }]);
  });

  it('lists at most eight indicators without a lookup and counts the rest; none when no analysis ran', () => {
    const ips = Array.from({ length: 11 }, (_, i) => `198.51.100.${i + 1}`);
    const base = investigationAlert();
    const inv = adaptInvestigation({ alert: investigationAlert({ normalized: { entities: { ips, urls: 'not-a-list' } }, findings: [] }) });
    expect(inv.not_established.not_checked).toHaveLength(9);
    expect(inv.not_established.not_checked[8]).toEqual({ what: '3 more indicators of this alert', why: 'No lookup was recorded for them.' });
    const noAnalysis = adaptInvestigation({ alert: investigationAlert({ summary: { ...base.summary, analysis: undefined }, normalized: { entities: { ips } }, findings: [] }) });
    expect(noAnalysis.not_established.not_checked).toEqual([]);
    expect(noAnalysis.claims.map((c) => c.direction)).toEqual(['malicious', 'benign']);
  });

  it('cites the lookups that returned data when a claim names both kinds, states each claim once, and keeps at most twelve', () => {
    const base = investigationAlert();
    const reasoning = ['203.0.113.50 and cdn-invoice-portal.example are linked.', '203.0.113.50 AND CDN-INVOICE-PORTAL.EXAMPLE are linked.', ...Array.from({ length: 14 }, (_, i) => `Statement ${i}`), 7, ' '];
    const inv = adaptInvestigation({ alert: investigationAlert({ summary: { ...base.summary, analysis: { reasoning } } }) });
    expect(inv.claims).toHaveLength(12);
    expect(inv.claims[0]).toMatchObject({ check: 'supported', observation_ids: ['O-01'] });
    expect(inv.claims[1].text).toBe('Statement 0');
    const long = adaptInvestigation({ alert: investigationAlert({ summary: { analysis: { reasoning: ['y'.repeat(900)] } } }) });
    expect(long.claims[0].text).toHaveLength(400);
  });
});

describe('adaptInvestigation: steps', () => {
  const steps = (...events: ReturnType<typeof event>[]) => adaptInvestigation({ alert: investigationAlert(), events }).steps;
  const T = '2026-11-14T10:00:00Z';

  it('says what closed an alert at the gate', () => {
    expect(steps(event(T, 'node.completed', 'gate', { suppressed: true, rule_id: 'r-1' }))[0]).toMatchObject({ actor: 'check', text: 'A suppression rule matched: no investigation ran.' });
    expect(steps(event(T, 'node.completed', 'gate', { suppressed: true, verdict_cache: true }))[0].text).toBe(
      'An analyst decided the same alert before: that verdict applies, so no new investigation ran.',
    );
  });

  it('says when no model was used, and leaves out what the event does not carry', () => {
    expect(steps(event(T, 'node.completed', 'triage', { llm_used: false }))[0]).toMatchObject({ actor: 'code', text: 'Triage: the rules scored the alert. No model was used.', produced: null });
    expect(steps(event(T, 'node.completed', 'correlation', { burst: true, llm_used: true, indicators: 1 }))[0]).toMatchObject({
      actor: 'model',
      text: 'Looked for related alerts of this tenant, arriving in a burst.',
      produced: '1 shared indicator',
    });
    expect(steps(event(T, 'node.completed', 'analysis', {}))[0]).toMatchObject({ actor: 'code', text: 'The rules wrote the analysis. No model was used.', produced: null });
    expect(steps(event(T, 'node.completed', 'analysis', { llm_used: true, tool_steps: 1 }))[0].text).toBe('The model wrote the analysis after 1 lookup.');
    expect(steps(event(T, 'node.completed', 'analysis', { llm_used: true }))[0].text).toBe('The model wrote the analysis.');
  });

  it('words the decision policy, the escalation, the response and the close', () => {
    expect(steps(event(T, 'node.completed', 'decide', { route: 'close', reason: 'low threat corroborated by approved benign evidence.' }))[0]).toMatchObject({
      actor: 'policy',
      text: 'Decision policy: close the alert. Low threat corroborated by approved benign evidence.',
    });
    expect(steps(event(T, 'node.completed', 'decide', { route: 'plan_response' }))[0].text).toBe('Decision policy: plan a response.');
    expect(steps(event(T, 'node.completed', 'escalate', { attached: true }))[0].text).toBe('Added to an escalation that is already open for the same activity.');
    expect(steps(event(T, 'node.completed', 'escalate', { created: true }))[0].text).toBe('Sent to an analyst.');
    expect(steps(event(T, 'node.completed', 'plan_response', { threat_type: 'malware', auto: 1, awaiting: 2, blocked: 1, done: 1 }))[0]).toMatchObject({
      text: 'Planned the response.',
      produced: '1 to run · 2 waiting for approval · 1 blocked · 1 already done',
    });
    expect(steps(event(T, 'node.completed', 'plan_response', { auto: 0 }))[0].produced).toBeNull();
    expect(steps(event(T, 'node.completed', 'execute_actions', { statuses: { succeeded: 2, dry_run: 1, failed: 0 } }))[0]).toMatchObject({
      actor: 'code',
      text: 'Ran the response actions that were approved.',
      produced: '2 succeeded · 1 dry run',
    });
    expect(steps(event(T, 'node.completed', 'execute_actions', {}))[0].produced).toBeNull();
    expect(steps(event(T, 'node.completed', 'execute_actions', { statuses: {} }))[0].produced).toBeNull();
    expect(steps(event(T, 'node.completed', 'close', { disposition: 'benign', close_reason: 'ai_closed:audit_required' }))[0].text).toBe(
      'Closed as benign on the analysis alone; it stays in the pool for the blind audit.',
    );
    expect(steps(event(T, 'node.completed', 'close', { disposition: 'malicious', close_reason: 'analyst:true_positive' }))[0].text).toBe(
      "Closed as malicious on the analyst's decision (true positive).",
    );
    expect(steps(event(T, 'node.completed', 'close', { close_reason: 'something_new' }))[0].text).toBe('Closed.');
    expect(steps(event(T, 'node.completed', 'close', {}))[0].text).toBe('Closed.');
  });

  it('leaves the waiting stages to the person’s own event, and never prints an unknown stage’s name', () => {
    expect(steps(event(T, 'node.completed', 'await_analyst'), event(T, 'node.completed', 'await_approval'))).toEqual([]);
    expect(steps(event(T, 'node.completed', 'retro_reopen'))[0]).toMatchObject({ actor: 'code', text: 'An investigation step finished.' });
    expect(steps(event(T, 'node.completed', null))[0].text).toBe('An investigation step finished.');
  });

  it('words what people did', () => {
    expect(steps(event(T, 'analyst.decision', 'await_analyst', { decision: 'false_positive' }, 'user'))[0]).toMatchObject({ actor: 'person', text: 'An analyst decided: false positive.' });
    expect(steps(event(T, 'analyst.decision', 'await_analyst', { folded: true }, 'user'))[0].text).toBe('An analyst decided (with the alerts grouped under one escalation).');
    expect(steps(event(T, 'actions.approval', 'await_approval', { approved: 2, rejected: 1 }, 'user'))[0]).toMatchObject({
      actor: 'person',
      text: 'A person decided on the response actions.',
      produced: '2 approved · 1 rejected',
    });
    expect(steps(event(T, 'actions.approval', 'await_approval', {}, 'user'))[0].produced).toBeNull();
    expect(steps(event(T, 'note', null, { text: 'Called the user.' }, 'user'))[0]).toMatchObject({ actor: 'person', text: 'Note: Called the user.' });
    expect(steps(event(T, 'note', null, {}, 'user'))).toEqual([]);
  });

  it('words checks and other events, falling back to the event’s own name or note', () => {
    expect(steps(event(T, 'escalation.detached', 'await_analyst'))[0]).toMatchObject({ actor: 'policy', text: 'Given its own escalation, apart from the group it was decided with.' });
    expect(steps(event(T, 'action.verified', null, { action_type: 'block_ip' }))[0]).toMatchObject({ actor: 'check', text: 'Checked again that block ip is in effect: it is.' });
    expect(steps(event(T, 'action.verified', null))[0].text).toBe('Checked again that the action is in effect: it is.');
    expect(steps(event(T, 'action.verification_failed', null, { action_type: 'isolate_host', reason: 'the device is offline' }))[0].text).toBe(
      'Could not confirm that isolate host is in effect: the device is offline.',
    );
    expect(steps(event(T, 'action.verification_failed', null))[0].text).toBe('Could not confirm that the action is in effect.');
    expect(steps(event(T, 'alert.reopened', 'retro_reopen'))[0]).toMatchObject({ actor: 'policy', text: 'Reopened: a related alert was confirmed as a threat.' });
    expect(steps(event(T, 'ticket.created', null, { note: 'Ticket SEC-12 opened in Jira.' }))[0]).toMatchObject({ actor: 'code', text: 'Ticket SEC-12 opened in Jira.' });
    expect(steps(event(T, 'alert.reprocess_requested', null, {}, 'user'))[0]).toMatchObject({ actor: 'person', text: 'Alert reprocess requested.' });
    expect(steps(event(T, 'analysis.tool_called', null, {}, 'agent'))[0].actor).toBe('model');
  });

  it('orders by time, then by id, and bounds a long text', () => {
    const late = event('2026-11-14T10:00:05Z', 'note', null, { text: 'z'.repeat(900) }, 'user');
    const first = event('2026-11-14T10:00:00Z', 'note', null, { text: 'first' }, 'user');
    const second = event('2026-11-14T10:00:00Z', 'note', null, { text: 'second' }, 'user');
    const out = steps(late, second, first);
    expect(out.map((s) => s.text.slice(0, 12))).toEqual(['Note: first', 'Note: second', 'Note: zzzzzz']);
    expect(out[2].text).toHaveLength(300);
  });
});
