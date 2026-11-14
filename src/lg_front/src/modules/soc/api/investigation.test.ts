import { describe, expect, it } from 'vitest';

import { ALERT_ID, event, investigationAlert, investigationEscalation, investigationEvents, investigationPreview } from '../../../test/investigation';
import { ESCALATED_INVESTIGATION } from '../../../test/investigationReadModels';
import { ADAPTER_GAPS, INVESTIGATION_VERSION, adaptInvestigation } from './investigation';
import type { AlertDetailOut, FindingOut } from './types';

const closed = (summary: Record<string, unknown>, overrides: Partial<AlertDetailOut> = {}) =>
  adaptInvestigation({ alert: investigationAlert({ status: 'closed', closed_at: '2026-11-14T10:00:00Z', summary, findings: [], ...overrides }) });

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

describe('adaptInvestigation: the read model, from an API that does not serve it', () => {
  const inv = adaptInvestigation({
    alert: investigationAlert(),
    escalation: investigationEscalation(),
    events: investigationEvents(),
    preview: investigationPreview(),
  });

  it('has every field of the read model, and names what that API cannot give', () => {
    expect(Object.keys(inv).sort()).toEqual(Object.keys(ESCALATED_INVESTIGATION).sort());
    expect(inv).toMatchObject({ schema_version: INVESTIGATION_VERSION, alert_id: ALERT_ID, tenant_id: 'acme', hidden_for_blind_audit: false, track_record: null });
    expect(inv.pending_harness).toEqual([...ADAPTER_GAPS]);
    expect(inv.pending_harness.map((p) => p.field)).toContain('track_record');
    // Each nested object has the read model's fields too.
    expect(Object.keys(inv.outcome ?? {}).sort()).toEqual(Object.keys(ESCALATED_INVESTIGATION.outcome ?? {}).sort());
    expect(Object.keys(inv.claims[0]).sort()).toEqual(Object.keys(ESCALATED_INVESTIGATION.claims[0]).sort());
    expect(Object.keys(inv.observations[0]).sort()).toEqual(Object.keys(ESCALATED_INVESTIGATION.observations[0]).sort());
    expect(Object.keys(inv.response.actions[0]).sort()).toEqual(Object.keys(ESCALATED_INVESTIGATION.response.actions[0]).sort());
    expect(Object.keys(inv.not_established.unavailable[0]).sort()).toEqual(Object.keys(ESCALATED_INVESTIGATION.not_established.unavailable[0]).sort());
  });

  it('puts a malicious verdict that waits for a person in "needs_decision", with the decide reason in plain words', () => {
    expect(inv.outcome).toEqual({
      category: 'needs_decision',
      reason: { code: 'false_positive_review', sentence: 'The AI did not close this alert: high severity alerts are closed only by an analyst.' },
      blockers: [],
      evidence: [],
      closed_by: null,
    });
    expect(inv.summary).toEqual({
      text: 'Word ran a hidden, encoded PowerShell command that downloaded a script from a three-day-old domain. Two minutes later the same host read LSASS memory.',
      written_by: 'model',
    });
  });

  it('turns every lookup into an observation with its outcome, its source and no invented highlight or hash', () => {
    expect(inv.observations.map((o) => [o.id, o.tool, o.outcome, o.sources, o.verdict])).toEqual([
      ['O-01', 'reputation', 'success', ['virustotal'], 'malicious'],
      ['O-02', 'reputation', 'empty', ['abuseipdb'], null],
      ['O-03', 'history', 'success', ['history'], 'unknown'],
      ['O-04', 'reputation', 'failed', ['virustotal'], null],
    ]);
    const [first, second, third, fourth] = inv.observations;
    expect(first).toMatchObject({ title: 'Threat-intelligence reputation', kind: 'domain', target: 'cdn-invoice-portal.example', at: '2026-11-14T09:44:28Z', cached: false, excerpt_truncated: false });
    expect(first.excerpt.map((l) => l.text)).toEqual([
      'virustotal  ok  malicious',
      '  malicious_engines: 14',
      '  total_engines: 91',
      '  registered: 2026-11-11',
      '  categories: phishing, malware',
    ]);
    expect(inv.observations.every((o) => o.excerpt.every((l) => l.marks.length === 0) && o.input_sha256 === null && o.output_sha256 === null)).toBe(true);
    expect(second.excerpt).toEqual([{ text: 'abuseipdb  not_found', marks: [] }]);
    expect(third).toMatchObject({ title: 'Earlier alerts of this customer for the same entity', kind: 'host', target: 'WS-FIN-0142', cached: true });
    expect(fourth.excerpt).toEqual([{ text: 'virustotal  error', marks: [] }]);
    expect(fourth.at).toBeNull();
  });

  it('lists the fast model’s indicators as unsupported claims and one rule claim per lookup that reported a threat', () => {
    expect(inv.claims.map((c) => [c.id, c.written_by, c.direction, c.check, c.observation_ids])).toEqual([
      ['C-01', 'model', 'malicious', 'unsupported', []],
      ['C-02', 'model', 'benign', 'unsupported', []],
      ['C-03', 'rules', 'malicious', 'supported', ['O-01']],
    ]);
    expect(inv.claims[0]).toMatchObject({ text: 'The PowerShell command is hidden and encoded.', check_reason: 'The model named no observation for it.' });
    expect(inv.claims[2]).toMatchObject({ text: 'A threat-intelligence source reports a value of this alert as malicious.', check_reason: null });
    // The rules' signals and the model's step-by-step reasoning are not claims.
    expect(inv.claims.map((c) => c.text).join(' ')).not.toMatch(/file_hash_present|office_spawns_script_host|The script came from/);
  });

  it('keeps the three kinds of "not established" apart', () => {
    expect(inv.not_established.empty).toEqual(['O-02']);
    expect(inv.not_established.unavailable).toEqual([
      { what: 'Threat-intelligence reputation', why: 'The source did not answer.', kind: 'tool_failed', source: 'virustotal', observation_id: 'O-04' },
    ]);
    // An indicator of the alert that no lookup was recorded for.
    expect(inv.not_established.not_checked).toEqual([{ what: 'Reputation of domain unchecked.example', why: 'No lookup was recorded for it.' }]);
  });

  it('writes the steps in plain words, oldest first, without an engine node name', () => {
    expect(inv.steps.map((s) => [s.actor, s.text, s.produced])).toEqual([
      ['check', 'Checked the suppression rules and earlier analyst verdicts: none applies.', null],
      ['model', 'Triage: the rules and the model scored the alert.', 'rule signs of an attack: office spawns script host'],
      ['code', 'Looked for related alerts of this tenant: 2 found.', '3 shared indicators'],
      ['model', 'The model wrote the analysis after 4 lookups.', 'assessed as malicious · rule signals: file hash present, process execution'],
      ['policy', 'Decision policy: send it to an analyst. High severity alerts are closed only by an analyst.', null],
      ['policy', 'Sent to an analyst, level L2.', null],
    ]);
    const words = inv.steps.map((s) => `${s.text} ${s.produced ?? ''}`).join(' ');
    for (const node of ['gate', 'node', 'plan_response', 'await_analyst', 'execute_actions']) expect(words).not.toContain(node);
  });

  it('carries the response preview as the proposed response', () => {
    expect(inv.response.source).toBe('preview');
    expect(inv.response.actions.map((a) => [a.approval_entry, a.status, a.action_id, a.can_preapprove, a.role_lock])).toEqual([
      ['isolate_host:WS-FIN-0142', null, null, false, 'admin'],
      ['kill_process:powershell.exe PID 7340', null, null, true, null],
      ['block_domain:cdn-invoice-portal.example', null, null, true, null],
      ['reset_password:m.keller@acme.example', null, null, false, 'disabled'],
    ]);
    expect(inv.response.actions[3].guardrail).toEqual({ verdict: 'blocked', code: 'autonomy_disabled', reason: 'The autonomy policy switches off critical-risk actions' });
    expect(inv.response.actions[0]).toMatchObject({ description: null, inverse_action: 'release_host', irreversible_note: null });
    expect(adaptInvestigation({ alert: investigationAlert() }).response).toEqual({ source: 'none', actions: [] });
    expect(adaptInvestigation({ alert: investigationAlert(), preview: investigationPreview([]) }).response.source).toBe('none');
  });
});

describe('adaptInvestigation: outcome', () => {
  it('is "needs_review" when the analysis did not call it malicious, and takes the reason from the alert without an escalation', () => {
    const base = investigationAlert();
    const alert = investigationAlert({ summary: { ...base.summary, analysis: { verdict: 'inconclusive', conclusion: 'Unclear.' }, decision: { reason: 'assessment in the grey zone', code: 'grey_zone' } } });
    const inv = adaptInvestigation({ alert });
    expect(inv.outcome).toMatchObject({ category: 'needs_review', reason: { code: 'grey_zone', sentence: 'The AI did not close this alert: assessment in the grey zone.' } });
    expect(inv.summary).toEqual({ text: 'Unclear.', written_by: null });
    expect(inv.steps).toEqual([]);
  });

  it('reads the verdict and the summary from the escalation when the alert has no analysis, and gives no reason it was not sent', () => {
    const alert = investigationAlert({ status: 'processing', summary: {}, findings: [], hidden_for_blind_audit: true });
    const escalation = investigationEscalation({ status: 'open', reason: '', routing: null, summary: { verdict: 'malicious', conclusion: 'Beaconing to a known C2 host.', llm_used: false } });
    const inv = adaptInvestigation({ alert, escalation });
    expect(inv.outcome).toMatchObject({ category: 'needs_decision', reason: null, closed_by: null });
    expect(inv.summary).toEqual({ text: 'Beaconing to a known C2 host.', written_by: 'rules' });
    expect(inv.hidden_for_blind_audit).toBe(true);
    const coded = adaptInvestigation({ alert: investigationAlert({ summary: { decision: { reason: 'no automatic policy applies' } }, findings: [] }) });
    expect(coded.outcome?.reason).toEqual({ code: 'unknown', sentence: 'The AI did not close this alert: no automatic policy applies.' });
  });

  it('has no outcome while the alert is being investigated, waits for an approval or failed', () => {
    for (const status of ['processing', 'waiting_approval', 'failed']) {
      const inv = adaptInvestigation({ alert: investigationAlert({ status, summary: {}, findings: [] }), escalation: investigationEscalation({ status: 'decided' }) });
      expect(inv.outcome).toBeNull();
      expect(inv.summary).toEqual({ text: null, written_by: null });
    }
  });

  it('closed by the AI: sampled for audit, by the policy, after a response, or at triage', () => {
    const audit = closed({ close_reason: 'ai_closed:audit_required', decision: { reason: 'AI-closed, audit required: the analysis judged it benign' } }).outcome;
    expect(audit).toMatchObject({
      category: 'ai_closed_audit',
      reason: { code: 'ai_closed:audit_required', sentence: 'AI-closed, audit required: the analysis judged it benign.' },
      closed_by: { kind: 'ai', at: '2026-11-14T10:00:00Z', decision: null, rule_id: null, rule_name: null, source_alert_id: null },
    });
    expect(audit?.reason).toEqual(audit?.closed_by?.reason);
    expect(closed({ close_reason: 'ai_closed:audit_required' }).outcome?.closed_by?.reason.sentence).toBe('The analysis judged it benign. It stays in the pool for the blind audit.');
    expect(closed({ close_reason: 'policy:close', decision: { reason: 'low threat corroborated by approved benign evidence' } }).outcome).toMatchObject({
      category: 'ai_closed_evidence',
      closed_by: { kind: 'ai', reason: { code: 'policy:close', sentence: 'Low threat corroborated by approved benign evidence.' } },
    });
    expect(closed({ close_reason: 'policy:close' }).outcome?.closed_by?.reason.sentence).toBe('The decision policy closed it.');
    expect(closed({ close_reason: 'policy:response' }).outcome).toMatchObject({ category: 'ai_closed_evidence', closed_by: { kind: 'ai' } });
    expect(closed({ close_reason: 'triage:false_positive' }).outcome).toMatchObject({ category: 'ai_closed_evidence', closed_by: { reason: { sentence: 'Triage judged it a false positive.' } } });
  });

  it('closed by a person, a suppression rule or an earlier analyst verdict: no AI category, and who closed it', () => {
    expect(closed({ close_reason: 'analyst:true_positive' }).outcome).toMatchObject({
      category: null,
      closed_by: { kind: 'analyst', decision: 'true_positive', reason: { code: 'analyst:true_positive', sentence: 'An analyst decided it.' } },
    });
    expect(closed({ close_reason: 'analyst:' }).outcome?.closed_by).toMatchObject({ kind: 'analyst', decision: null });
    expect(closed({ close_reason: 'suppression_rule', suppressed_by: { type: 'suppression_rule', rule_id: 'r-1', name: 'Patch window' } }).outcome?.closed_by).toMatchObject({
      kind: 'suppression_rule',
      rule_id: 'r-1',
      rule_name: 'Patch window',
      reason: { code: 'suppression_rule', sentence: 'A suppression rule matched this alert.' },
    });
    expect(closed({ close_reason: 'suppression_rule' }).outcome?.closed_by).toMatchObject({ kind: 'suppression_rule', rule_name: null });
    expect(closed({ suppressed_by: { type: 'verdict_cache', decision: 'benign_positive', source_alert_id: 'a-0' } }).outcome?.closed_by).toMatchObject({
      kind: 'cached_verdict',
      decision: 'benign_positive',
      source_alert_id: 'a-0',
    });
    expect(closed({ close_reason: 'verdict_cache' }).outcome?.closed_by).toMatchObject({ kind: 'cached_verdict', decision: null });
  });

  it('says nothing about a close it cannot read', () => {
    expect(closed({}).outcome).toMatchObject({ category: null, reason: null, closed_by: null });
    expect(closed({ close_reason: 'reopened:related_threat' }).outcome).toMatchObject({ category: null, reason: null, closed_by: null });
    expect(adaptInvestigation({ alert: investigationAlert({ status: 'closed', summary: undefined, findings: undefined }) }).outcome?.category).toBeNull();
  });
});

describe('adaptInvestigation: observations and what is not established', () => {
  it('says why a lookup could not be made: no source for this customer, or a source that failed', () => {
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
    expect(inv.not_established.unavailable.map((i) => [i.kind, i.source, i.why])).toEqual([
      ['no_source', 'greynoise', 'The source is not configured for this tenant.'],
      ['no_source', 'urlhaus', 'The source does not answer for this kind of indicator.'],
      ['tool_failed', 'virustotal', 'The source refused the lookup: its rate limit was reached.'],
      ['tool_failed', 'otx', 'The lookup was skipped.'],
      ['tool_failed', 'shodan', 'The source did not answer.'],
    ]);
    expect(inv.not_established.empty).toEqual([]);
    expect(inv.not_established.not_checked).toEqual([]);
  });

  it('bounds a long result to six lines and says it is cut; a simulated flag is not a line', () => {
    const data = { simulated: true, a: 1, b: true, c: 'x'.repeat(400), d: ['p', 2], e: 5, f: 6, nested: { skip: 1 }, none: null, blank: ' ', empty: [{}] };
    const inv = adaptInvestigation({ alert: investigationAlert({ findings: [finding({ verdict: 'suspicious', data })] }) });
    const [o] = inv.observations;
    expect(o.excerpt).toHaveLength(6);
    expect(o.excerpt_truncated).toBe(true);
    expect(o.excerpt[0].text).toBe('abuseipdb  ok  suspicious');
    expect(o.excerpt[3].text.length).toBeLessThanOrEqual(200);
    expect(o.excerpt[3].text.endsWith('…')).toBe(true);
    expect(o.excerpt.map((l) => l.text).join('\n')).not.toContain('simulated');
    expect(inv.claims.at(-1)).toMatchObject({ written_by: 'rules', text: 'A threat-intelligence source reports a value of this alert as suspicious.', observation_ids: ['O-01'] });
  });

  it('shows a lookup without a verdict as unknown, drops malformed findings, and words a history claim', () => {
    const alert = investigationAlert({
      findings: [
        finding({ verdict: '', data: undefined, target: ' ', kind: 'ip' }),
        { origin: 'other' } as unknown as FindingOut,
        finding({ source: '' }),
        finding({ origin: 'history', kind: 'user', target: 'm.keller', source: 'history', verdict: 'malicious' }),
      ],
      summary: { triage: { llm_tp: ['Same.', 'same.'] } },
    });
    const inv = adaptInvestigation({ alert });
    expect(inv.observations).toHaveLength(2);
    expect(inv.observations[0]).toMatchObject({ verdict: 'unknown', target: null, excerpt: [{ text: 'abuseipdb  ok  unknown', marks: [] }] });
    expect(inv.claims.map((c) => c.text)).toEqual(['Same.', 'Earlier alerts of this customer for the same entity were confirmed malicious.']);
  });

  it('lists at most eight indicators without a lookup and counts the rest; none when no analysis ran; at most twelve claims', () => {
    const ips = Array.from({ length: 11 }, (_, i) => `198.51.100.${i + 1}`);
    const base = investigationAlert();
    const inv = adaptInvestigation({ alert: investigationAlert({ normalized: { entities: { ips, urls: 'not-a-list' } }, findings: [] }) });
    expect(inv.not_established.not_checked).toHaveLength(9);
    expect(inv.not_established.not_checked[0]).toEqual({ what: 'Reputation of IP address 198.51.100.1', why: 'No lookup was recorded for it.' });
    expect(inv.not_established.not_checked[8]).toEqual({ what: '3 more indicators of this alert', why: 'No lookup was recorded for them.' });
    const noAnalysis = adaptInvestigation({ alert: investigationAlert({ summary: { ...base.summary, analysis: undefined }, normalized: { entities: { ips } }, findings: [] }) });
    expect(noAnalysis.not_established.not_checked).toEqual([]);
    const many = adaptInvestigation({ alert: investigationAlert({ summary: { triage: { llm_tp: [...Array.from({ length: 14 }, (_, i) => `Statement ${i}`), 7, ' ', 'y'.repeat(900)] } } }) });
    expect(many.claims).toHaveLength(12);
    const long = adaptInvestigation({ alert: investigationAlert({ summary: { triage: { llm_fp: ['y'.repeat(900)] } }, findings: [] }) });
    expect(long.claims[0].text).toHaveLength(400);
  });
});

describe('adaptInvestigation: steps', () => {
  const steps = (...events: ReturnType<typeof event>[]) => adaptInvestigation({ alert: investigationAlert({ summary: {} }), events }).steps;
  const T = '2026-11-14T10:00:00Z';

  it('says what closed an alert at the gate', () => {
    expect(steps(event(T, 'node.completed', 'gate', { suppressed: true, rule_id: 'r-1' }))[0]).toMatchObject({ actor: 'check', text: 'A suppression rule matched: no investigation ran.' });
    expect(steps(event(T, 'node.completed', 'gate', { suppressed: true, verdict_cache: true }))[0].text).toBe(
      'An analyst decided the same alert before: that verdict applies, so no new investigation ran.',
    );
  });

  it('says when no model was used, and leaves out what the event does not carry', () => {
    expect(steps(event(T, 'node.completed', 'triage', { llm_used: false }))[0]).toMatchObject({ actor: 'code', text: 'Triage: the rules scored the alert. No model was used.', produced: null });
    expect(steps(event(T, 'node.completed', 'triage', { rule_tp: 2, rule_fp: 1 }))[0].produced).toBe('2 signs of an attack · 1 of a false positive');
    expect(steps(event(T, 'node.completed', 'correlation', { burst: true, llm_used: true, indicators: 1 }))[0]).toMatchObject({
      actor: 'model',
      text: 'Looked for related alerts of this tenant, arriving in a burst.',
      produced: '1 shared indicator',
    });
    expect(steps(event(T, 'node.completed', 'analysis', {}))[0]).toMatchObject({ actor: 'code', text: 'The rules wrote the analysis. No model was used.', produced: null });
    expect(steps(event(T, 'node.completed', 'analysis', { llm_used: true, tool_steps: 1 }))[0].text).toBe('The model wrote the analysis after 1 lookup.');
    expect(steps(event(T, 'node.completed', 'analysis', { llm_used: true }))[0].text).toBe('The model wrote the analysis.');
    const many = { triage: { rule_tp: Array.from({ length: 8 }, (_, i) => `sign_${i}`), rule_fp: ['known_scanner'] } };
    const listed = adaptInvestigation({ alert: investigationAlert({ summary: many }), events: [event(T, 'node.completed', 'triage', {})] });
    expect(listed.steps[0].produced).toBe('rule signs of an attack: sign 0, sign 1, sign 2, sign 3, sign 4, sign 5 +2 more · of a false positive: known scanner');
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
    expect(steps(event(T, 'analyst.decision', 'await_analyst', { decision: 'escalated_elsewhere', folded: true }, 'user'))[0].text).toBe(
      'An analyst decided: escalated elsewhere (with the alerts grouped under one escalation).',
    );
    expect(steps(event(T, 'analyst.decision', 'await_analyst', {}, 'user'))[0].text).toBe('An analyst decided.');
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
