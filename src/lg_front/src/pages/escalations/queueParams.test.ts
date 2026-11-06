import { describe, expect, it } from 'vitest';

import { escalationQueueHref } from '../../lib/links';
import { readEntities, readEvidence } from './evidence';
import { bandLabel, decisionLabel, percent, routingLabel, routingSentence } from './labels';
import { currentView, filtersFromParams, groupedFromParams, VIEWS, viewParams, withParams } from './queueParams';

const p = (q: string) => new URLSearchParams(q);

describe('queue URL parameters', () => {
  it('reads the API filters, waiting statuses and SLA order by default', () => {
    expect(filtersFromParams(p(''))).toEqual({
      status: ['open', 'claimed', 'expired'],
      level: undefined,
      assigned_to: undefined,
      decided_by: undefined,
      overdue: undefined,
      source_id: undefined,
      rule: undefined,
      order: 'sla_deadline',
    });
  });

  it('round-trips the links other pages build (the Overview links)', () => {
    const href = escalationQueueHref({ assigned_to: 'none', overdue: true, order: 'sla_deadline' });
    const f = filtersFromParams(p(href.split('?')[1]));
    expect(f).toMatchObject({ assigned_to: 'none', overdue: true, order: 'sla_deadline', status: ['open', 'claimed', 'expired'] });
    const group = filtersFromParams(p('status=decided&level=L2&level=L3&decided_by=me&source_id=s-1&rule=A+%26+B&order=created_at'));
    expect(group).toMatchObject({ status: ['decided'], level: ['L2', 'L3'], decided_by: 'me', source_id: 's-1', rule: 'A & B', order: 'created_at' });
  });

  it('ignores unknown orders and empty values, and an empty status means every status', () => {
    expect(filtersFromParams(p('order=priority&assigned_to=&overdue=yes'))).toMatchObject({ order: 'sla_deadline', assigned_to: undefined, overdue: undefined });
    expect(filtersFromParams(p('status=')).status).toBeUndefined();
  });

  it('sets and removes parameters, keeping the others', () => {
    expect(withParams(p('a=1&level=L1'), { level: ['L2', 'L3'], overdue: true, a: undefined }).toString()).toBe('level=L2&level=L3&overdue=true');
    expect(withParams(p('rule=x'), { rule: '' }).toString()).toBe('');
  });

  it('knows the view the URL shows and switches views keeping the order and grouping', () => {
    expect(currentView(p(''))?.id).toBe('active');
    expect(currentView(p('assigned_to=none&order=created_at'))?.id).toBe('unassigned');
    expect(currentView(p('decided_by=me&status=decided'))?.id).toBe('decided');
    expect(currentView(p('assigned_to=none&level=L1'))).toBeNull();
    const mine = VIEWS.find((v) => v.id === 'mine')!;
    expect(viewParams(p('overdue=true&order=created_at&group=rule'), mine).toString()).toBe('order=created_at&group=rule&assigned_to=me');
    expect(groupedFromParams(p('group=rule'))).toBe(true);
    expect(groupedFromParams(p('group=other'))).toBe(false);
  });
});

describe('labels', () => {
  it('explains the routing code with the confidence against its band', () => {
    expect(routingSentence({ code: 'grey_zone', confidence: 42, band: { min: 20, max: 60 } })).toBe(
      'Escalated because triage confidence 42% is inside the review band (20–60%).',
    );
    expect(routingSentence({ code: 'grey_zone', confidence: 70 })).toBe('Escalated because triage confidence 70% is in the grey zone.');
    expect(routingSentence({ code: 'grey_zone' })).toBe('Escalated because triage confidence is in the grey zone.');
    expect(routingSentence({ code: 'model_refused' })).toMatch(/declined/);
    expect(routingSentence({ code: 'brand_new_code' })).toBe('Escalated: Brand new code.');
    expect(routingSentence(null)).toBeNull();
    for (const code of ['false_positive_review', 'inconclusive', 'llm_normalized', 'analyst_request', 'response_review', 'group_review']) {
      expect(routingSentence({ code })).toMatch(/^Escalated/);
    }
    expect(bandLabel({ code: 'grey_zone', band: { min: 20.4, max: 59.6 } })).toBe('band 20–60');
    expect(bandLabel(null)).toBeNull();
    expect(percent(41.6)).toBe('42%');
    expect(percent(null)).toBeNull();
    expect(routingLabel('grey_zone')).toBe('Grey zone');
    expect(decisionLabel('benign_positive')).toBe('Benign positive');
    expect(decisionLabel('other_thing')).toBe('Other thing');
    expect(decisionLabel(null)).toBe('-');
  });
});

describe('evidence digest', () => {
  it('reads indicators for and against the verdict with who stated them, and the simulated flag', () => {
    const d = readEvidence(
      {
        summary: {
          triage: { rule_tp: ['TOR exit node'], llm_tp: ['MFA burst', 'tor exit node'], rule_fp: ['Known VPN'], llm_fp: [3, null, ' '] },
          analysis: { threat_indicators: ['Lookalike domain'], conclusion: 'Looks bad.', verdict: 'malicious', llm_used: false, threat_score: 71, simulated_evidence: true, llm_refusal: { code: 'x' } },
          llm_budget_exceeded: true,
        },
      },
      { summary: { recommended_actions: ['block_ip'] } },
    );
    expect(d.malicious).toEqual([
      { text: 'TOR exit node', by: 'rule' },
      { text: 'MFA burst', by: 'model' },
      { text: 'Lookalike domain', by: 'analysis' },
    ]);
    expect(d.benign).toEqual([
      { text: 'Known VPN', by: 'rule' },
      { text: '3', by: 'model' },
    ]);
    expect(d).toMatchObject({ conclusion: 'Looks bad.', verdict: 'malicious', llmUsed: false, threatScore: 71, simulated: true, modelRefused: true, budgetExceeded: true, recommended: ['block_ip'] });
  });

  it('falls back to the escalation summary and invents nothing', () => {
    const d = readEvidence(undefined, { summary: { conclusion: 'From the escalation.', verdict: 'inconclusive', llm_used: true, simulated_evidence: false } });
    expect(d).toMatchObject({ malicious: [], benign: [], conclusion: 'From the escalation.', llmUsed: true, threatScore: null, simulated: false, reasoning: [] });
    expect(readEvidence({ summary: undefined }, {}).llmUsed).toBeNull();
  });

  it('lists non-empty entity kinds', () => {
    expect(readEntities({ normalized: { entities: { users: ['a'], ips: [], hosts: 'x' } } })).toEqual([['users', ['a']]]);
    expect(readEntities(undefined)).toEqual([]);
  });
});
