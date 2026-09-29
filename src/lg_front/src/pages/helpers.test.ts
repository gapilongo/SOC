import { describe, expect, it, vi } from 'vitest';

import { createApiClient } from '../api/client';
import { endpoints } from '../api/endpoints';

import { keysForEvent } from '../live/LiveProvider';
import { filtersFromParams } from './alerts/AlertsPage';
import { buildConfig, splitConfig } from './SourcesPage';
import { buildMatch } from './SuppressionsPage';
import { autonomyPatch, storedAutonomy } from './TenantSettingsPage';
import { dailyTotals } from './UsagePage';

describe('page helpers', () => {
  it('reads alert filters from the URL, keeping multi-valued parameters', () => {
    const f = filtersFromParams(new URLSearchParams('status=queued&status=failed&severity=high&q=mimikatz&from=2026-09-01T00:00:00.000Z'));
    expect(f).toEqual({ status: ['queued', 'failed'], severity: ['high'], q: 'mimikatz', from: '2026-09-01T00:00:00.000Z' });
  });

  it('sends at most one source_id, as the API filters on a single source', () => {
    const f = filtersFromParams(new URLSearchParams('source_id=splunk-prod&source_id=wazuh-dc'));
    expect(f.source_id).toBe('splunk-prod');
    expect(filtersFromParams(new URLSearchParams('source_id=%20')).source_id).toBeUndefined();
  });

  it('puts exactly one source_id in the alerts request', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ items: [], next_cursor: null }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const api = createApiClient({ baseUrl: '/api/v1', auth: { getToken: () => 't', refresh: async () => null, actingTenant: () => null }, fetchImpl });
    await endpoints.alerts(api, filtersFromParams(new URLSearchParams('source_id=a&source_id=b&severity=high&severity=low')));
    const url = new URL(String((fetchImpl.mock.calls[0] as unknown[])[0]), 'https://soc.example');
    expect(url.searchParams.getAll('source_id')).toEqual(['a']);
    expect(url.searchParams.getAll('severity')).toEqual(['high', 'low']);
  });

  it('maps live events to the queries they make stale', () => {
    expect(keysForEvent('alert.updated')).toEqual(['alerts', 'alert', 'dashboard']);
    expect(keysForEvent('escalation.created')).toContain('escalations');
    expect(keysForEvent('action.updated')).toContain('actions');
  });

  it('builds source configuration from typed fields and extra JSON', () => {
    expect(buildConfig('splunk', { base_url: ' https://splunk:8089 ', max_event_lag_s: '600' }, '{"verify": true}')).toEqual({
      verify: true,
      base_url: 'https://splunk:8089',
      max_event_lag_s: 600,
    });
    expect(() => buildConfig('splunk', { max_event_lag_s: 'soon' }, '')).toThrow(/number/);
    expect(() => buildConfig('splunk', {}, '[1]')).toThrow(/JSON object/);
    expect(splitConfig('qradar', { base_url: 'https://q', custom: 1 })).toEqual({ known: { base_url: 'https://q' }, extra: '{\n  "custom": 1\n}' });
  });

  it('builds suppression predicates', () => {
    expect(
      buildMatch([
        { path: 'title', op: 'regex', value: '.*backup.*' },
        { path: 'entities.ips', op: 'cidr', value: '10.0.0.0/8, 192.168.0.0/16' },
        { path: 'severity', op: 'in', value: 'low,info' },
        { path: 'category', op: 'eq', value: '' },
      ]),
    ).toEqual({ title: { regex: '.*backup.*' }, 'entities.ips': { cidr: ['10.0.0.0/8', '192.168.0.0/16'] }, severity: { in: ['low', 'info'] } });
  });

  it('merges legacy response.autonomy and writes one top-level map', () => {
    const settings = { autonomy: { low: 'auto' }, response: { autonomy: { low: 'approval', high: 'disabled' } } };
    expect(storedAutonomy(settings)).toEqual({ low: 'approval', high: 'disabled' });
    expect(autonomyPatch(settings, { low: 'auto', medium: '', high: 'approval' })).toEqual({ autonomy: { low: 'auto', high: 'approval' }, response: { autonomy: null } });
    expect(autonomyPatch({}, {})).toEqual({ autonomy: null });
  });

  it('sums daily LLM cost across models and fills empty days', () => {
    const row = (day: string, cost: string, calls: number) => ({ day, model: 'm', agent: 'a', calls, input_tokens: 10, output_tokens: 5, cache_read_tokens: 0, cache_write_tokens: 0, cost_usd: cost, refusals: 0, errors: 0 });
    const days = dailyTotals([row('2026-09-01', '0.10', 2), row('2026-09-01', '0.05', 1), row('2026-09-03', '1.00', 4)], '2026-09-01', '2026-09-03');
    expect(days.map((d) => [d.day, Number(d.cost.toFixed(2)), d.calls])).toEqual([
      ['2026-09-01', 0.15, 3],
      ['2026-09-02', 0, 0],
      ['2026-09-03', 1, 4],
    ]);
  });
});
