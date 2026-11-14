import { QueryClient } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';

import * as policies from './invalidate';

/** The keys each policy invalidates: the inline calls they replaced, in the same order, under the module id. */
const EXPECTED: Array<[string, (client: QueryClient) => Promise<void>, unknown[][]]> = [
  ['afterAlertChange', (c) => policies.afterAlertChange(c, 'a-1'), [['soc', 'alert', 'a-1'], ['soc', 'alerts']]],
  ['afterAlertTimelineChange', (c) => policies.afterAlertTimelineChange(c, 'a-1'), [['soc', 'alert', 'a-1', 'events']]],
  ['afterAlertsAdded', policies.afterAlertsAdded, [['soc', 'alerts']]],
  ['afterEscalationChange', policies.afterEscalationChange, [['soc', 'escalations'], ['soc', 'escalation'], ['soc', 'dashboard']]],
  ['afterEscalationDecision', policies.afterEscalationDecision, [['soc', 'escalations'], ['soc', 'escalation'], ['soc', 'alerts'], ['soc', 'dashboard']]],
  ['afterBulkClaim', policies.afterBulkClaim, [['soc', 'escalations'], ['soc', 'escalation'], ['soc', 'alerts'], ['soc', 'dashboard']]],
  ['afterBulkClose', (c) => policies.afterBulkClose(c), [['soc', 'escalations'], ['soc', 'escalation'], ['soc', 'alerts'], ['soc', 'alert'], ['soc', 'dashboard']]],
  [
    'afterBulkClose (with a proposed rule)',
    (c) => policies.afterBulkClose(c, true),
    [['soc', 'escalations'], ['soc', 'escalation'], ['soc', 'alerts'], ['soc', 'alert'], ['soc', 'dashboard'], ['soc', 'suppressions']],
  ],
  ['afterBulkSuppressionProposal', policies.afterBulkSuppressionProposal, [['soc', 'suppressions']]],
  ['afterActionChange', policies.afterActionChange, [['soc', 'actions']]],
  ['afterActionDecision', policies.afterActionDecision, [['soc', 'actions'], ['soc', 'alerts'], ['soc', 'dashboard']]],
  ['afterBlindAuditLabel', (c) => policies.afterBlindAuditLabel(c, false), [['soc', 'blind-audit'], ['soc', 'report-blind-audit']]],
  [
    'afterBlindAuditLabel (an escalation was opened)',
    (c) => policies.afterBlindAuditLabel(c, true),
    [['soc', 'blind-audit'], ['soc', 'report-blind-audit'], ['soc', 'escalations'], ['soc', 'dashboard']],
  ],
  ['afterBlindAuditSample', policies.afterBlindAuditSample, [['soc', 'blind-audit'], ['soc', 'report-blind-audit']]],
  ['afterPovRunChange', policies.afterPovRunChange, [['soc', 'pov']]],
  ['afterSourceChange', policies.afterSourceChange, [['soc', 'sources']]],
  ['afterSuppressionChange', policies.afterSuppressionChange, [['soc', 'suppressions']]],
  ['afterIntegrationChange', policies.afterIntegrationChange, [['soc', 'integrations']]],
  ['afterIntegrationTest', (c) => policies.afterIntegrationTest(c, 'i-1'), [['soc', 'integrations', 'i-1', 'deliveries']]],
  ['afterTenantSettingsChange', policies.afterTenantSettingsChange, [['soc', 'onboarding-status']]],
  ['afterOnboardingChange', policies.afterOnboardingChange, [['soc', 'onboarding-status']]],
  ['afterSetupSaved', policies.afterSetupSaved, [['core', 'me'], ['soc', 'platform-tenants']]],
  ['afterUserChange', policies.afterUserChange, [['soc', 'users']]],
  ['afterApiKeyChange', policies.afterApiKeyChange, [['soc', 'api-keys']]],
  ['afterMfaChange', policies.afterMfaChange, [['soc', 'mfa-status'], ['soc', 'users']]],
  ['afterRecoveryCodesChange', policies.afterRecoveryCodesChange, [['soc', 'mfa-status']]],
  ['afterTenantChange', policies.afterTenantChange, [['soc', 'platform-tenants']]],
];

describe('invalidation policies', () => {
  it('covers every exported policy', () => {
    const names = new Set(EXPECTED.map(([name]) => name.split(' ')[0]));
    expect([...names].sort()).toEqual(Object.keys(policies).sort());
  });

  it.each(EXPECTED)('%s invalidates the same keys as before', async (_name, policy, keys) => {
    const client = new QueryClient();
    const spy = vi.spyOn(client, 'invalidateQueries');
    await policy(client);
    expect(spy.mock.calls.map(([filters]) => filters)).toEqual(keys.map((queryKey) => ({ queryKey })));
  });
});
