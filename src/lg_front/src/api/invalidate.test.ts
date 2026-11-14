import { QueryClient } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';

import * as policies from './invalidate';

/** The keys each policy invalidates: the inline calls they replaced, in the same order. */
const EXPECTED: Array<[string, (client: QueryClient) => Promise<void>, unknown[][]]> = [
  ['afterAlertChange', (c) => policies.afterAlertChange(c, 'a-1'), [['alert', 'a-1'], ['alerts']]],
  ['afterAlertTimelineChange', (c) => policies.afterAlertTimelineChange(c, 'a-1'), [['alert', 'a-1', 'events']]],
  ['afterAlertsAdded', policies.afterAlertsAdded, [['alerts']]],
  ['afterEscalationChange', policies.afterEscalationChange, [['escalations'], ['escalation'], ['dashboard']]],
  ['afterEscalationDecision', policies.afterEscalationDecision, [['escalations'], ['escalation'], ['alerts'], ['dashboard']]],
  ['afterBulkClaim', policies.afterBulkClaim, [['escalations'], ['escalation'], ['alerts'], ['dashboard']]],
  ['afterBulkClose', (c) => policies.afterBulkClose(c), [['escalations'], ['escalation'], ['alerts'], ['alert'], ['dashboard']]],
  [
    'afterBulkClose (with a proposed rule)',
    (c) => policies.afterBulkClose(c, true),
    [['escalations'], ['escalation'], ['alerts'], ['alert'], ['dashboard'], ['suppressions']],
  ],
  ['afterBulkSuppressionProposal', policies.afterBulkSuppressionProposal, [['suppressions']]],
  ['afterActionChange', policies.afterActionChange, [['actions']]],
  ['afterActionDecision', policies.afterActionDecision, [['actions'], ['alerts'], ['dashboard']]],
  ['afterBlindAuditLabel', (c) => policies.afterBlindAuditLabel(c, false), [['blind-audit'], ['report-blind-audit']]],
  [
    'afterBlindAuditLabel (an escalation was opened)',
    (c) => policies.afterBlindAuditLabel(c, true),
    [['blind-audit'], ['report-blind-audit'], ['escalations'], ['dashboard']],
  ],
  ['afterBlindAuditSample', policies.afterBlindAuditSample, [['blind-audit'], ['report-blind-audit']]],
  ['afterPovRunChange', policies.afterPovRunChange, [['pov']]],
  ['afterSourceChange', policies.afterSourceChange, [['sources']]],
  ['afterSuppressionChange', policies.afterSuppressionChange, [['suppressions']]],
  ['afterIntegrationChange', policies.afterIntegrationChange, [['integrations']]],
  ['afterIntegrationTest', (c) => policies.afterIntegrationTest(c, 'i-1'), [['integrations', 'i-1', 'deliveries']]],
  ['afterTenantSettingsChange', policies.afterTenantSettingsChange, [['onboarding-status']]],
  ['afterOnboardingChange', policies.afterOnboardingChange, [['onboarding-status']]],
  ['afterSetupSaved', policies.afterSetupSaved, [['me'], ['platform-tenants']]],
  ['afterUserChange', policies.afterUserChange, [['users']]],
  ['afterApiKeyChange', policies.afterApiKeyChange, [['api-keys']]],
  ['afterMfaChange', policies.afterMfaChange, [['mfa-status'], ['users']]],
  ['afterRecoveryCodesChange', policies.afterRecoveryCodesChange, [['mfa-status']]],
  ['afterTenantChange', policies.afterTenantChange, [['platform-tenants']]],
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
